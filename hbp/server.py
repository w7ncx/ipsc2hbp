"""
HBP master/server stack — asyncio DatagramProtocol implementing a simple
HBP master that accepts incoming HBP peer (repeater) connections.

This is a compact implementation based on the test harness in
`tests/fake_hbp_master.py`. It exposes the same minimal interface as
`HBPClient` so the translator can treat either a client or server
implementation interchangeably:

  start(loop) / stop()
  activate() / deactivate()
  send_dmrd(data)
  is_connected()

For TRACKING mode the server only binds when `activate()` is called; for
PERSISTENT mode it binds on `start()`.
"""

import asyncio
import logging
import os
from hashlib import sha256

from config import Config
from hbp.const import (
    HBPF_RPTL, HBPF_RPTK, HBPF_RPTC, HBPF_RPTO, HBPF_RPTPING, HBPF_RPTCL,
    HBPF_RPTACK, HBPF_MSTNAK, HBPF_MSTPONG, HBPF_MSTCL,
    HBPF_DMRD,
    RPTACK_NONCE_OFF,
)

log = logging.getLogger(__name__)
_wire = logging.getLogger('hbp.wire')


class HBPServer(asyncio.DatagramProtocol):
    """Simple HBP master/server protocol managing a single connected peer."""

    def __init__(self, cfg: Config, translator):
        self._cfg = cfg
        self._translator = translator
        self._transport = None
        self._loop = None
        self._active = False   # whether server is bound/active

        # Per-peer state (single peer supported)
        self._peer_addr = None
        self._peer_id = None
        self._state = 'IDLE'   # IDLE -> WAIT_RPTK -> WAIT_RPTC -> WAIT_RPTO -> CONNECTED
        self._salt = os.urandom(4)

    # Public interface -------------------------------------------------
    def start(self, loop: asyncio.AbstractEventLoop):
        self._loop = loop
        if self._cfg.hbp_mode == 'PERSISTENT':
            self.activate()

    def stop(self):
        self.deactivate()

    def activate(self):
        if self._active:
            return
        if not self._loop:
            raise RuntimeError('HBPServer.start must be called before activate()')
        coro = self._loop.create_datagram_endpoint(lambda: self,
                                                  local_addr=(self._cfg.hbp_master_ip, self._cfg.hbp_master_port))
        try:
            transport, _ = self._loop.run_until_complete(coro) if self._loop.is_running() is False else None
        except Exception:
            transport = None
        # If loop already running, schedule creation as task
        if transport is None:
            async def _create():
                transport, _ = await self._loop.create_datagram_endpoint(lambda: self,
                                                                           local_addr=(self._cfg.hbp_master_ip, self._cfg.hbp_master_port))
                return transport
            task = self._loop.create_task(_create())
            # when created, connection_made will be called
        self._active = True
        log.info('HBP server activate — binding %s:%d', self._cfg.hbp_master_ip, self._cfg.hbp_master_port)

    def deactivate(self):
        if not self._active:
            return
        self._active = False
        if self._transport:
            try:
                self._transport.close()
            except Exception:
                pass
            self._transport = None
        # drop peer if present
        if self._state == 'CONNECTED':
            self._translator.hbp_disconnected()
        self._state = 'IDLE'
        self._peer_addr = None
        self._peer_id = None
        log.info('HBP server deactivated')

    def send_dmrd(self, data: bytes):
        if self._state != 'CONNECTED' or not self._peer_addr or not self._transport:
            return
        _wire.debug('HBP SEND %d %s', len(data), data.hex())
        self._transport.sendto(data, self._peer_addr)

    def is_connected(self) -> bool:
        return self._state == 'CONNECTED'

    # asyncio.DatagramProtocol hooks ----------------------------------
    def connection_made(self, transport):
        self._transport = transport
        host, port = transport.get_extra_info('sockname')
        log.info('HBP server listening on %s:%d', host, port)

    def connection_lost(self, exc):
        log.info('HBP server socket closed')
        self._transport = None

    def error_received(self, exc):
        log.warning('HBP server socket error: %s', exc)

    def datagram_received(self, data: bytes, addr):
        if len(data) < 4:
            return
        _wire.debug('HBP RECV %d %s from %s', len(data), data.hex(), addr)
        # Longest-prefix dispatch, mirror fake_hbp_master behaviour
        if len(data) >= 7 and data[:7] == HBPF_RPTPING:
            self._on_rptping(data, addr)
        elif len(data) >= len(HBPF_RPTCL) and data[:len(HBPF_RPTCL)] == HBPF_RPTCL:
            self._on_rptcl(data, addr)
        elif len(data) >= 4 and data[:4] == HBPF_RPTL:
            self._on_rptl(data, addr)
        elif len(data) >= 4 and data[:4] == HBPF_RPTK:
            self._on_rptk(data, addr)
        elif len(data) >= 4 and data[:4] == HBPF_RPTC:
            self._on_rptc(data, addr)
        elif len(data) >= 4 and data[:4] == HBPF_RPTO:
            self._on_rpto(data, addr)
        elif len(data) >= 4 and data[:4] == HBPF_DMRD:
            self._on_dmrd(data, addr)
        else:
            log.debug('HBP server: unknown packet cmd=%s len=%d', data[:4], len(data))

    # Handlers (server-side handshake) --------------------------------
    def _on_rptl(self, data: bytes, addr):
        if len(data) < 8:
            log.warning('HBP: RPTL too short from %s', addr)
            return
        peer_id = data[4:8]
        peer_id_int = int.from_bytes(peer_id, 'big')
        log.info('HBP: ← RPTL  peer_id=%d  from %s', peer_id_int, addr)
        self._peer_addr = addr
        self._peer_id = peer_id
        self._state = 'WAIT_RPTK'
        self._salt = os.urandom(4)
        reply = HBPF_RPTACK + self._salt
        self._transport.sendto(reply, addr)

    def _on_rptk(self, data: bytes, addr):
        if self._state != 'WAIT_RPTK':
            log.debug('HBP: RPTK in unexpected state %s', self._state)
            return
        if len(data) < 40:
            log.warning('HBP: RPTK too short')
            return
        peer_id = data[4:8]
        recv_hash = data[8:40]
        expected = bytes.fromhex(sha256(self._salt + self._cfg.hbp_passphrase).hexdigest())
        if recv_hash == expected:
            log.info('HBP: ← RPTK  hash OK')
            self._transport.sendto(HBPF_RPTACK + peer_id, addr)
            self._state = 'WAIT_RPTC'
        else:
            log.warning('HBP: ← RPTK  hash MISMATCH — sending MSTNAK')
            self._transport.sendto(HBPF_MSTNAK + peer_id, addr)
            self._state = 'IDLE'
            self._peer_addr = None
            self._peer_id = None

    def _on_rptc(self, data: bytes, addr):
        if self._state != 'WAIT_RPTC':
            log.debug('HBP: RPTC in unexpected state %s', self._state)
            return
        peer_id = data[4:8] if len(data) >= 8 else (self._peer_id or b'\x00\x00\x00\x00')
        callsign = data[8:16].rstrip(b'\x00').decode(errors='replace') if len(data) >= 16 else ''
        log.info('HBP: ← RPTC  %d bytes  callsign=%r', len(data), callsign)
        self._transport.sendto(HBPF_RPTACK + peer_id, addr)
        log.info('HBP: → RPTACK (config accepted) — waiting for RPTO or CONNECTED')
        self._state = 'WAIT_RPTO'

    def _on_rpto(self, data: bytes, addr):
        peer_id = data[4:8] if len(data) >= 8 else (self._peer_id or b'\x00\x00\x00\x00')
        options = data[8:].rstrip(b'\x00').decode(errors='replace') if len(data) > 8 else ''
        log.info('HBP: ← RPTO  options=%r', options)
        if self._state == 'WAIT_RPTO':
            self._transport.sendto(HBPF_RPTACK + peer_id, addr)
            log.info('HBP: → RPTACK (options accepted) — CONNECTED')
            self._state = 'CONNECTED'
            self._translator.hbp_connected()
        else:
            log.debug('HBP: RPTO in unexpected state %s', self._state)

    def _on_rptping(self, data: bytes, addr):
        # RPTPING in WAIT_RPTO means client sent no options — advance to CONNECTED
        if self._state == 'WAIT_RPTO':
            self._state = 'CONNECTED'
            self._translator.hbp_connected()
        if self._state != 'CONNECTED':
            return
        # Peer id location in RPTPING varies; MSTPONG expects peer id at offset 5..9 in reply
        peer_id = data[7:11] if len(data) >= 11 else self._peer_id
        self._transport.sendto(HBPF_MSTPONG + (peer_id or b'\x00\x00\x00\x00'), addr)
        log.debug('HBP: ← RPTPING → MSTPONG  peer_id=%s', int.from_bytes(peer_id, 'big') if peer_id else '?')

    def _on_rptcl(self, data: bytes, addr):
        peer_id = int.from_bytes(data[len(HBPF_RPTCL):len(HBPF_RPTCL)+4], 'big') if len(data) >= len(HBPF_RPTCL) + 4 else 0
        log.info('HBP: ← RPTCL from peer_id=%d — peer disconnected', peer_id)
        if self._state == 'CONNECTED':
            self._translator.hbp_disconnected()
        self._state = 'IDLE'
        self._peer_addr = None
        self._peer_id = None

    def _on_dmrd(self, data: bytes, addr):
        if self._state == 'CONNECTED':
            # Forward inbound DMRD frames to translator
            self._translator.hbp_voice_received(data)

