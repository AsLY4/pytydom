"""Tydom Gateway session client — websocket handshake.

HTTP Digest challenge, authenticated
websocket upgrade, then one HTTP-framed ping to validate the session.
"""

import asyncio
import base64
import hashlib
import logging
import re
import secrets
import ssl
import time

import aiohttp

from . import protocol
from .exceptions import TydomAuthenticationError, TydomConnectionError

_LOGGER = logging.getLogger(__name__)

# Transport defaults; the integration overrides these from its own config.
DEFAULT_PORT = 443
DEFAULT_TIMEOUT = 60
DEFAULT_HEARTBEAT = 20


def _build_ssl_context(verify: bool) -> ssl.SSLContext:
    """Gateway TLS stacks are old: OpenSSL 3 refuses their legacy
    renegotiation by default, so OP_LEGACY_SERVER_CONNECT is required."""
    context = ssl.create_default_context()
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    context.options |= getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0x4)
    return context


# Built at import time: Home Assistant imports integrations off the loop.
_SSL_CONTEXT_VERIFY = _build_ssl_context(verify=True)
_SSL_CONTEXT_NO_VERIFY = _build_ssl_context(verify=False)


def _md5(value: str) -> str:
    return hashlib.md5(value.encode()).hexdigest()


def _digest_header(
    mac: str,
    password: str,
    realm: str,
    nonce: str,
    uri: str,
    algorithm: str | None,
    opaque: str | None,
) -> str:
    cnonce = secrets.token_hex(8)
    nc = "00000001"
    ha1 = _md5(f"{mac}:{realm}:{password}")
    ha2 = _md5(f"GET:{uri}")
    response = _md5(f"{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}")
    header = (
        f'Digest username="{mac}", realm="{realm}", nonce="{nonce}", '
        f'uri="{uri}", response="{response}", qop=auth, nc={nc}, '
        f'cnonce="{cnonce}"'
    )
    # Challenge directives must be echoed when the gateway sends them.
    if algorithm:
        header += f", algorithm={algorithm}"
    if opaque:
        header += f', opaque="{opaque}"'
    return header


def _probe_headers() -> dict[str, str]:
    """Real gateways answer the digest challenge only to upgrade-style
    requests."""
    return {
        "Connection": "Upgrade",
        "Upgrade": "websocket",
        "Sec-WebSocket-Key": base64.b64encode(secrets.token_bytes(16)).decode(),
        "Sec-WebSocket-Version": "13",
    }


async def async_open_session(
    session: aiohttp.ClientSession,
    host: str,
    mac: str,
    gateway_password: str,
    verify_tls: bool,
    *,
    port: int = DEFAULT_PORT,
    timeout: float = DEFAULT_TIMEOUT,
    heartbeat: float = DEFAULT_HEARTBEAT,
) -> aiohttp.ClientWebSocketResponse:
    """Perform the digest handshake and return an open websocket."""
    uri = f"/mediation/client?mac={mac}&appli=1"
    endpoint = f"{host}:{port}{uri}"
    ssl_ctx = _SSL_CONTEXT_VERIFY if verify_tls else _SSL_CONTEXT_NO_VERIFY
    try:
        async with asyncio.timeout(timeout):
            async with session.get(
                f"https://{endpoint}", headers=_probe_headers(), ssl=ssl_ctx
            ) as resp:
                challenge = resp.headers.get("WWW-Authenticate", "")
                _LOGGER.debug(
                    "Challenge probe to %s: HTTP %s, digest challenge %s",
                    host,
                    resp.status,
                    "present" if challenge else "absent",
                )
            realm = re.search(r'realm="([^"]*)"', challenge)
            nonce = re.search(r'nonce="([^"]*)"', challenge)
            if not realm or not nonce:
                # Booting gateways expose HTTPS before their authentication
                # service: not ready is NOT an authentication failure
                # (reauth requires an explicit digest rejection).
                _LOGGER.debug(
                    "No usable digest challenge from %s: %r", host, challenge[:120]
                )
                raise TydomConnectionError(
                    "Gateway offered no digest challenge (still booting?)"
                )

            algorithm = re.search(r"algorithm=\"?([A-Za-z0-9\-]+)\"?", challenge)
            opaque = re.search(r'opaque="([^"]*)"', challenge)
            auth = _digest_header(
                mac,
                gateway_password,
                realm.group(1),
                nonce.group(1),
                uri,
                algorithm.group(1) if algorithm else None,
                opaque.group(1) if opaque else None,
            )
            websocket = await session.ws_connect(
                f"wss://{endpoint}",
                headers={"Authorization": auth},
                ssl=ssl_ctx,
                # Second keep-alive level: protocol PINGs (the gateway
                # drops silent sessions).
                autoping=True,
                heartbeat=heartbeat,
            )
            _LOGGER.debug("Websocket session established with %s", host)
            return websocket
    except aiohttp.WSServerHandshakeError as err:
        _LOGGER.debug("Websocket upgrade to %s refused: HTTP %s", host, err.status)
        if err.status == 401:
            raise TydomAuthenticationError(
                "Gateway rejected the digest credentials"
            ) from err
        raise TydomConnectionError("Websocket upgrade failed") from err
    except (TimeoutError, aiohttp.ClientError, OSError) as err:
        _LOGGER.debug(
            "Gateway connection to %s failed (%s): %s", host, type(err).__name__, err
        )
        raise TydomConnectionError("Gateway unreachable") from err


def _scan_for_response(buffer: bytes, transac_id: str):
    """Find our correlated response in the stream, skipping other messages.

    Returns (frame or None, remaining buffer)."""
    while buffer:
        try:
            frame, remainder = protocol.next_frame(buffer)
        except ValueError:
            return None, b""
        if frame is None:
            return None, remainder
        if frame.kind == "response" and frame.transac_id == transac_id:
            return frame, remainder
        buffer = remainder
    return None, b""


async def async_validate_connection(
    session: aiohttp.ClientSession,
    host: str,
    mac: str,
    gateway_password: str,
    verify_tls: bool,
    remote: bool = False,
    *,
    port: int = DEFAULT_PORT,
    timeout: float = DEFAULT_TIMEOUT,
    heartbeat: float = DEFAULT_HEARTBEAT,
) -> None:
    """Open an authenticated session, ping the gateway, and close.

    The ping response is correlated by Transac-Id while scanning the
    stream like the runtime router: it may be preceded by unsolicited
    messages or split across frames, and cloud mode prefixes outbound
    frames with 0x02.
    """
    ws = await async_open_session(
        session,
        host,
        mac,
        gateway_password,
        verify_tls,
        port=port,
        timeout=timeout,
        heartbeat=heartbeat,
    )
    prefix = b"\x02" if remote else b""
    # Epoch milliseconds, like every outbound id.
    transac_id = str(time.time_ns() // 1_000_000)
    buffer = b""
    try:
        async with asyncio.timeout(timeout):
            await ws.send_bytes(
                prefix + protocol.build_request("GET", "/ping", transac_id)
            )
            while True:
                msg = await ws.receive()
                if msg.type not in (aiohttp.WSMsgType.BINARY, aiohttp.WSMsgType.TEXT):
                    raise TydomConnectionError("Gateway closed the session")
                raw = (
                    bytes(msg.data)
                    if isinstance(msg.data, (bytes, bytearray))
                    else str(msg.data).encode()
                )
                buffer += raw.lstrip(b"\x02")
                frame, buffer = _scan_for_response(buffer, transac_id)
                if frame is not None:
                    if frame.status is not None and 200 <= frame.status < 300:
                        return
                    raise TydomConnectionError("Gateway rejected the ping")
    except (TimeoutError, aiohttp.ClientError, OSError) as err:
        raise TydomConnectionError("Gateway unreachable") from err
    finally:
        await ws.close()
