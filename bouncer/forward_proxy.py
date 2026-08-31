"""HTTP forward-proxy mode.

Point an agent's ``HTTP_PROXY`` at this and its outbound calls arrive here in
absolute-URI form. bouncer parses the intent, enforces policy, and either
forwards the request upstream or blocks it with a 403.

Threat model — read this before trusting the proxy:

- **The proxy is not a sandbox.** An agent with unrestricted network egress can
  simply ignore ``HTTP_PROXY`` and connect directly. Containment requires
  firewall or container rules that make bouncer the only route out. bouncer is
  the policy *decision* point; the network is the *enforcement* point.

- **CONNECT tunnels are denied by default.** Inside a TLS tunnel bouncer sees a
  hostname and nothing else, so amount caps, rolling windows and approval
  thresholds cannot apply. ``--allow-connect`` opens tunnels to explicitly
  allowlisted hosts only, and the traffic inside them is *unenforced*. Enforcing
  HTTPS payment traffic properly requires terminating TLS, which v1 does not do.

- Requests are handled one per connection (``Connection: close``). This is not a
  performance-tuned proxy; it is an enforcement point.
"""

from __future__ import annotations

import asyncio
import logging
import re
from decimal import Decimal
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from .adapters import RequestContext, parse_intent
from .api import build_enforcer
from .config import BouncerConfig
from .enforcement import Enforcer
from .errors import UnparseableIntent
from .models import Outcome, PaymentIntent

__all__ = ["ProxyServer", "serve_forever"]

logger = logging.getLogger("bouncer.proxy")

#: Cap on the request line plus headers.
MAX_HEADER_BYTES = 64 * 1024
#: Cap on a buffered request body. Larger bodies are refused rather than
#: streamed, because an intent must be read in full before it can be judged.
MAX_BODY_BYTES = 1024 * 1024
#: Hop-by-hop headers that must not be forwarded upstream (RFC 9110).
_HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)

#: Any control character is unforwardable: written back out between CRLF
#: separators, a bare CR or LF becomes a header boundary at the upstream.
_CONTROL_CHARS = re.compile("[\x00-\x1f\x7f]")

#: RFC 9110 token, which is what a method and a header name must be.
_TOKEN = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")

#: Header an agent uses to identify itself. Unauthenticated by design — see the
#: module threat model.
AGENT_HEADER = "x-bouncer-agent"


class ProxyError(Exception):
    """A malformed request that cannot even be evaluated."""


class ParsedRequest:
    """A single parsed HTTP request from the client."""

    __slots__ = ("method", "target", "version", "headers", "body")

    def __init__(
        self,
        method: str,
        target: str,
        version: str,
        headers: list[tuple[str, str]],
        body: bytes,
    ) -> None:
        self.method = method
        self.target = target
        self.version = version
        self.headers = headers
        self.body = body

    def header(self, name: str, default: str = "") -> str:
        wanted = name.lower()
        for key, value in self.headers:
            if key.lower() == wanted:
                return value
        return default

    def header_map(self) -> dict[str, str]:
        return {key.lower(): value for key, value in self.headers}


async def _read_headers(reader: asyncio.StreamReader) -> bytes:
    """Read up to the end of the header block."""
    try:
        data = await reader.readuntil(b"\r\n\r\n")
    except asyncio.IncompleteReadError as exc:
        raise ProxyError("connection closed before headers completed") from exc
    except asyncio.LimitOverrunError as exc:
        raise ProxyError("header block too large") from exc
    if len(data) > MAX_HEADER_BYTES:
        raise ProxyError("header block too large")
    return data


def _parse_request_head(raw: bytes) -> tuple[str, str, str, list[tuple[str, str]]]:
    """Parse the request line and headers, rejecting anything unforwardable.

    Threat model: an authorized request is rebuilt and written upstream by
    concatenating these values with CRLF separators. Splitting the client's
    input on ``\\r\\n`` alone leaves a *bare* ``\\n`` intact inside a header
    value, and an upstream that accepts LF-terminated headers — many do — would
    then read everything after it as a header of its own. An agent could inject
    into a request bouncer had already approved, up to and including a competing
    ``X-Bouncer-Mandate``, so the audit row would no longer describe what
    actually left the machine.

    Every control character is therefore refused here rather than sanitized.
    Stripping them would silently forward a request the client did not send;
    refusing is the only behaviour that keeps the logged decision and the
    forwarded bytes the same thing. RFC 9110 forbids them in field values
    anyway.
    """
    text = raw.decode("iso-8859-1")
    lines = text.split("\r\n")
    request_line = lines[0]
    parts = request_line.split(" ")
    if len(parts) != 3:
        raise ProxyError(f"malformed request line: {request_line!r}")
    method, target, version = parts

    if _CONTROL_CHARS.search(request_line):
        raise ProxyError("control character in the request line")
    if not _TOKEN.fullmatch(method):
        raise ProxyError(f"malformed method: {method!r}")

    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if not line:
            continue
        name, separator, value = line.partition(":")
        if not separator:
            raise ProxyError(f"malformed header line: {line!r}")
        name, value = name.strip(), value.strip()
        if not _TOKEN.fullmatch(name):
            raise ProxyError(f"malformed header name: {name!r}")
        if _CONTROL_CHARS.search(value):
            raise ProxyError(f"control character in the value of header {name!r}")
        headers.append((name, value))
    return method.upper(), target, version, headers


async def _read_body(
    reader: asyncio.StreamReader, headers: list[tuple[str, str]]
) -> bytes:
    """Read the body, which must be Content-Length delimited.

    Chunked bodies are refused: bouncer must see the complete intent before
    deciding, and accepting a body it cannot fully read would mean forwarding
    something it never judged.
    """
    lookup = {key.lower(): value for key, value in headers}
    if "chunked" in lookup.get("transfer-encoding", "").lower():
        raise ProxyError(
            "chunked request bodies are not supported; bouncer must read the "
            "whole intent before authorizing it"
        )
    raw_length = lookup.get("content-length")
    if not raw_length:
        return b""
    try:
        length = int(raw_length)
    except ValueError as exc:
        raise ProxyError(f"invalid Content-Length: {raw_length!r}") from exc
    if length < 0 or length > MAX_BODY_BYTES:
        raise ProxyError(f"body of {length} bytes exceeds the {MAX_BODY_BYTES} limit")
    try:
        return await reader.readexactly(length)
    except asyncio.IncompleteReadError as exc:
        raise ProxyError("connection closed mid-body") from exc


def _blocked_response(result_body: str, status: str = "403 Forbidden") -> bytes:
    payload = result_body.encode("utf-8")
    head = (
        f"HTTP/1.1 {status}\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(payload)}\r\n"
        "Connection: close\r\n"
        "X-Bouncer: blocked\r\n"
        "\r\n"
    )
    return head.encode("ascii") + payload


def _json_error(decision_dict: dict[str, Any]) -> str:
    import json

    return json.dumps({"blocked_by": "bouncer", **decision_dict}, default=str)


class ProxyServer:
    """An asyncio HTTP forward proxy that enforces policy on every request."""

    def __init__(self, enforcer: Enforcer, *, allow_connect: bool = False) -> None:
        self.enforcer = enforcer
        self.allow_connect = allow_connect

    async def handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            await self._handle(reader, writer)
        except ProxyError as exc:
            logger.warning("rejecting malformed request: %s", exc)
            await self._write(writer, _blocked_response(
                _json_error({"error": str(exc)}), "400 Bad Request"
            ))
        except (ConnectionResetError, BrokenPipeError):
            pass
        except Exception:  # pragma: no cover - defensive
            logger.exception("proxy handler failed")
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionResetError, BrokenPipeError):
                pass

    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        head = await _read_headers(reader)
        method, target, _version, headers = _parse_request_head(head)
        agent_id = _agent_from(headers)

        if method == "CONNECT":
            await self._handle_connect(target, agent_id, reader, writer)
            return

        split = urlsplit(target)
        if not split.scheme or not split.hostname:
            raise ProxyError(
                f"expected an absolute URI (proxy form), got {target!r}; "
                "set HTTP_PROXY so your client sends absolute URIs"
            )
        if split.scheme != "http":
            raise ProxyError(f"unsupported scheme {split.scheme!r} in proxy request")

        body = await _read_body(reader, headers)
        # Off the event loop: _authorize takes the decision lock and
        # commits under synchronous=FULL, so running it inline would
        # stall every other proxied connection behind one fsync.
        result = await asyncio.to_thread(
            self._authorize, method, target, headers, body, agent_id
        )

        if result.decision.outcome is not Outcome.ALLOW:
            logger.info(
                "BLOCK %s %s -> %s (%s)",
                method, target, result.decision.outcome.value,
                result.decision.reason_code.value,
            )
            status = "403 Forbidden" if result.decision.outcome is Outcome.DENY else "202 Accepted"
            await self._write(writer, _blocked_response(_json_error(result.to_dict()), status))
            return

        logger.info("ALLOW %s %s", method, target)
        await self._forward(split, method, headers, body, result.mandate, writer)

    def _authorize(
        self,
        method: str,
        target: str,
        headers: list[tuple[str, str]],
        body: bytes,
        agent_id: str,
    ) -> Any:
        ctx = RequestContext(
            method=method,
            url=target,
            body=body,
            agent_id=agent_id,
            headers={key.lower(): value for key, value in headers},
        )
        try:
            intent = parse_intent(ctx)
        except UnparseableIntent as exc:
            placeholder = PaymentIntent(
                agent_id=agent_id,
                merchant=ctx.host or "unknown",
                amount=Decimal(0),
                currency="XXX",
                rail="unparsed",
                description=f"{method} {target}"[:512],
            )
            return self.enforcer.deny_unparseable(exc, placeholder)
        return self.enforcer.authorize(intent)

    async def _forward(
        self,
        split: Any,
        method: str,
        headers: list[tuple[str, str]],
        body: bytes,
        mandate: str | None,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Relay an authorized request upstream and stream the response back."""
        host = split.hostname
        port = split.port or 80
        origin_form = urlunsplit(("", "", split.path or "/", split.query, ""))

        forwarded = [
            (key, value)
            for key, value in headers
            if key.lower() not in _HOP_BY_HOP
        ]
        forwarded.append(("Connection", "close"))
        if mandate:
            # Hand the mandate to the upstream service so it can verify that
            # bouncer authorized this exact payment.
            forwarded.append(("X-Bouncer-Mandate", mandate))

        request = f"{method} {origin_form} HTTP/1.1\r\n"
        request += "".join(f"{key}: {value}\r\n" for key, value in forwarded)
        request += "\r\n"

        try:
            upstream_reader, upstream_writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=30
            )
        except (OSError, asyncio.TimeoutError) as exc:
            await self._write(writer, _blocked_response(
                _json_error({"error": f"upstream connection failed: {exc}"}),
                "502 Bad Gateway",
            ))
            return

        try:
            upstream_writer.write(request.encode("iso-8859-1") + body)
            await upstream_writer.drain()
            while True:
                chunk = await upstream_reader.read(65536)
                if not chunk:
                    break
                writer.write(chunk)
                await writer.drain()
        finally:
            upstream_writer.close()
            try:
                await upstream_writer.wait_closed()
            except (ConnectionResetError, BrokenPipeError):
                pass

    async def _handle_connect(
        self,
        target: str,
        agent_id: str,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle a CONNECT tunnel request. Denied unless explicitly enabled."""
        host, _, raw_port = target.partition(":")
        port = int(raw_port) if raw_port.isdigit() else 443

        if not self.allow_connect:
            result = await asyncio.to_thread(
                self.enforcer.authorize_tunnel, host, agent_id
            )
            logger.info("BLOCK CONNECT %s (tunnels disabled)", target)
            await self._write(writer, _blocked_response(
                _json_error(
                    {
                        "error": (
                            "CONNECT tunnels are disabled. bouncer cannot read "
                            "payment intent inside TLS, so it will not open a "
                            "channel it cannot police. Start the proxy with "
                            "--allow-connect to permit tunnels to allowlisted "
                            "hosts (their contents are then unenforced)."
                        ),
                        "audit_seq": result.audit_seq,
                    }
                ),
                "403 Forbidden",
            ))
            return

        result = await asyncio.to_thread(
            self.enforcer.authorize_tunnel, host, agent_id
        )
        if result.decision.outcome is not Outcome.ALLOW:
            logger.info("BLOCK CONNECT %s (%s)", target, result.decision.reason_code.value)
            await self._write(writer, _blocked_response(
                _json_error(result.to_dict()), "403 Forbidden"
            ))
            return

        logger.info("TUNNEL %s (contents unenforced)", target)
        try:
            upstream_reader, upstream_writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=30
            )
        except (OSError, asyncio.TimeoutError) as exc:
            await self._write(writer, _blocked_response(
                _json_error({"error": f"upstream connection failed: {exc}"}),
                "502 Bad Gateway",
            ))
            return

        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        await _pipe_both(reader, writer, upstream_reader, upstream_writer)

    @staticmethod
    async def _write(writer: asyncio.StreamWriter, payload: bytes) -> None:
        writer.write(payload)
        await writer.drain()


async def _pipe_both(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    upstream_reader: asyncio.StreamReader,
    upstream_writer: asyncio.StreamWriter,
) -> None:
    """Relay bytes in both directions until either side closes."""

    async def pump(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            while True:
                chunk = await reader.read(65536)
                if not chunk:
                    break
                writer.write(chunk)
                await writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            pass
        finally:
            writer.close()

    await asyncio.gather(
        pump(client_reader, upstream_writer),
        pump(upstream_reader, client_writer),
        return_exceptions=True,
    )


def _agent_from(headers: list[tuple[str, str]]) -> str:
    for key, value in headers:
        if key.lower() == AGENT_HEADER:
            return value.strip() or "unknown"
    return "unknown"


async def serve_forever(
    config: BouncerConfig,
    *,
    host: str = "127.0.0.1",
    port: int = 8081,
    allow_connect: bool = False,
    enforcer: Enforcer | None = None,
) -> None:
    """Run the forward proxy until cancelled."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    engine = enforcer if enforcer is not None else build_enforcer(config)
    proxy = ProxyServer(engine, allow_connect=allow_connect)
    server = await asyncio.start_server(proxy.handle, host, port)
    async with server:
        await server.serve_forever()
