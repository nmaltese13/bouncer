"""Request splitting through the forward proxy.

What the client sends and what bouncer forwards upstream must be the same
request. The forwarder rebuilds it by joining header names and values with
CRLF, so any control character that survives parsing becomes a header boundary
at the upstream.
"""

from __future__ import annotations

import pytest

from bouncer.forward_proxy import ProxyError, _parse_request_head

HEAD = b"POST http://api.vendor.example/pay HTTP/1.1\r\n"
TAIL = b"\r\n"


def head_with(header: bytes) -> bytes:
    return HEAD + header + b"\r\n" + TAIL


@pytest.mark.parametrize(
    "value,label",
    [
        (b"a\nX-Injected: bad", "bare LF"),
        (b"a\rX-Injected: bad", "bare CR"),
        (b"a\x00b", "NUL"),
        (b"a\x1fb", "unit separator"),
        (b"a\x7fb", "DEL"),
    ],
)
def test_a_control_character_in_a_header_value_is_refused(
    value: bytes, label: str
) -> None:
    """Splitting on CRLF alone left a bare LF intact inside a header value.

    An upstream that accepts LF-terminated headers -- many do -- would read
    everything after the newline as a header of its own, letting an agent inject
    into a request bouncer had already approved, up to and including a competing
    X-Bouncer-Mandate. The audit row would then no longer describe what actually
    left the machine.

    Refused rather than stripped: silently forwarding a request the client did
    not send is the same class of problem in the other direction.
    """
    with pytest.raises(ProxyError, match="control character"):
        _parse_request_head(head_with(b"X-Note: " + value))


def test_a_control_character_in_the_request_line_is_refused() -> None:
    with pytest.raises(ProxyError, match="control character"):
        _parse_request_head(
            b"POST http://api.vendor.example/pay\nHTTP/1.1 X\r\nHost: x\r\n\r\n"
        )


@pytest.mark.parametrize("name", [b"X Note", b"X;Note", b"X(Note", b"X@Note"])
def test_a_header_name_that_is_not_a_token_is_refused(name: bytes) -> None:
    """A name carrying a delimiter cannot be written back out intact."""
    with pytest.raises(ProxyError, match="malformed header name"):
        _parse_request_head(head_with(name + b": value"))


def test_a_malformed_method_is_refused() -> None:
    with pytest.raises(ProxyError, match="malformed method"):
        _parse_request_head(b'PO"ST http://x/p HTTP/1.1\r\nHost: x\r\n\r\n')


def test_ordinary_headers_still_parse() -> None:
    """The guard must not reject the traffic the proxy exists to forward."""
    method, target, _version, headers = _parse_request_head(
        HEAD
        + b"Host: api.vendor.example\r\n"
        + b"X-Bouncer-Agent: research-bot\r\n"
        + b"Content-Type: application/json\r\n"
        + b"Authorization: Bearer sk_test_abc123\r\n"
        + b"Content-Length: 42\r\n"
        + TAIL
    )
    assert method == "POST"
    assert target == "http://api.vendor.example/pay"
    assert dict(headers) == {
        "Host": "api.vendor.example",
        "X-Bouncer-Agent": "research-bot",
        "Content-Type": "application/json",
        "Authorization": "Bearer sk_test_abc123",
        "Content-Length": "42",
    }


def test_a_value_may_still_contain_spaces_and_punctuation() -> None:
    """Only control characters are forbidden, not ordinary field content."""
    _m, _t, _v, headers = _parse_request_head(
        head_with(b'User-Agent: agent/1.0 (compatible; "quoted", a=b)')
    )
    assert headers[0][1] == 'agent/1.0 (compatible; "quoted", a=b)'
