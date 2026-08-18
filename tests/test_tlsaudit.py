import ssl

import pytest

from tlsaudit import Verdict, check_protocol_version


@pytest.mark.parametrize("version,label,is_deprecated", [
    (ssl.TLSVersion.SSLv3, "SSLv3", True),
    (ssl.TLSVersion.TLSv1, "TLS 1.0", True),
    (ssl.TLSVersion.TLSv1_1, "TLS 1.1", True),])
def test_deprecated_version_accepted_returns_fail(
        mocker, version, label, is_deprecated):
    mock_sock = mocker.MagicMock()
    mock_ssock = mocker.MagicMock()
    mock_create_connection = mocker.patch("socket.create_connection", return_value=mock_sock)
    mocker.patch("ssl.SSLContext.wrap_socket", return_value=mock_ssock)

    result = check_protocol_version(
        "example.com", 443,
        version=version, label=label, is_deprecated=is_deprecated)

    mock_create_connection.assert_called_once_with(("example.com", 443), timeout=20)
    assert result is not None
    assert result.verdict == Verdict.FAIL


@pytest.mark.parametrize("reason,is_deprecated,expected_verdict", [
    ("HANDSHAKE_FAILURE", True, Verdict.PASS),
    ("NO_SHARED_CIPHER", True, Verdict.WARN),
    ("NO_SHARED_CIPHER", False, Verdict.WARN),
    ("NO_PROTOCOLS_AVAILABLE", True, Verdict.WARN),
    ("NO_PROTOCOLS_AVAILABLE", False, Verdict.WARN),
], ids=["generic_fallback", "no_shared_cipher_deprecated", "no_shared_cipher_not_deprecated",
        "no_protocols_available_deprecated", "no_protocols_available_not_deprecated"])
def test_deprecated_version_ssl_error_reason(mocker, reason, is_deprecated, expected_verdict):
    """Verify check_protocol_version's verdict for each known SSLError reason.

    NO_SHARED_CIPHER and NO_PROTOCOLS_AVAILABLE are local/negotiation
    limitations and must verdict WARN regardless of is_deprecated (tested
    with both True and False). HANDSHAKE_FAILURE represents a genuine
    server-side rejection and only makes sense with is_deprecated=True —
    the False case for that reason returns None, not a verdict, and is
    covered separately.
    """
    fake_error = ssl.SSLError("Simulated")
    fake_error.reason = reason
    mocker.patch("ssl.SSLContext.wrap_socket", side_effect=fake_error)
    mocker.patch("socket.create_connection", return_value=mocker.MagicMock())

    result = check_protocol_version("example.com", 443,
                                    version=ssl.TLSVersion.TLSv1, label="TLS 1.0",
                                    is_deprecated=is_deprecated)
    assert result is not None
    assert result.verdict == expected_verdict


@pytest.mark.parametrize("version,label,is_deprecated", [
    (ssl.TLSVersion.TLSv1_2, "TLS 1.2", False),
    (ssl.TLSVersion.TLSv1_3, "TLS 1.3", False),
])
def test_current_version_accepted_returns_pass(mocker, version, label, is_deprecated):
    mock_sock = mocker.MagicMock()
    mock_ssock = mocker.MagicMock()
    mock_create_connection = mocker.patch("socket.create_connection", return_value=mock_sock)
    mocker.patch("ssl.SSLContext.wrap_socket", return_value=mock_ssock)

    result = check_protocol_version("example.com", 443,
                                    version=version, label=label, is_deprecated=is_deprecated)
    mock_create_connection.assert_called_once_with(("example.com", 443), timeout=20)
    assert result is not None
    assert result.verdict == Verdict.PASS


def test_timeout_returns_warn(mocker):
    timeout_error = TimeoutError()
    mocker.patch("ssl.SSLContext.wrap_socket", return_value=mocker.MagicMock())
    mock_create_connection = mocker.patch("socket.create_connection", side_effect=timeout_error)
    result = check_protocol_version("example.com", 443,
                                    version=ssl.TLSVersion.TLSv1, label="TLS 1.0",
                                    is_deprecated=False)
    mock_create_connection.assert_called_once_with(("example.com", 443), timeout=20)
    assert result is not None
    assert result.verdict == Verdict.WARN


def test_handshake_failure_returns_warn(mocker):
    fake_error= ssl.SSLError("Handshake failure")
    fake_error.reason = "HANDSHAKE_FAILURE"
    mocker.patch("ssl.SSLContext.wrap_socket", side_effect=fake_error)
    mocker.patch("socket.create_connection", return_value=mocker.MagicMock())
    result = check_protocol_version("example.com", 443,
                                    version=ssl.TLSVersion.TLSv1_3, label="TLS 1.3",
                                    is_deprecated=False)
    assert result is None
