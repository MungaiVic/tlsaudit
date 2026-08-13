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
        version, label, is_deprecated)

    mock_create_connection.assert_called_once_with(("example.com", 443), timeout=20)
    assert result is not None
    assert result.verdict == Verdict.FAIL


def test_deprecated_version_rejected_returns_pass(mocker):
    fake_error = ssl.SSLError("Simulated")
    fake_error.reason = "HANDSHAKE_FAILURE"
    mocker.patch("ssl.SSLContext.wrap_socket", side_effect=fake_error)
    mocker.patch("socket.create_connection", return_value=mocker.MagicMock())

    result = check_protocol_version("example.com", 443, ssl.TLSVersion.TLSv1, "TLS 1.0", True)
    assert result is not None
    assert result.verdict == Verdict.PASS


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