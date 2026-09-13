import socket
import ssl

import pytest

from tlsaudit import (
    NOT_TLS_CHECK_NAME,
    CheckResult,
    ScanReport,
    Verdict,
    display_report,
)
from tlsaudit.scanner import check_cipher_suite, check_protocol_version, scan_host


@pytest.mark.parametrize(
    "version,label,is_deprecated",
    [
        (ssl.TLSVersion.SSLv3, "SSLv3", True),
        (ssl.TLSVersion.TLSv1, "TLS 1.0", True),
        (ssl.TLSVersion.TLSv1_1, "TLS 1.1", True),
    ],
)
def test_deprecated_version_accepted_returns_fail(
    mocker, version, label, is_deprecated
):
    mock_sock = mocker.MagicMock()
    mock_ssock = mocker.MagicMock()
    mock_create_connection = mocker.patch(
        "socket.create_connection", return_value=mock_sock
    )
    mocker.patch("ssl.SSLContext.wrap_socket", return_value=mock_ssock)

    result = check_protocol_version(
        "example.com", 443, version=version, label=label, is_deprecated=is_deprecated
    )

    mock_create_connection.assert_called_once_with(("example.com", 443), timeout=20)
    assert result is not None
    assert result.verdict == Verdict.FAIL


@pytest.mark.parametrize(
    "reason,is_deprecated,expected_verdict",
    [
        ("HANDSHAKE_FAILURE", True, Verdict.PASS),
        ("NO_SHARED_CIPHER", True, Verdict.WARN),
        ("NO_SHARED_CIPHER", False, Verdict.WARN),
        ("NO_PROTOCOLS_AVAILABLE", True, Verdict.WARN),
        ("NO_PROTOCOLS_AVAILABLE", False, Verdict.WARN),
    ],
    ids=[
        "generic_fallback",
        "no_shared_cipher_deprecated",
        "no_shared_cipher_not_deprecated",
        "no_protocols_available_deprecated",
        "no_protocols_available_not_deprecated",
    ],
)
def test_deprecated_version_ssl_error_reason(
    mocker, reason, is_deprecated, expected_verdict
):
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

    result = check_protocol_version(
        "example.com",
        443,
        version=ssl.TLSVersion.TLSv1,
        label="TLS 1.0",
        is_deprecated=is_deprecated,
    )
    assert result is not None
    assert result.verdict == expected_verdict


@pytest.mark.parametrize(
    "version,label,is_deprecated",
    [
        (ssl.TLSVersion.TLSv1_2, "TLS 1.2", False),
        (ssl.TLSVersion.TLSv1_3, "TLS 1.3", False),
    ],
)
def test_current_version_accepted_returns_pass(mocker, version, label, is_deprecated):
    mock_sock = mocker.MagicMock()
    mock_ssock = mocker.MagicMock()
    mock_create_connection = mocker.patch(
        "socket.create_connection", return_value=mock_sock
    )
    mocker.patch("ssl.SSLContext.wrap_socket", return_value=mock_ssock)

    result = check_protocol_version(
        "example.com", 443, version=version, label=label, is_deprecated=is_deprecated
    )
    mock_create_connection.assert_called_once_with(("example.com", 443), timeout=20)
    assert result is not None
    assert result.verdict == Verdict.PASS


def test_timeout_returns_warn(mocker):
    timeout_error = TimeoutError()
    mocker.patch("ssl.SSLContext.wrap_socket", return_value=mocker.MagicMock())
    mock_create_connection = mocker.patch(
        "socket.create_connection", side_effect=timeout_error
    )
    result = check_protocol_version(
        "example.com",
        443,
        version=ssl.TLSVersion.TLSv1,
        label="TLS 1.0",
        is_deprecated=False,
    )
    mock_create_connection.assert_called_once_with(("example.com", 443), timeout=20)
    assert result is not None
    assert result.verdict == Verdict.WARN


def test_handshake_failure_returns_warn(mocker):
    fake_error = ssl.SSLError("Handshake failure")
    fake_error.reason = "HANDSHAKE_FAILURE"
    mocker.patch("ssl.SSLContext.wrap_socket", side_effect=fake_error)
    mocker.patch("socket.create_connection", return_value=mocker.MagicMock())
    result = check_protocol_version(
        "example.com",
        443,
        version=ssl.TLSVersion.TLSv1_3,
        label="TLS 1.3",
        is_deprecated=False,
    )
    assert result is None


@pytest.mark.parametrize(
    "cipher_name,expected_verdict",
    [
        ("ECDHE-RSA-AES256-GCM-SHA384", Verdict.PASS),
        ("ECDHE-RSA-RC4-SHA", Verdict.FAIL),
        ("ECDHE-RSA-DES-CBC3-SHA", Verdict.FAIL),
    ],
    ids=["strong_aes_gcm", "weak_rc4", "weak_cbc"],
)
def test_cipher_suite_returns_expected_verdict(mocker, cipher_name, expected_verdict):
    mock_ssock = mocker.MagicMock()
    mock_ssock.__enter__.return_value = mock_ssock
    mock_ssock.cipher.return_value = (cipher_name,)
    mocker.patch("socket.create_connection", return_value=mocker.MagicMock())
    mocker.patch("ssl.SSLContext.wrap_socket", return_value=mock_ssock)

    result = check_cipher_suite("example.com", 443)

    assert result is not None
    assert result.verdict == expected_verdict


@pytest.mark.parametrize(
    "exception, expected_name, expected_detail",
    [
        (socket.gaierror(), "Hostname", "Could not resolve hostname"),
        (TimeoutError(), "Connection", "Connection timed out"),
        (ConnectionRefusedError(), "Connection", "Connection refused"),
        (ConnectionResetError(), "Connection", "Connection reset"),
        (OSError("Simulated"), "Network Error", "OS Error: Simulated"),
    ],
    ids=["gaierror", "timeout", "connection_refused", "connection_reset", "os_error"],
)
def test_scan_host_stage1_failure(mocker, exception, expected_name, expected_detail):
    mocker.patch("socket.create_connection", side_effect=exception)
    report = scan_host("example.com", 443)

    assert len(report.results) == 1
    assert report.results[0].name == expected_name
    assert report.results[0].detail == expected_detail
    assert report.results[0].verdict == Verdict.WARN


@pytest.mark.parametrize(
    "reason,expected_detail",
    [
        ("RECORD_LAYER_FAILURE", "Provided port does not run TLS"),
        (
            "NO_SHARED_CIPHER",
            "Provided port does not appear to run TLS (NO_SHARED_CIPHER)",
        ),
    ],
    ids=["record_layer_failure", "no_shared_cipher"],
)
def test_scan_host_stage1_ssl_error(mocker, reason, expected_detail):
    fake_error = ssl.SSLError()
    fake_error.reason = reason
    mocker.patch("socket.create_connection", return_value=mocker.MagicMock())
    mocker.patch("ssl.SSLContext.wrap_socket", side_effect=fake_error)
    report = scan_host("example.com", 443)

    assert len(report.results) == 1
    assert report.results[0].name == "Not TLS"
    assert report.results[0].detail == expected_detail
    assert report.results[0].verdict == Verdict.WARN


def test_scan_host_success_assembles_full_report(mocker):
    mock_ssock = mocker.MagicMock()
    mock_ssock.__enter__.return_value = mock_ssock
    mock_ssock.cipher.return_value = ("ECDHE-RSA-AES256-GCM-SHA384",)
    mocker.patch("socket.create_connection", return_value=mocker.MagicMock())
    mocker.patch("ssl.SSLContext.wrap_socket", return_value=mock_ssock)
    report = scan_host("example.com", 443)

    assert len(report.results) == 6
    assert report.results[1].name == "SSL 3.0"
    assert report.results[1].verdict == Verdict.FAIL

    assert report.results[2].name == "TLS 1.0"
    assert report.results[2].verdict == Verdict.FAIL

    assert report.results[3].name == "TLS 1.1"
    assert report.results[3].verdict == Verdict.FAIL

    assert report.results[4].name == "TLS 1.2"
    assert report.results[4].verdict == Verdict.PASS

    assert report.results[5].name == "TLS 1.3"
    assert report.results[5].verdict == Verdict.PASS


def test_display_report_prints_verdict_lines_and_summary(capsys):
    report = ScanReport(
        "example.com",
        443,
        [
            CheckResult(
                "Cipher Suite",
                "Strong cipher suite: TLS_AES_256_GCM_SHA384",
                Verdict.PASS,
            ),
            CheckResult("TLS 1.0", "Deprecated", Verdict.FAIL),
            CheckResult("TLS 1.2", "Connection timed out", Verdict.WARN),
        ],
    )

    display_report(report)
    output = capsys.readouterr().out

    assert "[PASS] Cipher Suite: Strong cipher suite: TLS_AES_256_GCM_SHA384" in output
    assert "[FAIL] TLS 1.0: Deprecated" in output
    assert "[WARN] TLS 1.2: Connection timed out" in output
    assert "PASS: 1 | FAIL: 1 | WARN: 1" in output


def test_display_report_not_tls_shows_banner_not_table(capsys):
    report = ScanReport(
        "example.com",
        80,
        [
            CheckResult(
                NOT_TLS_CHECK_NAME, "Provided port does not run TLS", Verdict.WARN
            ),
        ],
    )

    display_report(report)
    output = capsys.readouterr().out

    assert "NOT A TLS service" in output
    assert "[WARN]" not in output
