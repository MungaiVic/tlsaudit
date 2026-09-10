import socket
import ssl

from .report import (
    NOT_TLS_CHECK_NAME,
    WEAK_CIPHER_MARKERS,
    CheckResult,
    ScanReport,
    Verdict,
    VersionSpec,
)


def check_protocol_version(
    hostname: str, port: int, version: ssl.TLSVersion, label: str, is_deprecated: bool
) -> CheckResult | None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = context.maximum_version = version

    try:
        with (
            socket.create_connection((hostname, port), timeout=20) as sock,
            context.wrap_socket(sock, server_hostname=hostname),
        ):
            if is_deprecated:
                return CheckResult(label, "Deprecated", Verdict.FAIL)
            return CheckResult(label, "Supported", Verdict.PASS)

    except ssl.SSLError as e:
        if e.reason == "NO_SHARED_CIPHER":
            return CheckResult(label, "No shared cipher", Verdict.WARN)
        elif e.reason == "NO_PROTOCOLS_AVAILABLE":
            return CheckResult(label, "No protocols available", Verdict.WARN)
        if is_deprecated:
            return CheckResult(label, "Not supported & Deprecated", Verdict.PASS)
        return None
    except TimeoutError:
        return CheckResult(label, "Connection timed out", Verdict.WARN)


def check_cipher_suite(hostname: str, port: int = 443) -> CheckResult:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with (
            socket.create_connection((hostname, port), timeout=20) as sock,
            context.wrap_socket(sock, server_hostname=hostname) as ssock,
        ):
            cipher_info = ssock.cipher()
            if cipher_info is None:
                return CheckResult("Cipher Suite", "No cipher negotiated", Verdict.WARN)
            cipher_name = cipher_info[0]

        if any(marker in cipher_name for marker in WEAK_CIPHER_MARKERS):
            return CheckResult(
                "Cipher Suite", f"Weak cipher negotiated: {cipher_name}", Verdict.FAIL
            )
        else:
            return CheckResult(
                "Cipher Suite", f"Strong cipher suite: {cipher_name}", Verdict.PASS
            )
    except TimeoutError:
        return CheckResult("Cipher Suite", "Connection timed out", Verdict.WARN)


def scan_host(hostname: str, port: int) -> ScanReport:
    report = ScanReport(hostname, port)
    target_versions = [
        VersionSpec(ssl.TLSVersion.SSLv3, "SSL 3.0", True),
        VersionSpec(ssl.TLSVersion.TLSv1, "TLS 1.0", True),
        VersionSpec(ssl.TLSVersion.TLSv1_1, "TLS 1.1", True),
        VersionSpec(ssl.TLSVersion.TLSv1_2, "TLS 1.2", False),
        VersionSpec(ssl.TLSVersion.TLSv1_3, "TLS 1.3", False),
    ]
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with (
            socket.create_connection((hostname, port), timeout=10) as sock,
            context.wrap_socket(sock, server_hostname=hostname),
        ):
            pass
        check_cipher_suite_result = check_cipher_suite(hostname, port)
        report.results.append(check_cipher_suite_result)
        for version in target_versions:
            try:
                result = check_protocol_version(
                    hostname,
                    port,
                    version.version,
                    version.label,
                    version.is_deprecated,
                )
                if result:
                    report.results.append(result)
            except Exception as e:  # noqa: BLE001 — deliberate safety net; check_protocol_version already handles its known exception types internally
                report.results.append(
                    CheckResult(
                        version.label, f"Could not complete check: {e!s}", Verdict.WARN
                    )
                )
        return report
    except socket.gaierror:
        return ScanReport(
            hostname,
            port,
            [CheckResult("Hostname", "Could not resolve hostname", Verdict.WARN)],
        )
    except TimeoutError:
        return ScanReport(
            hostname,
            port,
            [CheckResult("Connection", "Connection timed out", Verdict.WARN)],
        )
    except ConnectionRefusedError:
        return ScanReport(
            hostname,
            port,
            [CheckResult("Connection", "Connection refused", Verdict.WARN)],
        )
    except ConnectionResetError:
        return ScanReport(
            hostname,
            port,
            [CheckResult("Connection", "Connection reset", Verdict.WARN)],
        )
    except ssl.SSLError as e:
        if e.reason == "RECORD_LAYER_FAILURE":
            return ScanReport(
                hostname,
                port,
                [
                    CheckResult(
                        NOT_TLS_CHECK_NAME,
                        "Provided port does not run TLS",
                        Verdict.WARN,
                    )
                ],
            )
        return ScanReport(
            hostname,
            port,
            [
                CheckResult(
                    NOT_TLS_CHECK_NAME,
                    f"Provided port does not appear to run TLS ({e.reason})",
                    Verdict.WARN,
                )
            ],
        )
    except OSError as e:
        return ScanReport(
            hostname,
            port,
            [CheckResult("Network Error", f"OS Error: {e}", Verdict.WARN)],
        )
