import argparse
import socket
import ssl
import warnings
from collections import Counter
from dataclasses import dataclass, field
from enum import Enum

warnings.filterwarnings("ignore", category=DeprecationWarning)

WEAK_CIPHER_MARKERS = ["RC4", "3DES", "NULL", "EXPORT", "CBC"]
NOT_TLS_CHECK_NAME = "Not TLS"

class Verdict(Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"

@dataclass
class VersionSpec:
    version: ssl.TLSVersion
    label: str
    is_deprecated: bool

@dataclass
class CheckResult:
    name: str # which check this is, e.g. "TLS 1.0" or "Cipher Suite"
    detail: str
    verdict: Verdict

@dataclass
class ScanReport:
    hostname: str
    port: int
    results: list[CheckResult] = field(default_factory=list)


def check_protocol_version(hostname: str, port: int, version: ssl.TLSVersion, label: str, is_deprecated: bool) \
        -> CheckResult | None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = context.maximum_version = version

    try:
        with socket.create_connection((hostname, port), timeout=20) as sock, \
            context.wrap_socket(sock, server_hostname=hostname) as ssock:
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
    except TimeoutError:
        return CheckResult(label, "Connection timed out", Verdict.WARN)

def check_cipher_suite(hostname: str, port: int = 443) -> CheckResult:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((hostname, port), timeout=20) as sock, \
            context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cipher_name = ssock.cipher()[0]

        if any(marker in cipher_name for marker in WEAK_CIPHER_MARKERS):
            return CheckResult("Cipher Suite", f"Weak cipher negotiated: {cipher_name}", Verdict.FAIL)
        else:
            return CheckResult("Cipher Suite", f"Strong cipher suite: {cipher_name}", Verdict.PASS)
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
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                pass
        check_cipher_suite_result = check_cipher_suite(hostname, port)
        report.results.append(check_cipher_suite_result)
        for version in target_versions:
            try:
                result = check_protocol_version(hostname, port, version.version, version.label, version.is_deprecated)
                if result:
                    report.results.append(result)
            except Exception as e:
                report.results.append(CheckResult(version.label, f"Could not complete check: {e!s}", Verdict.WARN))
        return report
    except socket.gaierror:
        return ScanReport(hostname, port, [CheckResult("Hostname", "Could not resolve hostname", Verdict.WARN)])
    except TimeoutError:
        return ScanReport(hostname, port, [CheckResult("Connection", "Connection timed out", Verdict.WARN)])
    except ConnectionRefusedError:
        return ScanReport(hostname, port, [CheckResult("Connection", "Connection refused", Verdict.WARN)])
    except ConnectionResetError:
        return ScanReport(hostname, port, [CheckResult("Connection", "Connection reset", Verdict.WARN)])
    except ssl.SSLError as e:
        if e.reason == "RECORD_LAYER_FAILURE":
            return ScanReport(hostname, port,
                              [CheckResult(NOT_TLS_CHECK_NAME, "Provided port does not run TLS", Verdict.WARN)])
        return ScanReport(hostname, port,
                          [CheckResult(NOT_TLS_CHECK_NAME, f"Provided port does not appear to run TLS ({e.reason})",
                                       Verdict.WARN)])
    except OSError as e:
        return ScanReport(hostname, port, [CheckResult("Network Error", f"OS Error: {e}", Verdict.WARN)])


def display_report(report: ScanReport):
    print(f"[+] TLS Audit Report for {report.hostname}:{report.port}")
    if len(report.results) == 1 and report.results[0].name == NOT_TLS_CHECK_NAME:
        print('-' * 40)
        print(f"[!] NOT A TLS service: {report.results[0].detail}")
        print('-' * 40)
        return

    for result in report.results:
        print(f"[{result.verdict.value}] {result.name}: {result.detail}")

    verdict_count = Counter({v: 0 for v in Verdict})
    verdict_count.update(result.verdict for result in report.results)

    summary_part = [f"{v.value}: {verdict_count[v]}" for v in Verdict]
    one_liner = " | ".join(summary_part)
    print(f"\n[+] Verdict Summary: {one_liner}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("hostname", type=str, help="Hostname to audit")
    parser.add_argument("-p", "--port", type=int, default=443, help="Port to audit")
    args = parser.parse_args()

    print(f"[*] Auditing {args.hostname} on port {args.port}")
    report = scan_host(args.hostname, args.port)

    display_report(report)


if __name__ == "__main__":
    main()