import ssl
import argparse
import socket
import warnings

from dataclasses import dataclass, field
from enum import Enum

warnings.filterwarnings("ignore", category=DeprecationWarning)

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
        with socket.create_connection((hostname, port), timeout=20) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                if is_deprecated:
                    return CheckResult(label, "Deprecated", Verdict.FAIL)
                return CheckResult(label, "Supported", Verdict.PASS)

    except ssl.SSLError:
        if is_deprecated:
            return CheckResult(label, "Not supported & Deprecated", Verdict.PASS)
        return None
    except socket.timeout:
        return CheckResult(label, "Connection timed out", Verdict.WARN)

def scan_host(hostname: str, port: int) -> ScanReport:
    report = ScanReport(hostname, port)
    target_versions = [
        VersionSpec(ssl.TLSVersion.TLSv1, "TLS 1.0", True),
        VersionSpec(ssl.TLSVersion.TLSv1_1, "TLS 1.1", True),
        VersionSpec(ssl.TLSVersion.TLSv1_2, "TLS 1.2", False),
        VersionSpec(ssl.TLSVersion.TLSv1_3, "TLS 1.3", False),
        VersionSpec(ssl.TLSVersion.SSLv3, "SSL 3.0", True),
    ]
    try:
        for version in target_versions:
            result = check_protocol_version(hostname, port, version.version, version.label, version.is_deprecated)
            if result:
                report.results.append(result)
        return report
    except Exception as e:
        print(f"[-] Error scanning {hostname}: {e}")

def check_cipher_suite(hostname: str, port: int = 443):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((hostname, port), timeout=20) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                print(f"Cipher is: {ssock.cipher()}")
    except socket.timeout:
        print("[-] Connection timed out")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("hostname", type=str, help="Hostname to audit")
    parser.add_argument("-p", "--port", type=int, default=443, help="Port to audit")
    args = parser.parse_args()

    print(f"[*] Auditing {args.hostname} on port {args.port}")
    scan_host(args.hostname, args.port)


if __name__ == "__main__":
    main()