import ssl
from collections import Counter
from dataclasses import dataclass, field
from enum import Enum

NOT_TLS_CHECK_NAME = "Not TLS"
WEAK_CIPHER_MARKERS = ["RC4", "3DES", "NULL", "EXPORT", "CBC"]


class Verdict(Enum):
    PASS = "PASS"  # nosec: B105 - num member, not a credential; Bandit's heuristic matches on the name "PASS"
    FAIL = "FAIL"
    WARN = "WARN"


@dataclass
class VersionSpec:
    version: ssl.TLSVersion
    label: str
    is_deprecated: bool


@dataclass
class CheckResult:
    name: str  # which check this is, e.g. "TLS 1.0" or "Cipher Suite"?
    detail: str
    verdict: Verdict


@dataclass
class ScanReport:
    hostname: str
    port: int
    results: list[CheckResult] = field(default_factory=list)


def display_report(report: ScanReport):
    print(f"[+] TLS Audit Report for {report.hostname}:{report.port}")
    if len(report.results) == 1 and report.results[0].name == NOT_TLS_CHECK_NAME:
        print("-" * 40)
        print(f"[!] NOT A TLS service: {report.results[0].detail}")
        print("-" * 40)
        return

    for result in report.results:
        print(f"[{result.verdict.value}] {result.name}: {result.detail}")

    verdict_count = Counter({v: 0 for v in Verdict})
    verdict_count.update(result.verdict for result in report.results)

    summary_part = [f"{v.value}: {verdict_count[v]}" for v in Verdict]
    one_liner = " | ".join(summary_part)
    print(f"\n[+] Verdict Summary: {one_liner}")
