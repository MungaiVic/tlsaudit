import argparse

from .report import display_report
from .scanner import scan_host


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
