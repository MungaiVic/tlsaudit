# tlsaudit

A command-line TLS/cipher auditor. Points at a host, tests which TLS/SSL protocol
versions it accepts and how strong its negotiated cipher suite is, then reports
findings as a simple PASS/FAIL/WARN table.

Standard library only (`ssl`, `socket`, `argparse`), no dependencies to install.

## What it checks

**Protocol version support** — tests SSLv3, TLS 1.0, TLS 1.1, TLS 1.2, and TLS 1.3
individually by pinning the handshake to each version in turn.

- A deprecated version (SSLv3, TLS 1.0, TLS 1.1) that the server still **accepts**
  is a **FAIL**.
- A deprecated version that the server correctly **rejects** is a **PASS**, that's
  the server behaving securely.
- TLS 1.2 or TLS 1.3 being **supported** is a **PASS**.
- TLS 1.2 or TLS 1.3 **not** being supported produces no result at all, that's not
  a finding worth reporting in Phase 1, it just means the server doesn't offer that
  particular version.

**Cipher suite strength** — connects normally (letting the server negotiate freely)
and checks the resulting cipher name against known-weak markers: `RC4`, `3DES`,
`NULL`, `EXPORT`, `CBC`.

## Usage

```bash
python3 tlsaudit.py <hostname> [--port PORT]
```

Port defaults to 443.

Example:

```
$ python3 tlsaudit.py github.com
[*] Auditing github.com on port 443
[+] TLS Audit Report for github.com:443
[PASS] Cipher Suite: Strong cipher suite: TLS_AES_256_GCM_SHA384
[PASS] TLS 1.2: Supported
[PASS] TLS 1.3: Supported

[+] Verdict Summary: PASS: 3 | FAIL: 0 | WARN: 0
```

If the target isn't running TLS at all (wrong port, plain HTTP, etc.), the tool
prints a distinct banner instead of the normal table:

```
$ python3 tlsaudit.py example.com --port 80
[*] Auditing example.com on port 80
[+] TLS Audit Report for example.com:80
------------------------------------------------------------
[!] NOT A TLS service: Provided port does not run TLS
------------------------------------------------------------
```

## Known limitations (by design, not bugs)

- **No certificate validation yet.** This is Phase 1, only protocol version and
  cipher strength are checked. Certificate chain validation, expiry, key size,
  and hostname/SAN matching are planned for Phase 2.
- **SSLv3 is often untestable on modern systems.** Current OpenSSL builds
  frequently disable SSLv3 entirely at compile time, as a hardening measure. On
  those systems, testing SSLv3 fails locally before any packet reaches the
  server, and shows as a WARN ("no protocols available"), not a PASS or FAIL,
  since nothing was actually verified about the server itself.
- **A timeout doesn't necessarily mean nothing's there.** A well-configured
  firewall silently dropping unsolicited connections looks identical, from this
  tool's perspective, to a genuinely unreachable host. `Connection refused` (an
  explicit rejection) and `Connection timed out` (no response at all) are
  reported separately and mean different things.
- **Single host only.** No batch scanning from a file yet, and no JSON output.
  Both are planned for Phase 3.

## Roadmap

This is Phase 1 of a larger plan:

- **Phase 2** — certificate chain validation, expiry, key size, SAN matching
- **Phase 3** — batch scanning from a host list, JSON output
- **Phase 4** — HTTP security headers, A-F scoring, CAA/OCSP checks, and more

## Responsible Usage

**DO NOT** scan hosts you are not expressly authorized to do so. Doing so may land you in trouble with
the owners of the host. Therefore, seek permission from the owner before scanning.

## License

TBD, add MIT or Apache 2.0 once decided.