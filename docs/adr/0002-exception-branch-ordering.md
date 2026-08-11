# 0002 Exception branch ordering in check_protocol_version

## Status
**Accepted**

## Context
`check_protocol_version` pins a TLS handshake to one specific protocol version and
inspects what happens. Handshake failures can come from genuinely different causes,
and the tool needs to tell them apart rather than treating every failure the same way:

- The local environment (OpenSSL build) may refuse to even attempt the requested
  version completely before any packet reaches the server. This was confirmed directly
  by testing SSLv3 against a real host: the handshake failed with
  `NO_PROTOCOLS_AVAILABLE`, a purely local limitation, not a statement about the
  server's behavior.
- The server may reject the handshake for a real, negotiation-level reason
  (e.g. `NO_SHARED_CIPHER`).
- The server may correctly and deliberately reject a deprecated protocol version,
  which is the behavior we actually want to see and report as a pass.

All three cases raise `ssl.SSLError`, and are only distinguishable by inspecting
`e.reason`. If the code cannot tell a local environment limitation apart from a
genuine server rejection, it risks reporting a false PASS, claiming the server was
verified as secure when nothing about the server was actually tested.

## Decision
Inside the `except ssl.SSLError` block, branches are checked in this order:

1. `e.reason == "NO_SHARED_CIPHER"` → local/negotiation limitation, verdict WARN
2. `e.reason == "NO_PROTOCOLS_AVAILABLE"` → local environment cannot attempt this
   version at all, verdict WARN
3. Fallback: `is_deprecated` → the failure is treated as a genuine server-side
   rejection. A deprecated version being rejected is a PASS.

The two reason-specific checks must run **before** the `is_deprecated` fallback,
not after. This was verified with a test: setting `e.reason` to
`NO_PROTOCOLS_AVAILABLE` and moving the `is_deprecated` check first, the test
suite's assertion caught the switch, without correct ordering, that same
scenario resolves to `Verdict.PASS` instead of `Verdict.WARN`, silently claiming
the server correctly rejected the version when in fact the local machine never
managed to test it at all.

## Consequences
- The tool distinguishes "could not test this" (WARN) from "server correctly
  rejected a deprecated version" (PASS) from "server accepted a deprecated
  version" (FAIL), rather than collapsing all failures into one verdict.
- This ordering is load-bearing, not stylistic. Any future change to this
  function must preserve environment-limitation checks running before the
  deprecation fallback or re-verify against the test that currently guards
  this behavior.
- The correctness of this logic depends on OpenSSL continuing to use these
  specific reason strings. This is a known, accepted coupling to an external
  library's internal naming, not something this tool controls.