# 0001 Context per function

## Status
**Accepted**

## Context
`check_protocol_version`, `check_cipher_suite`, and `scan_host`'s stage-1
reachability check each need an `ssl.SSLContext` configured with different,
sometimes opposite, settings:

- `check_protocol_version` needs `minimum_version`/`maximum_version` pinned to
  one specific protocol version, and `verify_mode = CERT_NONE`, since it's
  probing what the server *offers*, not validating trust.
- `check_cipher_suite` needs an *unpinned* context (no version constraint at
  all), so the server can negotiate freely, the same way a real client would.
- Phase 2's future certificate-validation checks will need the opposite trust
  posture entirely: `verify_mode = CERT_REQUIRED` and `check_hostname = True`,
  since validating a certificate chain is the whole point of that check.

`ssl.SSLContext` is a mutable object. If one shared instance were built once,
at module level, and reused across functions, a setting one function needs
for its own purposes would silently apply to every other function using that
same object. A function that set `verify_mode = CERT_NONE` for its own probe
would leave that setting in place for whatever ran next, even if the next
function genuinely needed `CERT_REQUIRED`. This isn't a resource leak (`with`
already handles closing each connection correctly), it's shared mutable
configuration state producing wrong results silently, no error, no exception,
just a check running with the wrong trust posture and reporting an incorrect
verdict.

## Decision
Each function that performs a check constructs its own `ssl.SSLContext`,
explicitly setting only the attributes it needs:

```python
import ssl
...
def check_protocol_version(hostname, port, version, label, is_deprecated):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = context.maximum_version = version
    ...

def check_cipher_suite(hostname, port=443):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    # no version pinning — let the server negotiate freely
    ...
```

A shared, module-level context was considered and rejected specifically
because Phase 1 and Phase 2 need contradictory trust postures. No single
shared configuration can correctly serve both without one check
overwriting settings the other depends on.

## Consequences
- Every check's trust posture is explicit and self-contained at the top of
  its own function. Reading any single function tells you exactly what it
  trusts, without needing to trace back to a shared object defined elsewhere.
- The same 3–4 lines of context setup are repeated across every check
  function. This is a deliberate, accepted cost, small, obvious repetition
  in exchange for eliminating a whole class of silent cross-function
  configuration bugs.
- Adding a new check never risks breaking an existing one's trust
  configuration, each function's context is fully isolated by construction.