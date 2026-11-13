# GMAC trace audit (non-sensitive metadata only)

Run from this directory:

```bash
python3 -m unittest -v test_audit_gmac_nonce_trace.py
python3 audit_gmac_nonce_trace.py ../gmac-binding-observation.json \
  --expect-different-message-reuses 2
python3 audit_gmac_nonce_trace.py ../auxiliary-observation.json \
  --expect-different-message-reuses 0
```

The Go/Samba ordinary binding trace contains **three repeated key/nonce pairs**:
one repeated same authenticated byte string (events 11/19), and **two with
*different* authenticated messages** (12/20 and 13/21). These were independently
verified in the source observer.

The auxiliary trace includes four positive experiments (385 printed signed
events) and a partial `unsafe-control` negative trace (6 excluded events). The auxiliary recorder prints only a subset of
signed messages; therefore this audit is **not a lifetime-wide proof of GMAC
nonce uniqueness**. The control's expected assertion was recorded by its JUnit
run, but the sanitized text stops at the observer's assertion before printing
the actual different-message collision. The auditor explicitly **excludes** the
partial negative-control run from positive counts and collision claims.

The auditor uses only ephemeral keyed equality IDs, nonces, MessageIds, and
message fingerprints. It does not ingest raw signing keys, authentication
tokens, or complete SMB packets. It refuses to score unverified Go events.

Exit codes: 0 for success (or exact expected collision count), 1 for a different
count than requested, 2 for unexpected collision(s) without an expectation,
and 3 for invalid input/metadata.
