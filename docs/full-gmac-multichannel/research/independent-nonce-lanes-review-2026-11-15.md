# Independent nonce-lane submission review

Reviewed against feature `e415bbc5ce68c4c4debe50776b9339432e17b24f` on
2026-11-15. This is a review of the supplied record, patch, mirrored sources,
verifier and evidence summaries. The patch was not applied to the feature.

The submission is useful corroboration of an auxiliary-session construction and
provides a promising independent NTLM key-derivation verifier. Its disjoint lane
argument addresses the original-key binding collision in its stated operating
profile. I found no demonstrated collision in the lane allocation itself. The
submission does not establish closure of the agreed G0 requirements.

## Findings

### P1 — The global uniqueness claim is stronger than its assumptions

`G0-DECISION-RECORD.md:62-70` claims that under A1–A5 no two distinct messages
under an actual key share a nonce. A1 only bounds **non-interim** responses; it
does not exclude a signed interim followed by a signed final response with the
same MessageId/key/role. A2 permits random server notification MessageIds, which
does not rule out collision with another server message. The proof's response
case does not account for those notifications.

This is a gap in the stated proof, not an observed binding collision. State the
guarantee for client-allocated binding/ordinary request identifiers and the
corresponding final replies, and specify the additional server behavior needed
for a broader claim. Keep server notification and interim-response coverage
explicit. A client lane allocator cannot guarantee the server's random choices.
This correction needs an accurate contract and targeted checks, not new
cryptographic research.

The separate G0 closure claim also conflicts with the record's own sections 9
and 11: reauthentication and its bound-channel key interpretation remain open.
Those are explicit items 3 and 6 of the agreed plan's section 3.4. Missing full
Gradle/Java 8 validation is a validation limitation; it is not, by itself, a
reason to reject a design under G0. Windows remains deferred as requested.

### P2 — The verifier can report success without inspecting the relevant traffic

`observer/gmac_analyze.py:186-195` ignores `c2s-dropped` records and merely counts
unrecognized/transform frames. Its exit condition at lines 327-330 checks only
reuse and unverifiable signed messages. Empty input, transform-only input and
dropped-frame-only input all return success with zero verified messages.

The proxy records a dropped client frame after SMBJ has already serialized and
signed it (`observer/gmac_proxy.py`, `pump`). That signing use still matters for
nonce lifetime even though the proxy does not forward it to Samba. Ignoring it
weakens precisely the injected-failure audit.

Reproduced the three coverage-gate false successes using the real parser/report
and CLI, with an import stub that throws if AESGCM is invoked. This exercised
no cryptography and verified no tags; neither installed Python interpreter has
the required `cryptography` package. The result follows from the analyzer's
coverage/exit logic independently of its AES-GMAC implementation.

| Coverage-gate input | CLI exit | Signed messages inspected | Undecodable frames |
| --- | ---: | ---: | ---: |
| Empty capture | 0 | 0 | 0 |
| One transform marker | 0 | 0 | 1 |
| One `c2s-dropped` record | 0 | 0 | 0 |

Require nonempty expected scenario coverage, account for dropped signed inputs,
and reject or explicitly classify traffic the selected audit cannot decode.
Keep encryption audit coverage separate until it is actually implemented.
These findings do not show that the supplied 4,792 counted tags are wrong.

### P2 — Scenario failures do not propagate to the caller

`observer/run_scenario.sh:10-13` prints the Java and analyzer exit codes, then
returns the status of its final `echo`. `run_all.sh:5-7` similarly prints a
summary without aggregating failures. A failed Java run or detected reuse can
therefore leave the runner successful.

Propagate both statuses and assert each scenario's expected outcome, including
explicit expected nonzero statuses for the negative controls. The supplied
positive summaries do contain `java exit=0` and `analyzer exit=0`; this finding
concerns reliable reproduction/automation rather than contradicting those logs.

### P2 — Binding succeeds before auxiliary cleanup is known to succeed

In the mirrored `files/src/main/java/com/hierynomus/smbj/connection/` sources,
`SMBSessionBuilder.java:268-269` publishes the channel and sets `bound=true`.
The `finally` block then calls `MessageIdAdvancer.closeQuietly`, whose lines
147-155 suppress auxiliary LOGOFF failures. A rejected or timed-out LOGOFF can
therefore leave a reported successful channel with an unconfirmed auxiliary
server session. This does not match the decision record's unconditional
successful-cleanup outcome.

The current feature already closes the auxiliary session before channel
publication and preserves owned/borrowed transport failure handling. Retain that
behavior when evaluating any donor adaptation. A successful-binding/failed-LOGOFF
case is needed in addition to failures during authentication and advancement.

## Useful parts and tradeoffs

- Explicit disjoint ranges, monotonically consumed capacity and a guard before
  provider invocation make the binding allocation argument easy to inspect.
- The unsafe and deliberately overlapping-lane controls are valuable. The unsafe
  control is described by the kit as an older feature build with its GMAC
  binding rejection removed; it is not a reproduction against today's feature.
- Deriving NTLMv2/session/channel keys from captured bytes is additional
  independence beyond an observer supplied with client-exported keys. Preserve
  that independence if the verifier is adapted after fixing its coverage gates.
- Fixed lanes bound advancement per candidate, but consume lifetime capacity
  even on failure. Capacity zero disables binding, the maximum is 4,096 attempts,
  and the production path fixes each lane to four authentication exchanges.
  The current feature retains up to sixteen exchanges and does not require this
  fixed lifetime lane budget. These are compatibility choices, not proof of a
  collision in the fixed-lane design.
- Catch-up traffic remains significant: lane i starts at `16 + 4i`. Across C
  bindings this gives quadratic total ECHO work in C. The quoted roughly seven
  round trips assumes the ECHO burst fits a credit window; larger lanes require
  multiple batches. The supplied timing sample uses capacity 16 on loopback.

## Baseline and evidence limits

Read-only `git apply --check` fails on current `Connection`, `SMBSessionBuilder`
and `Session` contexts. The submission targets a prior feature state containing
the blanket GMAC binding rejection. Its statement that reauthentication is
unimplemented does not describe today's branch: the current public API, focused
tests and historical native reauthentication records already exist. Current
source must remain the integration baseline.

The ZIP contains analyzer summaries, configuration, probes and scripts, but no
raw JSONL captures referenced by those summaries. Consequently I could inspect
the verifier and reported totals but could not independently replay the claimed
4,792 successful tag verifications or either negative control from this package.
No live Samba scenario was run for this review. No uploaded setup/install script
was executed.

The supplied 328 Java-only results omit Gradle/Spock, actual Java 8 execution,
Kerberos and encryption-required qualification and use BC 1.77 rather than the
project's 1.86. The reported `ResponseAuthenticationTest` syntax failure is not
present in the current source. The current recorded rebase check is 1,167 cases
in 118 suites, zero failures/errors/skips; that check was not rerun for this
read-only code review and does not validate this patch.

JDT.LS reports STOPPED; the user's existing authorization to continue with
available checks applies. Source/patch comparison used text and Git. Secrets
prechecks reported no findings with an authentication warning; this was not an
authenticated Sonar server analysis.

## Artifact identity

The original user artifacts remain unchanged in `/workspace/plans/`:

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| `G0-DECISION-RECORD.md` | 13288 | `fb8a93f4ad14d533fdddcd74add5808ac15fbbcf58e5e8c58e899674a0effe4f` |
| `g0-nonce-lanes.patch` | 80058 | `e3355e78e8bcee9906ab1aa70a1d7b438847fe3a7a946031df1f20059621c272` |
| `g0-solution.zip` | 111454 | `bf92827cfe2b64e8ad33e8a5576ec4df79eaf668902340c948a04daba6e0ae49` |

No production/test source, dependency, build configuration or gate status changed
in this review. Do not replace the current implementation with the mirrored
older source tree. The immediate reusable contribution is the independent
wire-derived NTLM verifier after its acceptance and failure gates are corrected.
