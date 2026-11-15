# Upstream donor review: connection recovery and directory leases

Reviewed 2026-11-15 against G0 `6e1fb8e`, followed by the validated integration
checkpoint `bbad850`. The five PRs below were open and unmerged when their
GitHub API metadata and immutable source heads were retrieved. None was imported
by this review. Source findings below are not claims that the donor suites ran.

Recommendation: bring **#892, #901 and #898** as upstream-based fix branches,
with their original commits intact. Use the upstream implementation as the
baseline, then keep necessary G0 adaptations in separate commits. #917 is useful
for upstream alignment and its tests, but supplies no missing G0 mechanism.
#893's reader-stop behavior already exists in G0; retain the stronger teardown.

| PR | Pinned head | Decision |
| --- | --- | --- |
| [#892](https://github.com/hierynomus/smbj/pull/892) | `2b044b6aa61659142091df916ed2c6ccb1f660e0` | Bring its root ParentLeaseKey fix and regression. G0's tree-scoped keys already solve its cross-share collision. |
| [#901](https://github.com/hierynomus/smbj/pull/901) | `97d85182d309f567ef002712928d53a209d753e5` | Bring nested DFS replacement, connection-lease release, and already-closed-share handling. Adapt to logical-session liveness and existing abort/pool ownership. |
| [#898](https://github.com/hierynomus/smbj/pull/898) | `58e35e44e7b43c4a7a7b4f86d14be165885b7c33` | Primary donor for reference counting, generation-checked publication, serialized scans, mutation invalidation, and non-waiting CLOSE response observation. Requires G0 ownership/lifetime integration. |
| [#917](https://github.com/hierynomus/smbj/pull/917) | `d78094d9b8fd0c47c2e52fd1279c0c6c97ead404` | Optional alignment/tests. G0 already aborts independently of pooled lease count, wakes credit waiters, fails requests and disconnects without LOGOFF. |
| [#893](https://github.com/hierynomus/smbj/pull/893) | `a0304f548ef5f0d375b47c9166513ec2d93b4468` | Reader-stop regression is useful; its inherited write-lock/stream-close teardown must not replace G0's raw-socket close outside the writer lock. |

## Must fix when assembling the combined branch

1. **Do not discard #892 as redundant.** A share root's `SmbPath.getParent()`
   returns itself. G0 mints the root key before looking up the parent, so
   `DiskShare.java:190-192` can send that same key as ParentLeaseKey. #892 adds
   the missing non-root guard. #898 looks up the parent before acquisition,
   which avoids the first-open case but still allows self-reference on a
   repeated root open. Preserve #892's guard when reconciling #898's rewrite.
   Otherwise the root CREATE still carries a false parent relationship.
   [Donor guard](https://github.com/nova-video-player/smbj/blob/2b044b6aa61659142091df916ed2c6ccb1f660e0/src/main/java/com/hierynomus/smbj/share/DiskShare.java#L195),
   [replacement path](https://github.com/Doddddd/smbj/blob/58e35e44e7b43c4a7a7b4f86d14be165885b7c33/src/main/java/com/hierynomus/smbj/share/DiskShare.java#L216).

2. **#898 must retain exact tree identity and terminal-state checks.** Its index
   uses share name plus path, and its cache-hit check verifies the Session but
   not the exact TreeConnect. Closing and reopening the same share in one
   Session can therefore find the old tree's entry unless tree teardown removes
   it. Also, `close()` clears the maps and stops the executors, but a later
   `acquire()` can register another entry: no closed guard prevents it. Retain
   G0's immutable tree owner, per-tree/per-session release, closed-owner checks,
   queued-break identity and canonical-manager lifetime. Otherwise cached state
   or leases can outlive their owning tree or lose break handling after shutdown.
   [Index/acquisition](https://github.com/Doddddd/smbj/blob/58e35e44e7b43c4a7a7b4f86d14be165885b7c33/src/main/java/com/hierynomus/smbj/connection/LeaseManager.java#L143),
   [cache hit](https://github.com/Doddddd/smbj/blob/58e35e44e7b43c4a7a7b4f86d14be165885b7c33/src/main/java/com/hierynomus/smbj/share/DiskShare.java#L451),
   [shutdown](https://github.com/Doddddd/smbj/blob/58e35e44e7b43c4a7a7b4f86d14be165885b7c33/src/main/java/com/hierynomus/smbj/connection/LeaseManager.java#L245).

3. **#901's nested-session health check needs the multichannel predicate.** It
   treats `existingSession.getConnection().isConnected()` as session health.
   In G0 the original connection may be retired while an authenticated bound
   channel still serves the same session and its open files. Importing the check
   unchanged would replace that healthy logical session. Test surviving-channel
   liveness and release the exact acquired connection lease once. Keep G0's
   complete abort path and identity-based pool eviction when resolving overlap.
   Otherwise DFS can replace healthy sessions and retain their surviving resources.
   [Nested-session selection](https://github.com/Bardioc1977/smbj/blob/97d85182d309f567ef002712928d53a209d753e5/src/main/java/com/hierynomus/smbj/session/Session.java#L179).

4. **#893's complete teardown is unsuitable for a blocked writer.** It stops the
   reader only after taking the same write lock held during socket writes, then
   closes the buffered output stream before the raw socket. A stalled writer can
   prevent shutdown from reaching socket closure, and stream close can flush.
   This is inherited behavior retained by the PR, not a new defect introduced
   by its reader-stop change. Preserve G0's terminal publication gate and raw
   socket closure outside that lock; keep the already-disconnected-reader test.
   Otherwise findings #2/#3 from the full GMAC plan regress.
   [Donor disconnect](https://github.com/arimu1/smbj/blob/a0304f548ef5f0d375b47c9166513ec2d93b4468/src/main/java/com/hierynomus/smbj/transport/tcp/direct/DirectTcpTransport.java#L108).

## Remaining coverage and resource work

- #898 has substantial useful tests for an early break racing CREATE, rollback
  of a second CREATE, detached entries retaining routing, concurrent scans,
  invalidation during enumeration, DFS redirection and separate Session access.
  Its Session-owner guard must be preserved; it is not absent from this donor.
- Its CLOSE observers use eight workers, an unbounded queue and an indefinite
  response wait. If a live peer leaves many CLOSE requests unanswered, queued
  observers and lease reservations accumulate. G0 resource qualification must
  cover that path without dropping an already-sent request's completion or
  blocking the break worker. Forced teardown must still perform no remote CLOSE.
- #901's `createNestedSession()` still acquires a connection before calling
  `authenticate()` without releasing that lease if authentication throws. Its
  donor tests cover successful nested lifecycle, not this failure. The PR also
  explicitly leaves `DFSPathResolver.sendDfsReferralRequest()` session/connection
  release unresolved. Neither gap should be described as fixed by importing #901.
- #898 additionally changes `SmbFiles.copy/write` error behavior: null arguments
  and missing/non-file sources stop returning zero and throw instead. Treat this
  as an explicit compatibility change when preparing the donor branch, separate
  from the cache-lifecycle justification.

## Preserve the donor, then add the G0 integration

KEEP #898's handle reservations, final-close release, generation checks, scan
serialization, mutation hooks, no-wait response observation and regression tests.
SUBSTITUTE exact TreeConnect identity for its share/path ownership boundary.
REWIRE cleanup and break routing through G0's canonical manager and surviving
channels. BORROW #892's root guard and #901's nested connection ownership work.
CUSTOM remains the existing G0 GMAC binding/key-lifetime mechanism and the
necessary multichannel/terminal-state connections; this review adds no new one.

#901's original series is `be6328094f1129c3934b4a4f1c665aadca502643`,
`d78f45127359fdaea7e872fc2a89b6fce56f5d16`,
`97d85182d309f567ef002712928d53a209d753e5`. Preserve all donor commit identities
where possible, or use `cherry-pick -x` when transplanting. If development
already contains a donor, rebase onto it rather than applying a second copy.
Keep required G0 changes as reviewable follow-up commits instead of rewriting
both implementations into a third design.

## Checks and verdict

Inspected the five PR diffs and the connected source and tests for the findings
above. GitHub metadata supplied current PR heads and states.
The separately completed G0 integration patch passes 70 affected cases and
`./gradlew check -x integrationTest`: 1,167 cases in 118 suites, no failures,
errors or skips, at `bbad850`. Those results do not validate the unimported PRs.

JDT.LS remains unavailable through this connector, with the existing permission
to continue available checks. The secrets precheck found no secrets but reported
failed authentication; no authenticated SonarQube server check is claimed.
No donor suite, native Samba, Windows/ONTAP or actual Java 8 rerun was performed
for this review. G0 remains open.

**Verdict:** bring #892, #901 and #898 with the integration corrections above.
#917 is optional alignment; retain the G0 teardown when #893 is reconciled.
