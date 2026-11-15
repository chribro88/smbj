# Test artifact retention

Old generated SMBJ test reports, trace JSON and validation directories are now
stored as verified gzip-compressed tar archives in `/tmp/smbj-retained-evidence`.
The [restore index](retained-test-artifacts.csv) maps every original path to its
archive, SHA-256 and allocated sizes. Every regular file was compared by SHA-256
against its archive member before the loose original was deleted. Existing
validation records retain their original paths and manifest hashes; restore the
corresponding archive to inspect or recheck those records:

```sh
tar -xzf /tmp/smbj-retained-evidence/ARCHIVE_NAME.tar.gz -C /tmp
```

This retains earlier passing and failing evidence without keeping duplicate HTML,
XML and raw trace trees expanded. The private archives remain temporary local
artifacts, as their original directories were; they are not committed to Git.
The current encrypted-cleanup investigation remains expanded while in use.

Obsolete task-specific Go build/module caches, the research Go toolchain and its
download were removed. Java 8/21 runtimes, pinned Samba fixtures, repository
source, dirty research worktrees and unrelated application artifacts were kept.
See [the cleanup measurement](validation-test-artifact-cleanup.json) for counts
and measured storage reclaimed. No shared Docker prune was run.
