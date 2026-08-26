# Disposable live AFS/AuriStor test plan

## Objective and claim boundary

This plan validates the AFS-enhanced Tiny File Manager against a real OpenAFS or AuriStor client. It is the required complement to static tests. A successful static run alone is not evidence that tokens reach the web worker, ACLs are enforced, symlinks are confined, or operations behave correctly across volume mount points.

Run this plan only against disposable data and identities. The preferred fixture is a dedicated read-write test volume plus a second disposable volume for cross-volume tests. Never point `FM_ROOT_PATH` at a production volume, user home, shared project tree, or cell root.

## Safety rules and stop conditions

- Use an isolated VM or container host with the target AFS/AuriStor client version and a non-production web endpoint bound to loopback or a restricted test network.
- Use dedicated test principals. Do not copy production keytabs, long-lived tokens, cookies, configuration secrets, or ACLs into the evidence bundle.
- Create a unique run ID, a dedicated root, a sibling AFS escape target, and a local-filesystem escape target. Record their exact canonical paths before starting.
- Place a run-ID marker file at each test root. Destructive cleanup is permitted only after the operator verifies the marker, expected volume/FID, and exact path.
- Prefer a disposable volume snapshot/clone before destructive cases. Otherwise create a timestamped archive, file hash manifest, mount-point inventory, and complete ACL baseline.
- Stop immediately if an HTTP operation reads, changes, creates, renames, archives, downloads, or deletes anything outside the dedicated roots; if the web worker has an unexpected identity; or if a mount point resolves to a non-disposable volume.
- Treat a timeout, PHP warning, `fs` parse failure, or unexplained empty ACL as a failure, not as a skipped check.

Suggested logical names are:

```text
RUN_ID=<UTC timestamp plus random suffix>
AFS_TEST_ROOT=/afs/<test-cell>/<disposable-volume-path>/tfm-<RUN_ID>
AFS_CROSS_VOLUME_ROOT=/afs/<test-cell>/<second-disposable-volume>/tfm-<RUN_ID>
AFS_ESCAPE_ROOT=/afs/<test-cell>/<disposable-sibling>/outside-<RUN_ID>
LOCAL_ESCAPE_ROOT=/tmp/tfm-outside-<RUN_ID>
```

Substitute explicit, reviewed paths in commands. Do not use an unset variable, wildcard, cell root, `/afs`, `/`, home directory, or workspace root as a recursive-operation target.

## Evidence manifest before mutation

Create a timestamped evidence directory outside all test roots and record:

- `git rev-parse HEAD`, `git status --short`, the old/new mapping, and the safety-ref object ID;
- container or VM image identity, web-server and PHP versions, loaded PHP extensions, and relevant PHP limits;
- AFS/AuriStor client and `fs` versions, mount configuration, cell name, cache-manager status, and server/volume identity;
- exact test-root, escape-root, mount-point, volume, FID, and canonical-path results;
- sanitized application configuration and checksums of deployed source files;
- process UID/GID/groups, SELinux/AppArmor state if applicable, and web service start command;
- token issuer, principal names, PAG identifiers, token expiry times, and `fs getcalleraccess` results, but never token material;
- recursive file inventory with types, sizes, timestamps, hashes for regular files, symlink targets, and ACLs for every directory;
- web access/error logs and PHP logs from a clean starting point.

Keep command output in raw text as well as a short result table. Record the HTTP request, identity, expected result, actual result, and resulting filesystem/ACL delta for every case.

## Identity, token, and PAG setup

Use at least these dedicated identities:

| Identity | Intended access |
| --- | --- |
| ACL administrator | `a` and the rights needed to seed and restore the fixture |
| Editor | lookup/read/write/insert/delete/lock as required by positive tests |
| Reader | lookup/read only |
| Denied principal | a positive grant plus a negative ACL used to prove denial |

For OpenAFS, create a fresh PAG with the site's approved `pagsh`/Kerberos/`aklog` procedure. For AuriStor, use the site-approved equivalent isolated process credential/token procedure. Record the PAG and sanitized token listing before and after the test.

The token must belong to the web worker, not merely the interactive shell. Start the disposable web server or PHP-FPM worker from the prepared PAG, or use the deployment's documented credential-injection mechanism. Then prove the effective identity from the same UID, process context, and mount namespace as PHP by comparing:

1. the sanitized token/PAG view;
2. `fs getcalleraccess` for the test root;
3. a permitted and a denied HTTP filesystem action; and
4. the resulting server-side audit/access log identity.

Repeat the authorization subset as Editor, Reader, and Denied principal using newly started workers or otherwise isolated credential contexts. Do not reuse a worker that might retain the prior identity. Include an expired/destroyed-token case and verify fail-closed behavior.

## Deployment under test

Deploy the exact candidate commit into the disposable web root. Back up the original test configuration, then set at least:

```php
$afsSupport = true;
$root_path = '/afs/<reviewed-disposable-path>';
```

Do not assume the upstream Dockerfile is the candidate deployment: it copies only `tinyfilemanager.php` and omits `afs.php`. If a container is used, build or mount an explicitly reviewed AFS-capable artifact and record both source-file checksums.

Keep application authentication enabled unless the production design explicitly delegates authentication to the front-end server. Restrict the endpoint by network policy as well. Begin with URL proxying unset. If proxy behavior is in scope, test it later with a dedicated restricted proxy and record its DNS, redirect, and egress policy.

Before using the browser, run PHP lint and the no-live-mount suites against the deployed source. Confirm the page loads without PHP warnings and that AFS mode is actually enabled. Verify that disabling `$afsSupport` restores ordinary upstream behavior without loading `afs.php`.

## Fixture layout

Create a deterministic fixture containing:

- empty, small text, binary, zero-byte, large, Unicode-name, whitespace-name, dot, and allowed/disallowed-extension files;
- empty and nested directories, a deep tree, and a directory with enough entries to expose per-item command latency;
- same-volume and cross-volume destinations;
- a zip and tar archive with ordinary nested content;
- separately generated traversal archives containing `../`, absolute names, nested symlink entries, and names that collide with existing files;
- relative and absolute symlinks described below;
- a child-volume mount point and, when available, a read-only volume/mount point;
- sentinel files in both escape roots whose content, metadata, hashes, and ACLs are recorded.

Seed normal and negative ACL entries with `fs` before opening the ACL editor so every row and right can be round-tripped. For AuriStor, include the auxiliary rights `A-H` as distinct case-sensitive rights in addition to standard `lrwidka`. Record `fs listacl`, `fs getcalleraccess`, volume/FID information, and expected effective rights for each identity.

## ACL and caller-access matrix

For both a directory and a regular file path, while recording whether the implementation applies an ACL to the file, its parent, or rejects the operation:

1. Open the ACL editor and compare every normal and negative principal and each standard `l`, `r`, `w`, `i`, `d`, `k`, `a` and AuriStor auxiliary `A-H` checkbox with raw `fs listacl` output. Prove specifically that uppercase `A` is not decoded as lowercase admin `a`, uppercase `D` is not decoded as lowercase delete `d`, and `B`, `C`, `E`, `F`, `G`, and `H` survive unchanged.
2. Toggle each normal right individually, submit with a valid CSRF token, and confirm the exact raw ACL delta and a successful/denied operation that exercises the right.
3. Repeat for negative rights, including adding, changing, and clearing an entry to `none`. Negative ACL controls must not be reported as supported if the POST path ignores them.
4. Verify that the lock checkbox maps `k` to `k`; a principal with `l` but not `k`, and one with `k` but not `l`, must display differently.
5. Submit with a missing token, an invalid token, a stale token, a foreign-session token, and a readonly application account. The ACL must remain byte-for-byte unchanged.
6. Test principal names containing cell qualifiers and characters that exercise HTML/form encoding. Confirm that the displayed principal, submitted key, and `fs` argument are identical and that no markup executes.
7. Remove the token/PAG and repeat read and mutation attempts. Confirm a clear failure without partial ACL changes.
8. Compare the UI permission text with `fs getcalleraccess` under all four identities and across ordinary directories, child mount points, and the cross-volume root.
9. Measure listing time and count `fs getcalleraccess` executions for small and large directories. The expected optimized behavior is no constructor lookup and one explicit lookup per displayed item; record any remaining O(N) usability limit.
10. Capture raw OpenAFS and AuriStor CLI output separately if both implementations are supported. Parser success on one is not evidence for the other.
11. On AuriStor, create a file with an inherited ACL. Verify that the UI identifies it as inherited, disables submission, and that a crafted POST is rejected without converting it to a file-specific ACL. If explicit conversion is tested separately, record the exact command and use the client-supported ACL-removal operation to restore inheritance.
12. Populate multiple positive and negative ACEs and verify one `fs` invocation per set. Force the second set to fail after the first succeeds; record the partial-update behavior and restore the exact baseline before continuing.
13. Apply a disposable Volume Maximum ACL and capture the exact raw `fs listacl` output. The current implementation must report the ACL as unreadable and reject a crafted mutation without changing either the object ACL or MaxACL. A future parser may display MaxACL entries read-only, but must never post them as object ACL entries or calculate effective rights without server evidence.

A negative ACE alone is not proof of denial when `anonymous` or `system:anyuser` grants the same right. Include authenticated and token-discarded anonymous requests, and treat the observed effective operation—not the checkbox—as the authorization result.

Restore the ACL baseline after this matrix before starting data-plane tests.

## Data-plane operation matrix

Exercise each row as an allowed Editor, a Reader expected to be denied, and where meaningful the Denied principal. After every request, compare the full test-root and escape-root manifests.

| Area | Cases to execute | Required evidence |
| --- | --- | --- |
| Listing/navigation | root and nested navigation, parent link, hidden items, exclusions, search, large directory | HTTP result, displayed names/access, raw listing, timing, `fs` call count |
| Create | new file, empty file, directory, nested directory, invalid/NUL/path-like name, existing target | status/message, type/mode/FID, no outside-root delta |
| Edit/save | plain editor, ACE/AJAX save, empty content, large content, failed write, backup | before/after hash and length, CSRF result, absence of partial data |
| Upload | single file, overwrite/collision, zero/large file, disallowed extension, nested folder upload, chunked upload and interrupted chunk cleanup | request/chunk log, final hash/FID, `.part` cleanup, destination confinement |
| URL upload | direct HTTP(S), redirects, rejected loopback/port, configured restricted proxy, failed transfer and temp cleanup | application and proxy logs, resolved destination, final hash, no internal-network reachability |
| View/download | text, binary, zero/large file, byte-range request, image/media preview, missing and denied file | status/headers, byte-for-byte hash, token behavior, session behavior |
| Direct link | regular file and directory under each identity | web-server authorization result; record that PHP cannot confine or authorize a direct link |
| Copy/duplicate | file/tree, existing target, same-directory duplicate, copy into a direct and deep descendant, large/partial-write case, quota/writeback failure, symlink cases, missing/invalid CSRF token and cross-site GET completion | source/destination hashes/types/targets, CSRF rejection with no mutation, error atomicity, partial cleanup, confinement |
| Move/rename | file/tree, same volume, cross volume, existing target, symlink, denied destination, missing/invalid CSRF token and cross-site GET completion | source/destination state, CSRF rejection with no mutation, expected cross-volume error or documented fallback, no loss |
| Delete | file, empty/non-empty tree, batch selection, symlink, broken link, mount point | exact removed objects, sentinel preservation, no traversal into target/mounted volume |
| Archive create | zip/tar one and many files, nested tree, symlink, child volume, denied member | member list, hashes, omissions/errors, no unexpected traversal |
| Archive extract | zip/tar normal, overwrite, `../`, absolute path, symlink entry, extraction through symlink or mount point | destination manifest and proof that both escape sentinels remain unchanged |

Also exercise every single-item and batch route separately; they do not necessarily share implementation. A route that passes only because the kernel denied it is not equivalent to application-level confinement. Record both layers.

## Symlink confinement matrix

Create each link as both a file-facing and directory-facing case where possible:

- relative link to an object inside `AFS_TEST_ROOT`;
- absolute link to an object inside `AFS_TEST_ROOT`;
- link to `AFS_ESCAPE_ROOT` on the same AFS device/cell;
- link to the cross-volume AFS root;
- link to `LOCAL_ESCAPE_ROOT` on the local filesystem;
- broken link;
- two-link chain and a loop.

For every link, test list, navigate, view, edit/save, backup, upload through a linked directory, download, direct link, copy, duplicate, move/rename, single delete, batch delete, archive create, and archive extraction. The required confinement result is:

- an operation may act on the link itself where that is the documented intent;
- no operation may follow a link outside `FM_ROOT_PATH` for read or write;
- recursive operations must detect loops and must not traverse an outside target;
- deletion of a link must not delete its target;
- direct-link exposure must be blocked by web-server configuration or documented as unsupported, because the PHP AFS wrapper cannot mediate it.

Any outside-root read or write is a release blocker. Preserve the fixture and logs for diagnosis; do not continue destructive cases.

## Volume mount-point and cross-volume matrix

Use only disposable volumes. Record each mount point with the client tools, its target volume, read-write/read-only status, server, and FID before testing.

1. Navigate and list a child-volume mount point inside the test root.
2. Compare ACL display and effective caller access on the parent, mount point, child-volume root, and descendants.
3. Copy files and trees into and out of the child volume and compare hashes, ACL effects, and mount-point preservation.
4. Attempt rename/move across the volume boundary. Require either a clear non-destructive failure or an explicitly implemented copy-and-delete fallback with complete verification.
5. Attempt recursive copy, delete, and archive creation at the mount-point object. Confirm whether the operation treats it as a boundary or traverses it; traversal is permitted only when explicitly intended and the entire target volume is disposable.
6. Exercise a read-only mount/volume. Writes must fail clearly and leave no partial files or stale upload chunks.
7. Test a symlink to a child-volume path and a symlink to an AFS path outside the configured root.
8. Remove or make the mount temporarily unavailable and confirm fail-closed behavior without PHP warnings, hangs, or fallback to a local `/afs` directory.

Never use a production volume merely to test a read-only case. A supposedly read-only path can still expose sensitive data through view, download, direct-link, copy, or archive operations.

## Rollback and teardown

Rollback must be prepared before the first mutation and executed even after a failed test.

1. Stop the disposable web service so no request races with restoration.
2. Preserve final logs, HTTP transcripts, screenshots where useful, raw ACL/access output, and final filesystem manifests.
3. Compare both escape-root sentinels and their ACLs with baseline. Escalate any difference before cleanup.
4. Restore the application configuration from its timestamped backup and verify its checksum.
5. Restore the fixture from the disposable volume snapshot/clone, or restore files and ACLs from the verified baseline. Re-run hashes, type/symlink inventories, mount-point inventory, and `fs listacl` comparisons.
6. If destroying the disposable roots or volumes, verify the run-ID marker, canonical path, cell, volume, and FID immediately before the exact deletion. Use the cell's recoverable volume-destruction procedure where available.
7. Destroy test tokens, exit PAGs, terminate credential-bearing workers, and verify that the old token is no longer accepted.
8. Remove the disposable container/VM and restricted proxy only after evidence is copied to its retained location.
9. Record what was removed, whether a recoverable volume snapshot remains, and the final restore verification result.

## Exit criteria

An AFS/AuriStor compatibility claim requires all of the following:

- no PHP lint, static-test, upstream-check, warning, or parser failures;
- proven web-worker identity and token/PAG isolation for each authorization role;
- exact normal and negative ACL round trips for standard `lrwidka` and AuriStor `A-H`, preserved inherited ACLs, fail-closed MaxACL behavior, correct `k` handling, CSRF rejection, and enforcement evidence;
- every claimed I/O route tested in both allowed and denied cases with no unexplained partial state;
- no outside-root read or mutation through symlinks, archives, mount points, direct links, or cross-volume operations;
- documented, acceptable behavior for file ACL requests, read-only volumes, token expiry, unavailable mounts, and cross-volume moves;
- complete evidence and a verified rollback/teardown.

If a generic endpoint remains intentionally unwired, report it as unsupported rather than converting its static expected failure into a compatibility pass.
