# Disposable live AFS/AuriStor test plan

## Objective and claim boundary

This plan validates the AFS-enhanced Tiny File Manager against a real OpenAFS or AuriStor client. It is the required complement to static tests. A successful static run alone is not evidence that tokens reach the web worker, ACLs are enforced, symlinks are confined, a descriptor boundary survives races, or operations behave correctly across volume mount points.

The data-plane follow-on lane is deliberately not deployable with its bundled `AfsDataPlane`: that pathname-based class returns `false` from `isProductionReady()`. A live data-plane run may begin only after the candidate includes a separately reviewed descriptor-backed `AfsDataPlaneProvider` (or equivalent native broker) and the application accepts and initializes it. Overriding the readiness boolean without implementing and reviewing the boundary is not a test setup; it is a bypass. Until that prerequisite exists, only the readiness-failure, ACL, and mount-free tests can run, and no AFS data-plane compatibility claim is possible.

Run this plan only against disposable data and identities. The preferred fixture is a dedicated read-write test volume plus a second disposable volume for cross-volume tests. Never point `FM_ROOT_PATH` at a production volume, user home, shared project tree, or cell root.

## Safety rules and stop conditions

- Use an isolated VM or container host with the target AFS/AuriStor client version and a non-production web endpoint bound to loopback or a restricted test network.
- Use dedicated test principals. Do not copy production keytabs, long-lived tokens, cookies, configuration secrets, or ACLs into the evidence bundle.
- Create a unique run ID, a dedicated root, a sibling AFS escape target, and a local-filesystem escape target. Record their exact canonical paths before starting.
- Place a run-ID marker file at each test root. Destructive cleanup is permitted only after the operator verifies the marker, expected volume/FID, and exact path.
- Prefer a disposable volume snapshot/clone before destructive cases. Otherwise create a timestamped archive, file hash manifest, mount-point inventory, and complete ACL baseline.
- Stop immediately if an HTTP operation reads, changes, creates, renames, archives, downloads, or deletes anything outside the dedicated roots; if the web worker has an unexpected identity; or if a mount point resolves to a non-disposable volume.
- Stop if a rendered AFS page emits a raw managed-file URL, contacts an online document viewer, loads an unreviewed remote executable/style/media asset, or permits the web server to serve a guessed managed path without Tiny File Manager authorization.
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
- container or VM image identity, web-server and PHP versions, loaded PHP extensions, relevant PHP limits, and the exact production-provider artifact and build identity;
- AFS/AuriStor client and `fs` versions, mount configuration, cell name, cache-manager status, and server/volume identity;
- exact test-root, escape-root, mount-point, volume, FID, and canonical-path results;
- sanitized application configuration and checksums of deployed source, provider, local JavaScript/CSS/font/worker assets, and configuration files;
- process UID/GID/groups, SELinux/AppArmor state if applicable, and web service start command;
- token issuer, principal names, PAG identifiers, token expiry times, and `fs getcalleraccess` results, but never token material;
- recursive file inventory with types, sizes, timestamps, hashes for regular files, symlink targets, and ACLs for every directory;
- the response CSP, rendered HTML, browser console, complete browser network trace, canonical external origin, accepted/rejected Host and forwarded-host inputs, and web-server static-location configuration;
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

Deploy the exact candidate commit and the separately reviewed production-provider artifact into the disposable web root. `afs_contract.php` is mandatory and must be verified as a reviewed application blob before `config.php` loads the provider. Back up the original test configuration, then set at least:

```php
define('AFS_PRODUCTION_PROFILE', 'afs-descriptor-v1');
$afsSupport = true;
$afs_external_auth = true;
$use_auth = false;
$auth_users = array();
$readonly_users = array();
$directories_users = array();
$settings_enabled = false;
$direct_links_enabled = false;
$raw_previews_enabled = false;
$url_upload_enabled = false;
$root_path = '/afs/<reviewed-disposable-path>';
$root_url = '';
$online_viewer = false;
$favicon_path = '';
$external_asset_root = __DIR__ . '/<reviewed-local-asset-root>';
$afs_asset_manifest_file = 'relative/path/to/afs-assets-v1.json';
$afs_asset_manifest_sha256 = '<lowercase-sha256-of-exact-manifest-bytes>';
$content_security_policy = "default-src 'none'; base-uri 'none'; connect-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'none'; frame-src 'none'; img-src 'self' data:; media-src 'self'; object-src 'none'; script-src 'self'; style-src 'self'; worker-src 'self'";
$content_security_policy_approved = true;
require_once __DIR__ . '/<reviewed-provider-artifact>.php';
$afsDataPlaneFactory = new ReviewedAfsDataPlaneProviderFactory();
$afs_expected_factory_class = 'ReviewedAfsDataPlaneProviderFactory';
$afs_expected_factory_id = 'site.factory:sha256:<reviewed-lowercase-hash>';
$afs_expected_provider_class = 'ReviewedAfsDataPlaneProvider';
$afs_expected_provider_id = 'site.provider:sha256:<reviewed-lowercase-hash>';
```

Do not use that configuration with the bundled `AfsDataPlane`, a test double, or a provider whose only production change is returning `true` from `isProductionReady()`. The provider must own resolution, metadata, ACLs, and I/O through a descriptor-relative `RESOLVE_BENEATH`/no-magic-link boundary, initially rejecting POSIX symlinks, or an independently reviewed equivalent broker. Exact class/build IDs and provider-reported credential equality prevent accidental substitution but do not prove the implementation, token, or check/use boundary. Review the provider artifact and every call site together.

The one canonical JSON manifest must validate against `docs/AFS_ASSET_MANIFEST.schema.json` and be the same artifact the container lock consumes. Its exact raw bytes are pinned by `$afs_asset_manifest_sha256` and hashed before JSON parsing. It has version 1 and exactly ten logical asset rows. Each row binds type, relative local path, lowercase SHA-256, reviewed license, and boolean `defer`; style rows require `defer: false`. Do not generate an independent PHP manifest or container-only lock. Only a container-pinned, root-owned, non-writable manifest and asset tree makes these hashes a trust anchor; application validation alone cannot prevent an authorized writer from replacing both config and bytes. Every transitive dependency loaded by CSS, Font Awesome, ACE modes/themes/workers, Dropzone, DataTables, or Highlight.js must also be in the reviewed image/lock. The application validates the top-level files but cannot prove transitive browser loads, URL-to-file mapping, MIME, or served bytes; collect that evidence in the browser and web-server lanes. Keep the favicon empty or bind it to its separate lowercase SHA-256.

PHP is the only CSP-header source. The exact 13-directive policy above is required and rejects remote, wildcard, unsafe-inline/eval, and noncanonical variants. Do not add a second Apache CSP header. The application still contains inline templates, so `applicationTemplatesSupportStrictCsp()` intentionally makes this configuration return 503 until a reviewed nonce/hash/external-template refactor exists. A live positive data-plane run cannot start before that blocker is resolved; readiness-failure tests must prove the stop remains effective meanwhile.

AFS mode forces the Google/Microsoft online viewer off, suppresses raw image/audio/video and hover previews, and disables file/folder DirectLink and URL-upload controls. Ordinary controller-mediated navigation, browser upload, view, and download remain. Confirm that a pre-defined non-false `FM_DOC_VIEWER`, enabled settings/direct/raw state, or URL-upload variable/constant other than literal `false` produces the expected 503, then inspect the rendered response and network trace rather than relying on variables alone. A crafted URL-upload request must receive 403 before URL parsing, temporary-file creation, proxy setup, or network access. `FM_ROOT_URL` must be empty and `FM_SELF_URL` root-relative. Configure the web server to deny guessed static URLs below the managed root even though the UI no longer emits them.

Do not assume the upstream Dockerfile is the candidate deployment: it copies only `tinyfilemanager.php` and omits `afs_contract.php`, `afs.php`, the production provider, manifest/schema, reviewed local assets, and AFS configuration. If a container is used, build or mount an explicitly reviewed AFS-capable artifact and record every component checksum, including the provider contract. The container must expose the intended AFS mount and mount inventory to the worker, supply `/usr/bin/fs` and required PHP extensions, preserve the intended UID/PAG/token, serve the local assets, verify the application-owned CSP, pin the canonical external origin and reject untrusted Host/forwarded-host inputs, sanitize trusted proxy headers, and enforce static-file and URL-upload egress policy.

Keep the application and container changes reviewable as separate commits, but treat them as one security boundary. The application lane cannot validate the deployed mount, identity, assets, CSP, or static web-server rules. The container lane cannot repair provider dispatch, pathname races, CSRF, or raw-URL generation. Neither lane can claim compatibility until the combined image passes this plan.

The production profile requires front-end external authentication, disables Tiny File Manager local auth, removes all local/readonly/per-user accounts, and rejects a missing `REMOTE_USER`. That structural check does not prove Apache authenticated before PHP/session/CSRF handling, that the header cannot be spoofed, or that the provider uses the same PAG/token. The exact image must prove those semantics and retain a complete mod_auth/authz/header-trust configuration. Restrict the endpoint by network policy as well. URL upload must stay disabled with proxying unset. A separate non-AFS compatibility test may use a dedicated restricted proxy and record its DNS, redirect, and egress policy; that does not enable the route in AFS production.

Before using the browser, run PHP lint and every no-live-mount suite against the deployed source. Verify the readiness matrix separately: ordinary upstream mode still works with `$afsSupport = false`; AFS enabled without the immutable profile; profile with AFS disabled; local auth/users; missing external identity; embed/settings/direct/raw/URL-upload enablement; a pre-defined non-false `FM_URL_UPLOAD_ENABLED`; a root outside `/afs`, unnormalized root, or conflicting pre-defined `FM_ROOT_PATH`; raw/absolute URLs; missing contract; bad factory/provider class, build, credential identity, boundary, readiness, or initialization; missing/uppercase/mismatched manifest digest; invalid manifest/assets/hashes/licenses; invalid CSP/approval; and current inline templates each produce a 503 with no file operation. Confirm the exact expected blocker is reported, without PHP warnings or fallback.

After startup, request login, listing, upload, view, edit, help, and error pages and record for each:

- the CSP header and any browser CSP violation;
- every script, stylesheet, font, worker, image, media, iframe, favicon, preconnect, and DNS-prefetch request;
- absence of Google/Microsoft viewer requests and raw managed-file URLs;
- denial of guessed static file and directory URLs by the web server; and
- identical reviewed asset checksums in the image and HTTP responses.

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

The current audit has 24 classifications and no compatibility-pass status:

- **18 transitional:** provider-wired data, metadata, ACL, navigation/search, and readiness surfaces that still lack the native boundary/live evidence;
- **5 guarded-disabled:** URL upload, DirectLink controls, archive creation, archive extraction, and raw protected URLs/external viewers;
- **1 live-YFS:** AFS volume-mount traversal and mutation semantics;
- **0 protected and 0 XFAIL.**

Within the original 18 routes, the split is 13 transitional, 4 guarded-disabled, and 1 live-YFS. “Transitional” means a provider-aware call site exists, not that the descriptor boundary or live behavior passed. “Guarded-disabled” means the UI and crafted requests must remain unavailable before any generic code runs. DirectLink and URL upload are disabled; exercise ordinary browser upload/view/download/navigation separately.

Exercise each transitional row as an allowed Editor, a Reader expected to be denied, and where meaningful the Denied principal. After every request, compare the full test-root and escape-root manifests. For a guarded-disabled row, send both the ordinary UI request (if any control remains) and a crafted request, then prove that the complete manifests are unchanged.

| State | Area | Cases to execute | Required evidence |
| --- | --- | --- | --- |
| Transitional | Listing/navigation/search | root and nested navigation, parent link, hidden items, exclusions, literal-metacharacter search, large directory, concurrent link-swap attempt | HTTP result, displayed names/access, raw listing, timing, `fs` call count, provider trace, no path-only fallback |
| Transitional | Create | new file, empty file, directory, nested directory, invalid/NUL/path-like name, existing target, concurrent parent/leaf replacement | status/message, type/mode/FID, provider trace, no outside-root delta |
| Transitional | Edit/save/backup | plain fallback and ACE/AJAX save, empty/large content, failed/short write, backup, concurrent replacement | before/after hash and length, CSRF result, descriptor/provider trace, absence of partial data |
| Transitional | Upload | single file, overwrite/collision, zero/large file, disallowed extension, nested folder upload, chunked upload, reordered/retried chunks, interrupted cleanup | request/chunk log, final hash/FID, `.part` cleanup, descriptor/provider trace, destination confinement |
| Guarded-disabled | URL upload | absent tab/form/client function; crafted direct HTTP(S), redirect, loopback, blocked-port, proxy-configured, empty, and malformed requests | 403 before URL parsing/temp creation/cURL/stream/proxy work; no application/proxy/DNS request and no filesystem delta |
| Transitional | View/download | text, binary, zero/large file, valid/invalid/suffix/multiple byte ranges, missing and denied file | status/headers, byte-for-byte hash, token/session behavior, descriptor/provider trace; raw image/audio/video preview remains absent |
| Guarded-disabled | DirectLink/raw URLs | verify no DirectLink control, send crafted/guessed raw static URLs under every identity | no direct action emitted; explicit PHP/profile rejection where applicable; web-server denial and no managed bytes |
| Transitional | Copy/duplicate | file/tree, existing target, same-directory duplicate, direct/deep descendant, large/partial-write case, quota/writeback failure, race, missing/invalid CSRF token | source/destination hashes/types, provider trace, CSRF rejection, error atomicity, partial cleanup, confinement |
| Transitional | Move/rename | file/tree, same volume, cross volume, existing target, race, denied destination, missing/invalid CSRF token | source/destination state, provider trace, CSRF rejection, explicit cross-volume failure or reviewed fallback, no loss |
| Transitional | Delete | file, empty/non-empty tree, single/batch selection, race, symlink, broken link, kernel mount, AFS volume mount point | exact removed objects, provider preflight/trace, sentinel preservation, no traversal into link or mounted volume |
| Guarded-disabled | Archive create | ordinary and crafted ZIP/TAR requests over files, trees, symlinks, child volumes, and denied members | control absent or disabled, explicit rejection before `FM_Zipper`/`PharData`, no archive and no manifest delta |
| Guarded-disabled | Archive extract | ordinary and crafted ZIP/TAR requests including overwrite, `../`, absolute path, symlink entry, and mount/link destinations | explicit rejection before `extractTo`, no destination creation, both escape sentinels and full manifest unchanged |

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

For every link, test list, navigate, view, edit/save, backup, upload through a linked directory, download, former direct-link actions, copy, duplicate, move/rename, single delete, batch delete, archive create, and archive extraction. The required confinement result is:

- all content reads, writes, navigation, search, copy, and upload through a POSIX link fail closed; the initial production-provider contract does not follow even an in-root POSIX link;
- listing may expose only provider-returned no-follow link metadata and must not obtain `readlink` data through an independently resolved pathname;
- acting on the link object itself, such as unlink or rename, is permitted only if the reviewed broker binds the parent and leaf to a no-follow descriptor operation; otherwise it must also fail closed;
- recursive operations must reject the link before traversal, deletion must never affect its target, and link chains or loops must not cause a hang;
- archive create/extract remains guarded-disabled for both ordinary and crafted requests; and
- DirectLink controls must remain absent; ordinary PHP view/navigation remains provider-mediated, while the web server denies guessed raw URLs for both the link and its target.

Any outside-root read or write is a release blocker. Preserve the fixture and logs for diagnosis; do not continue destructive cases.

## Volume mount-point and cross-volume matrix

Use only disposable volumes. Record each mount point with the client tools, its target volume, read-write/read-only status, server, and FID before testing.

1. Navigate and list a child-volume mount point inside the test root. This logical AFS volume boundary is distinct from a POSIX symlink or kernel mount; the provider must identify it from reviewed AFS metadata and record the crossing.
2. Compare ACL display and effective caller access on the parent, mount point, child-volume root, and descendants.
3. Start single-file copy/read/write operations from inside the child volume and copy files into and out of it, then compare hashes, ACL effects, provider identity evidence, and mount-point preservation.
4. Attempt rename/move across the volume boundary. Require either a clear non-destructive failure or an explicitly implemented copy-and-delete fallback with complete verification.
5. Attempt parent-started search, recursive copy, and recursive delete across the mount-point object. Require a fail-closed boundary result with no child-volume delta. Archive creation is guarded-disabled and must be rejected before any archive walker runs. Renaming or deleting the mount-point object itself must also be rejected unless a separately reviewed AFS mount-management feature is explicitly in scope.
6. Exercise a read-only mount/volume. Writes must fail clearly and leave no partial files or stale upload chunks.
7. Test a POSIX symlink to a child-volume path and a symlink to an AFS path outside the configured root; both follow attempts must be rejected under the symlink policy above.
8. Add a nested kernel mount under the configured root and prove that it is never traversed, even if its device number or apparent path resembles the AFS tree.
9. Remove or make the AFS mount temporarily unavailable and confirm fail-closed behavior without PHP warnings, hangs, or fallback to a local `/afs` directory.

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
- a separately reviewed descriptor-backed provider or equivalent native broker, with every active metadata, ACL, and I/O call site bound to it and no production use of the bundled pathname preview;
- proven web-worker identity and token/PAG isolation for each authorization role;
- exact normal and negative ACL round trips for standard `lrwidka` and AuriStor `A-H`, preserved inherited ACLs, fail-closed MaxACL behavior, correct `k` handling, CSRF rejection, and enforcement evidence;
- all 18 transitional classifications tested in both allowed and denied cases, with provider/broker evidence, no generic-I/O fallback, and no unexplained partial state;
- all five guarded-disabled classifications proven through absent/disabled controls and crafted-request rejection before generic code or outbound network setup runs;
- no outside-root read or mutation through symlinks, archives, mount points, direct links, or cross-volume operations;
- documented, acceptable behavior for file ACL requests, read-only volumes, token expiry, unavailable mounts, and cross-volume moves;
- verified AFS-mode rejection of configuration self-write and online viewing, absence of raw media/hover and managed-root direct URLs, and web-server denial of guessed managed paths;
- the exact application-owned 13-directive CSP, refactored nonce/hash-compatible templates, one response header, and complete canonical-manifest/transitive asset evidence with a clean browser trace;
- one exact combined application/container image that supplies and checksum-locks `afs_contract.php`, `afs.php`, the provider, application, schema/manifest/assets, AFS client and mount inventory, external-auth bootstrap, worker identity/PAG/token, canonical origin/Host policy, trusted-proxy policy, egress policy, and static-file denial;
- complete evidence and a verified rollback/teardown.

If a transitional endpoint lacks the reviewed descriptor boundary or exact-image live evidence, report it as transitional/unsupported rather than a compatibility pass. If an operation remains deliberately disabled, preserve and report that rejection instead of implying feature support.
