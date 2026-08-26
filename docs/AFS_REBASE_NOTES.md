# AFS rebase notes

## Scope and provenance

The AFS-enhanced fork was replayed onto the fetched canonical Tiny File Manager tip without rewriting any remote-tracking ref. Its seven branch-local commits were later recreated to correct author and committer email metadata, then published with an explicitly authorized force-with-lease. Named safety refs retain both earlier histories. The provider/readiness work described below is part of this environment-neutral application branch. Deployment policy and runtime configuration are maintained separately and are not included here.

```text
origin   https://github.com/karlg100/tinyfilemanager.git
upstream https://github.com/prasathmani/tinyfilemanager.git
branch   kag/afs-rebase-upstream-20260817
```

| Role | Commit |
| --- | --- |
| Historical merge base | `2f357ee3d524f1085a7ca2707776c0f33ef85835` |
| Historical proxy commit | `da98b2aa88d9ba2df7c2d67578710faec4431c3e` |
| Historical AFS tip | `194b4d034e99e6ad20c99bb31ea512f12a9a916b` |
| Rebase target (`upstream/master`) | `41491439a6b243c55502581e53fad20bc4c6e777` |
| Replayed proxy commit | `9940e0e56b76ec41bf12a639d321d5afe094aa4f` |
| Replayed AFS commit | `8fd26cbf61e26fdc9831a83cfbb5b777f63f21c7` |
| Post-rebase AFS hardening | `7ea1040cd3d7c6c2b12c5949c8f4604bf72a87b0` |
| Independent-review AFS fix | `a3241138bea6f400534bb5a56c0c81944be08001` |
| Pre-existing upstream CSRF fix | `744c8eb07b024e6208f75ec6585da66f0ec8f0a9` |

The authoritative old-to-new mapping is:

```text
da98b2aa88d9ba2df7c2d67578710faec4431c3e -> 9940e0e56b76ec41bf12a639d321d5afe094aa4f
194b4d034e99e6ad20c99bb31ea512f12a9a916b -> 8fd26cbf61e26fdc9831a83cfbb5b777f63f21c7
```

All seven branch-local commits were subsequently recreated with author and committer email `karl@grindleyfamily.com`. Names, trees, raw messages, dates, ordering, and parent topology were preserved. The email-only object mapping is:

```text
a2df5e893041a3e18134299058f7aa74ccda96d9 -> 9940e0e56b76ec41bf12a639d321d5afe094aa4f
ed6cc370c4c6a908e9ffa9aa9d4c4b33be40a8a1 -> 8fd26cbf61e26fdc9831a83cfbb5b777f63f21c7
be98d299ec262e34bb2b759b7742c3dfc18bd3af -> 7ea1040cd3d7c6c2b12c5949c8f4604bf72a87b0
53b5501ed3ab55aef70d720b77e6e4ea8c21c339 -> ab4ca69009ecbb5a9bd73225d25f97065bcd60b9
029ddb12bdd627601e709bd91d9dc5e801624594 -> a3241138bea6f400534bb5a56c0c81944be08001
6cdef50404babb797965d152e501b4c5500f61a8 -> 744c8eb07b024e6208f75ec6585da66f0ec8f0a9
f4302bed20e7514fefdc8e6b0d785b5b8c8848a5 -> 502ac7013d4f307b7c3a58a1ecb3a09b9a0d8ddb
```

The historical fork tip and the complete pre-email-rewrite branch are retained at:

```text
refs/heads/safety/afs-pre-rebase-194b4d0-20260817
refs/heads/safety/afs-pre-email-rewrite-f4302be-20260817
```

Useful provenance checks are:

```sh
git range-diff --creation-factor=100 \
  2f357ee3d524f1085a7ca2707776c0f33ef85835..194b4d034e99e6ad20c99bb31ea512f12a9a916b \
  41491439a6b243c55502581e53fad20bc4c6e777..8fd26cbf61e26fdc9831a83cfbb5b777f63f21c7

git diff --exit-code \
  194b4d034e99e6ad20c99bb31ea512f12a9a916b:afs.php \
  8fd26cbf61e26fdc9831a83cfbb5b777f63f21c7:afs.php
```

The second command is clean: `afs.php` in the replay commit is byte-for-byte the historical file. Any later `afs.php` hardening is intentionally a post-rebase change, not a rewritten historical commit. Because the proxy patch was adapted around substantial upstream changes, `git range-diff` may show it as an old deletion plus a new addition; the explicit mapping above records its provenance.

## Semantic conflict inventory

The three-way audit found one proxy configuration conflict and 16 conflict blocks while replaying the AFS integration. The blocks below are numbered so that every resolution is reviewable even where one conceptual decision covered several adjacent hunks.

### Proxy configuration

| ID | Conflict | Resolution |
| --- | --- | --- |
| P-01 | The old proxy declaration expected the end of the 2020 configuration section. Upstream inserted editor-language, external-resource, and `config.php` override support there. | Keep all current upstream configuration. Place the optional `$proxyServer` declaration immediately before `config.php` is loaded, allowing a deployment override. In the URL-upload path, retain upstream URL/port SSRF checks and destination handling; only add the proxy-enabled HTTP stream context. |

The proxy is not a security boundary. A forward proxy performs its own DNS resolution and redirect handling and may be able to reach addresses that the application's hostname check did not anticipate. Its egress policy must therefore be independently restricted and tested.

### Defaults, configuration, and bootstrap

| ID | Conflict | Resolution |
| --- | --- | --- |
| AFS-01 | The old AFS commit carried a mixed-CRLF edit to the default JSON and the removed `calc_folder` setting, while upstream now stores `theme`. | Keep the upstream JSON and `theme`; normalize replayed lines to LF. The removed setting is not an AFS feature. |
| AFS-02 | The fork's site-specific date format overlapped upstream's current date format and new `path_display_mode`. | Keep both current upstream settings. Date formatting can still be changed through deployment configuration. |
| AFS-03 | The old import point collided with upstream editor mappings, `config.php`, ACE settings, and external-resource configuration. | Keep the whole upstream bootstrap. Define `$afsSupport = false` before `config.php`, load `config.php`, and then conditionally load `__DIR__ . '/afs.php'`. This makes AFS an explicit deployment opt-in and avoids breaking ordinary non-AFS Tiny File Manager installations. |
| AFS-04 | The fork conditionally omitted `FM_EXCLUDE_ITEMS`; upstream always defines it, serializes it for old PHP, and supports full-path exclusions. | Keep upstream's definition and behavior. Do not restore the fork's undefined-constant fallback. |

The old commit also changed authentication to disabled and disabled the online viewer. Those are deployment preferences, not AFS semantics. The historical replay deliberately retains upstream's authentication-enabled default, global-readonly behavior, online-viewer default, current theme, and current date format. The later data-plane readiness lane described below separately disables the online viewer whenever AFS mode is active, because it would disclose a protected file URL to a third party.

### Permission and ACL actions

| ID | Conflict | Resolution |
| --- | --- | --- |
| AFS-05 | The fork split the POSIX chmod handler before upstream added CSRF verification. | Retain the upstream `token` requirement, `verifyToken()` failure behavior, validation, translated messages, and redirect. Add only `!$afsSupport` to select the POSIX branch. |
| AFS-06 | The old AFS ACL POST handler collided with the end of the upstream action section. It had no current CSRF flow, skipped path cleaning, and did not redirect after mutation. | Add a separate AFS branch with the same readonly, platform, CSRF, path-cleaning, existence, message, and post/redirect/get behavior as upstream. The replay preserves the historical normal-ACL update behavior; negative-ACL mutation is a documented follow-up requirement. |
| AFS-07 | The old AFS ACL form collided with the current POSIX form and main-view boundary. | Keep the current POSIX view for non-AFS mode. Add a Bootstrap-5-aware AFS view using current path-display policy, a hidden CSRF token, guarded ACL arrays, current footer flow, and encoded displayed principals. |

### File-list metadata and table layout

| ID | Conflict | Resolution |
| --- | --- | --- |
| AFS-08 | The old table header removed the Owner column with markup from an older Bootstrap/DataTables layout. | Keep the upstream table and suppress only Owner while AFS metadata is displayed. |
| AFS-09 | Folder permission lookup overlapped upstream's raw/sortable modification time and hardened POSIX owner/group lookup. | Preserve current sorting and POSIX error handling. In AFS mode only, display `fs getcalleraccess` output in the permissions column. |
| AFS-10 | The folder Owner cell conflicted independently with the new folder-row markup. | Retain current folder actions and hide only the Owner cell in AFS mode. |
| AFS-11 | File permission and owner lookup conflicted with current size/date sorting, preview, and owner fallback changes. | Preserve all current file-row behavior. Substitute AFS access text for POSIX mode bits and hide only Owner in AFS mode. |
| AFS-12 | The empty-table colspan was hard-coded for the old column set. | Compute visible metadata and content column counts once and keep the translated upstream empty-folder label. |
| AFS-13 | The summary-footer colspan and old badges no longer matched upstream's readonly and Bootstrap-5 layouts. | Use the computed total column count while retaining current summary text and badges. |

The parent-directory row was adjusted with the same Owner-column rule; otherwise it would have remained misaligned even if the header and ordinary rows were correct.

### Helpers, assets, and translations

| ID | Conflict | Resolution |
| --- | --- | --- |
| AFS-14 | The old one-argument exclusion helper and undefined-constant guard conflicted with upstream's two-argument full-path exclusion helper. | Keep upstream's helper, call signature, serialization compatibility, and filename, extension, and full-path checks unchanged. |
| AFS-15 | A small historical DataTables version edit expanded into a wide footer/JavaScript conflict after upstream's Bootstrap, resource, CSP, and editor refactors. | Keep the complete upstream footer and configurable resource map. Do not downgrade or hard-code DataTables. The later AFS production gate requires a complete reviewed local-resource override and a deployment CSP rather than permitting the replay's public CDN defaults. |
| AFS-16 | The old inline AFS translations collided with the relocated and expanded `lng()` function and ACE footer code. | Keep the current footer/ACE code. Add each AFS English fallback key once in the current `lng()` table; do not restore the duplicate `admin` entry or replace `translation.json`. |

## Upstream security and behavior deliberately preserved

The replay does not intentionally remove or bypass these post-2020 upstream changes:

- authentication enabled by default, global readonly, per-user roots, and current session handling;
- CSRF tokens on the upstream-protected mutation routes, including both POSIX and AFS permission changes; the pre-existing single-copy GET mutation is corrected separately after the replay;
- URL-upload localhost/loopback and known-port rejection before the optional proxy context;
- current path cleaning, archive-item cleaning, filename validation, and NUL-byte rejection;
- current filename and path output encoding and excluded-name, extension, and full-path checks;
- current file download token/session behavior, upload naming, and error handling;
- current Bootstrap, external-resource, translation, theme, editor, sorting, and responsive-table behavior.

Preserving these controls is not a claim that upstream has complete symlink-safe confinement. The AFS-specific gaps below remain material.

## Compatibility blockers at the replay boundary

Do not claim general AFS/AuriStor compatibility from `8fd26cb` alone.

1. Tiny File Manager calls only `Afs::changeAcl()`, `Afs::readAcl()`, and `Afs::getACLAccess()`. Its forms do not use the legacy `command`, `formKey`, `selectedItems`, or `originPath` protocol. The AFS-safe copy, recursive copy/delete, move, and read helpers in `afs.php` are therefore dormant.
2. Save, backup, create, copy/duplicate, move/rename, delete, upload/chunked upload/URL upload, download, view, direct links, and archive paths still use generic upstream I/O. A lexical `FM_PATH` check does not stop an in-root symlink from reaching an AFS path outside `FM_ROOT_PATH` or a local filesystem path. Direct links bypass PHP entirely.
3. `Afs::pathSecurity()` in the historical file compares device IDs with `/afs`; it does not prove containment below `FM_ROOT_PATH`. A same-device AFS path outside the configured root can pass, a local filesystem mounted at `/afs` can be misidentified, and an alternate AFS mount root is unsupported.
4. The replayed `afs.php` assumes a readable `/afs`, `/usr/bin/fs`, enabled `shell_exec`, the POSIX extension, `REMOTE_USER`, and exact English `fs listacl` and `fs getcalleraccess` output. It does not robustly handle all failures.
5. Dormant paths refer to `filedrawers_rename` and `Mime`, neither of which is supplied by this repository. The undeclared `originPath` property also causes modern-PHP compatibility concerns.
6. The replayed UI displays negative ACLs but the POST handler updates normal ACLs only. Both lock checkboxes read the `l` state instead of `k`, so their initial state can be wrong. A negative entry with all boxes cleared is not posted.
7. The historical constructor performs request processing and `getcalleraccess`, after which the listing calls `getcalleraccess` again. This produces two subprocesses per listed item and gives construction unexpected side effects.
8. OpenAFS ACLs are directory-oriented. The UI offers permission editing for files as well as directories; exact OpenAFS and AuriStor behavior must be established on the target client and server versions.
9. A proxy can change URL-upload name resolution and reachable networks. The retained upstream hostname check is not a substitute for proxy-side egress policy.

## Post-rebase fixes and automated tests

The two mapped commits above are the historical replay layer and should remain unchanged. Hardening and tests belong in one or more commits after `8fd26cb` so `git range-diff` continues to show what was replayed versus what was newly repaired.

Commit `7ea1040cd3d7c6c2b12c5949c8f4604bf72a87b0` implements the separately reviewable production hardening:

- fail-closed AFS availability, path, stat, command-execution, and parser handling;
- removal of constructor request/shell side effects and exactly one explicit access lookup per listed item;
- declared runtime state, all seven standard caller-access flags including `k`, and testable ACL parsing;
- case-preserving round trips for standard `lrwidka` and AuriStor auxiliary `A-H` rights, so uppercase `A`/`D` cannot be confused with lowercase admin/delete;
- negative ACL updates, correct `k` checkbox state, clearing ACL entries, and one `fs` invocation per positive or negative ACL set;
- inherited AuriStor ACL detection with read-only UI and server-side mutation rejection, avoiding accidental materialization of an inherited file ACL;
- strict ACL-output validation that rejects unknown rights, duplicate rights, missing headers, and malformed command output;
- safe missing-`filedrawers_rename` behavior, complete copy writes including flush/close failures, partial-destination cleanup, recursive-copy ancestry rejection, and correct symlink destination names;
- a test-overridable AFS root and command runner while retaining the production defaults `/afs` and `/usr/bin/fs`;
- explicit retention of the narrower ACL display/edit claim because generic data-plane routing was not changed.

The case and inheritance handling follows the AuriStor [`fs listacl`](https://www.auristor.com/documentation/man/linux/1/fs_listacl.html) and [`fs setacl`](https://www.auristor.com/documentation/man/linux/1/fs_setacl.html) contracts: auxiliary rights are uppercase `A-H`, inherited file ACLs are marked in list output, and setting an ACL on such a file creates a file-specific ACL.

Independent review produced two additional, separately reviewable fixes after the original hardening commit:

- Commit `a3241138bea6f400534bb5a56c0c81944be08001` makes `Afs::copyFiles()` and recursive `copy_dirs()` share a link-first dispatcher. Directory symlinks and broken links are reproduced as links, direct `copy_dirs()` calls reject a symlink source, and FIFO or other unsupported file types fail without creating a destination. These helpers remain dormant from Tiny File Manager's active data plane and retain same-device and check/use limitations.
- The same commit makes the ACL parser explicitly recognize the AuriStor `Volume access list for ... is` boundary and fail closed instead of exposing any following MaxACL entries as editable object ACL entries. Until a separate read-only MaxACL model is implemented and validated live, ACL editing is disabled on volumes whose `fs listacl` output includes this block.

The reported nested-key principal mangling was retracted after PHP 7.4 and 8.3 reproduced dotted and spaced principals intact. A regression fixture records that behavior; the keyed ACL form was not changed without a failing case.

Commit `744c8eb07b024e6208f75ec6585da66f0ec8f0a9` converts single copy, move, and duplicate completion from a state-changing GET link to a token-verified POST form. This was a pre-existing canonical-upstream issue relevant to ambient SSO, not a conflict or regression introduced by the AFS replay.

The no-live-mount regression layer is intentionally separate as well:

- `tests/afs_regression.php` exercises ACL parsing and command construction, MaxACL fail-closed behavior, case-sensitive auxiliary rights, inherited ACLs, dotted/spaced principal keys, caller-access flags, path/device rejection, handle-time copy/read checks, directory and broken symlinks, unsupported special files, and helper inventory without touching `/afs`. The follow-on data-plane lane adds an offline path-policy model for rooted reads/writes, uploads, recursive operations, POSIX links, modeled kernel mounts, and modeled AFS volume boundaries; that model is not a production descriptor-boundary test.
- `tests/afs_static.php` checks default-off/config ordering, conditional implementation loading, the pre-config side-effect-free provider contract, retained upstream CSRF/URL-upload/exclusion controls, token-verified POST completion for single copy/move/duplicate, normal and negative ACL handling, all 15 rights, inherited-ACL gates, `k` mapping, strict provider status checks, and provider-owned metadata/ACL calls.
- `tests/afs_io_path_audit.php` is the current route inventory. It classifies all original 18 data-plane routes plus navigation, search, ACLs, MIME/metadata, raw protected URLs, and readiness. It deliberately has no `PROTECTED` result until a descriptor-backed provider and live evidence exist.
- `tests/afs_readiness.php` executes the immutable profile, provider/factory identity binding, exact CSP, settings/direct/raw/embed/URL-upload gates, and canonical JSON asset-manifest checks. It covers missing/extra rows and fields, licenses, required `defer`, lowercase SHA-256, traversal, symlinks, missing files, and manifest-file confinement. These checks do not establish web-server authentication provenance, CSP behavior in a browser, transitive assets, HTTP delivery, or a production descriptor boundary.
- Run PHP lint on `tinyfilemanager.php`, `afs.php`, and every PHP test, followed by every focused suite and any available upstream checks.

The finalized application lane is linted and executed under both PHP 7.4 and PHP 8.3. It includes 137 regression assertions, 564 static integration assertions, 306 readiness assertions, and a 24-classification/165-assertion I/O audit. The route result is 18 `TRANSITIONAL`, 5 `GUARDED-DISABLED`, 1 `LIVE-YFS`, 0 `PROTECTED`, 0 `XFAIL`, and zero failures. A green result proves the stated dispatch and fail-closed contracts only; it is not deployability evidence.

Static tests can validate dispatch, parsing, escaping, and fail-closed behavior, but they cannot validate PAG/token inheritance, AFS kernel behavior, ACL enforcement, mount points, volume boundaries, or the deployed `fs` output. Those claims require the disposable live plan in `docs/LIVE_AFS_TEST_PLAN.md`.

### Data-plane readiness follow-on lane

The follow-on data-plane lane changes the route architecture after the historical commits above. It introduces side-effect-free `AfsDataPlaneProviderFactory` and `AfsDataPlaneProvider` contracts and routes listing/search, create, save/backup, copy/duplicate, move/rename, delete, browser uploads, view/text reads, download, metadata/MIME, and ACL actions through provider-aware entry points. AFS direct-link controls are disabled; ordinary authenticated navigation, view, and download remain available through the controller. Image-hover and image/audio/video raw previews are suppressed, Google/Microsoft online viewing is forced off, settings and password-hash utilities are rejected, URL-upload egress is rejected before URL parsing or network setup, and archive create/extract is rejected before the generic archive classes run. The URL-upload switch remains literal `true` by default outside AFS to preserve upstream behavior and provides an explicit non-AFS opt-out.

These are transitional guards, not production passes. The bundled `AfsDataPlane` is deliberately pathname-based and returns `false` from `isProductionReady()`. No descriptor-backed provider is supplied by this repository. Production startup requires an exact factory class/build identity, exact provider class/build identity, provider-reported credential identity equal to the single post-config `REMOTE_USER` snapshot, literal `true` readiness and initialization, and the `descriptor-beneath-v1` boundary token. Active AFS routes no longer intentionally fall back to generic managed-root I/O, but the contract still exchanges path strings and the bundled preview still separates path checks from later operations. A provider that merely self-reports readiness cannot close `openat2`/descriptor ownership, TOCTOU, atomic replacement, partial-write, mount classification, or recursive-tree race concerns; those require an independently reviewed native provider or broker and live evidence.

Within the original 18-route inventory, 13 categories are `TRANSITIONAL`, URL upload, direct links, and archive create/extract are 4 `GUARDED-DISABLED`, and AFS volume-mount semantics are 1 `LIVE-YFS`. Adding the six explicit navigation/search/ACL/MIME/raw-URL/readiness surfaces produces the current total of **18 transitional, 5 guarded-disabled, and 1 live-YFS**. None is a compatibility pass. `GUARDED-DISABLED` means both UI and crafted requests are rejected before the generic implementation; `TRANSITIONAL` means the route reaches the provider seam but lacks native-boundary/live proof.

AFS startup also requires the exact application-owned 13-directive CSP in `AfsProductionReadiness::LOCAL_ONLY_CONTENT_SECURITY_POLICY`, literal `$content_security_policy_approved === true`, and one canonical version-1 JSON asset manifest. The policy is self-only/none except reviewed `data:` images; it rejects remote, wildcard, `unsafe-inline`, `unsafe-eval`, blob-script/worker, duplicate, missing, extra, and line-breaking forms. PHP emits the sole CSP header; the container must verify it rather than add another. Because the 2.6 templates still contain inline scripts/styles and event attributes, `applicationTemplatesSupportStrictCsp()` deliberately returns false and AFS startup remains unavailable until a nonce/hash/external-template refactor is reviewed.

The canonical asset schema is `docs/AFS_ASSET_MANIFEST.schema.json`. The same JSON file must be consumed by the application and container lock; a separate PHP or container-only manifest is not accepted. Its exact raw bytes are pinned by a lowercase profile SHA-256 and hashed before parsing. It contains version 1 and exactly ten logical keys. Every row requires `type`, relative no-symlink `path`, lowercase SHA-256, reviewed SPDX `license`, and boolean `defer` (`false` for styles). The application generates tags only after verifying the manifest and each file. Only root-owned, immutable, container-pinned bytes make those hashes a trust anchor. Transitive CSS/font/ACE dependencies, browser URL mapping, MIME, and served bytes remain exact-image checks. The optional favicon has an independent lowercase SHA-256 check.

An immutable `AFS_PRODUCTION_PROFILE` value `afs-descriptor-v1` ties these gates together. AFS cannot start without it, and a partial profile cannot enable production: AFS and external-auth flags must be literal true; Tiny File Manager local auth must be false; local, readonly, and per-user account maps must be empty; settings, embed, direct-link, raw-preview, and URL-upload surfaces must be false; one normalized nonempty root below `/afs` must bind the post-config snapshot, `FM_ROOT_PATH`, factory, and provider initialization; `FM_ROOT_URL` must remain empty; `FM_SELF_URL` must be root-relative; the manifest digest must be lowercase and exact; and factory/provider identities must match. A pre-defined `FM_ROOT_PATH` with any other value is rejected, as is any pre-defined `FM_URL_UPLOAD_ENABLED` value other than literal `false`. This is structural fail-closed validation, not evidence that Apache actually authenticated the request, established the correct PAG/token, protected headers, or bound that identity before PHP/session/CSRF processing. Those remain exact-container integration blockers.

## Remaining compatibility blockers

Before the follow-on data-plane lane, the hardening layer repairs the actively integrated ACL surface and several dormant helpers but leaves all 18 data-plane routes unconfined. The follow-on lane removes the audit's expected failures by routing or disabling them; it does not convert any route to `PROTECTED`. A blanket AFS/AuriStor compatibility claim remains blocked until a real descriptor-backed provider exists, every transition is exercised in the exact deployment, and disabled operations remain unreachable or receive provider-owned implementations.

Additional live-only blockers are web-worker token/PAG identity, real OpenAFS and AuriStor `fs` output, file-versus-directory ACL semantics, MaxACL display/edit policy, same- and cross-volume behavior, unavailable/read-only mounts, writeback failures, provider handling of `/proc/self/mountinfo` or an equivalent mount inventory, and the browser-visible CSP/resource boundary. Positive and negative ACL sets require separate `fs` commands, so a failure between the two batches can still leave a partial cross-set update; that failure mode must be exercised and documented live.

The upstream Dockerfile copies only `tinyfilemanager.php`, not `afs_contract.php`, `afs.php`, a production provider, the canonical asset manifest/schema, local assets, or an AFS-aware configuration, so its image is ordinary default-off Tiny File Manager rather than an AFS-capable deployment artifact. `afs_contract.php` is a mandatory reviewed application blob and must be checksum-locked with `tinyfilemanager.php`, `afs.php`, the provider, schema, manifest, and assets. `docs/AFS_APPLICATION_BLOBS.sha256` records the frozen application-side blob digests for downstream closure. Data-plane and container work should remain commit-separated for review but are security-coupled. The PHP lane owns provider dispatch, CSRF, confinement, and raw/direct URL removal. The container lane owns the complete reviewed artifact, authentication bootstrap, local assets, response verification, canonical origin, AFS client and mount namespace, mount inventory, worker UID/PAG/token, trusted-proxy and egress policy, and web-server denial of guessed static paths below the managed root. Neither lane alone closes the other's transitional categories; compatibility requires an exact-image integration run.
