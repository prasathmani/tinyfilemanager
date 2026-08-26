# AFS Feature Inventory

This document records the AFS-related behavior present at the pre-rebase fork tip
`194b4d034e99e6ad20c99bb31ea512f12a9a916b`. It is an inventory, not a statement
that the behavior is correct or has been validated against a live OpenAFS or
AuriStor mount. Post-rebase fixes are deliberately not folded into this historical
inventory; see `docs/AFS_REBASE_NOTES.md` for the replay mapping, hardening layer,
test results, and current claim boundary.

Evidence references below use the form `commit:file:line`. Line numbers refer to
the old AFS tip so that the inventory remains stable after rebasing.

## Classification

- **Actively wired** means Tiny File Manager calls the code from its normal
  request flow when `$afsSupport` is enabled.
- **Latent helper** means `afs.php` contains an implementation, but Tiny File
  Manager does not call it or produce the legacy form fields needed to reach it.
- **Generic bypass** means Tiny File Manager continues to use its ordinary PHP
  data-plane path without the AFS device and opened-handle checks in `afs.php`.

This distinction is important: the old fork actively wires AFS ACL display and
editing, but it does not route most file operations through the AFS-safe helper
methods.

## Provenance

Fork repository: `https://github.com/karlg100/tinyfilemanager.git`

Canonical upstream: `https://github.com/prasathmani/tinyfilemanager.git`

The old AFS tip is exactly two fork-local commits after merge base
`2f357ee3d524f1085a7ca2707776c0f33ef85835` (`Fix translation error (#349)`).
The canonical upstream tip fetched for the rebase was
`41491439a6b243c55502581e53fad20bc4c6e777`.

| Commit | Subject | Fork-local behavior |
| --- | --- | --- |
| `da98b2aa88d9ba2df7c2d67578710faec4431c3e` | `added proxy support for URL downloads` | Adds optional `$proxyServer` configuration and an HTTP stream context for the non-cURL URL-upload path. It contains no AFS logic. |
| `194b4d034e99e6ad20c99bb31ea512f12a9a916b` | `added AFS support` | Adds all 967 lines of `afs.php` and modifies Tiny File Manager to load it, display caller access, and read/write ACLs. It also contains unrelated local configuration and UI changes. |

The added `afs.php` carries a University of Michigan copyright notice and says
“See COPYRIGHT” (`194b4d0:afs.php:2-5`), but the old tree contains `LICENSE` and
no `COPYRIGHT` file. That source/license provenance should be resolved before
redistribution.

## Actively wired AFS behavior

### Bootstrap and platform assumptions

- `$afsSupport` defaults to `true`, and Tiny File Manager conditionally loads
  `afs.php` (`194b4d0:tinyfilemanager.php:134-146`).
- Loading `afs.php` requires the PHP `posix` extension. If it is absent, the
  include prints an error and terminates the request
  (`194b4d0:afs.php:12-16`).
- Tiny File Manager's configured root remains `$_SERVER['DOCUMENT_ROOT']`; AFS
  enablement does not change it to `/afs` or require it to be within AFS
  (`194b4d0:tinyfilemanager.php:56-62`).
- Application login is disabled by default in the AFS commit
  (`194b4d0:tinyfilemanager.php:20-30`). As a result, `FM_READONLY` is false for
  this configuration. The code appears to assume external authentication and
  filesystem enforcement, but does not establish either.
- `Afs::__construct()` reads `$_SERVER['REMOTE_USER']` without checking that it
  exists, records the initial working directory, stats `/afs/`, compares its
  device with `/`, validates the supplied path, initializes legacy form state,
  invokes the legacy command dispatcher, and calls `getACLAccess()`
  (`194b4d0:afs.php:52-94`). `REMOTE_USER` is used only in error logging; it is
  not used to acquire credentials.

No `aklog`, `klog`, token, PAG, `setpag`, or equivalent caller-credential setup
exists in either fork-local commit. `/usr/bin/fs` and all filesystem operations
inherit the web-server process's effective credentials.

### Permission display and `getcalleraccess`

When AFS support is enabled and permission columns are visible, Tiny File
Manager replaces the POSIX mode string with the output of
`Afs::getACLAccess()` for both folders and files. It also removes the POSIX
owner/group column and adjusts table colspans
(`194b4d0:tinyfilemanager.php:1981-1986,2010-2049,2063-2124,2142-2156`).

`Afs::getACLAccess($path)`:

1. Runs `/usr/bin/fs getcalleraccess <path>`.
2. Accepts only output matching the exact English form
   `Callers access to ... is <one-to-seven word characters>`.
3. Lowercases and returns the rights string.
4. Maps `l`, `a`, `d`, `i`, `r`, and `w` to public privilege flags, but only
   enters the mapping block if lookup (`l`) is present.

The implementation is at `194b4d0:afs.php:651-685`.

For every displayed item, Tiny File Manager constructs `Afs`, whose constructor
already invokes `getACLAccess()`, and then explicitly calls `getACLAccess()` a
second time (`194b4d0:tinyfilemanager.php:2015-2017,2072-2074`). Therefore a
normal directory listing performs two shell commands per displayed entry.

The resulting privilege flags do not authorize or hide actions. The delete,
rename, copy, edit, upload, and download controls continue to be governed by
`FM_READONLY`, not AFS rights. `Afs::get_js_declarations()` can expose the flags
to JavaScript, but Tiny File Manager never calls it
(`194b4d0:afs.php:933-952`).

### ACL reading

`Afs::readAcl($path)` runs `/usr/bin/fs listacl <path>` and parses normal and
negative ACL entries into boolean maps for these AFS rights:

| Right | Meaning used by the UI |
| --- | --- |
| `l` | lookup |
| `r` | read |
| `w` | write |
| `i` | insert |
| `d` | delete |
| `k` | lock |
| `a` | administer |

The parser is at `194b4d0:afs.php:593-649`. It depends on the exact English
headings emitted by `fs listacl`, splits on `Negative rights:`, and recognizes
an error only if output starts with `fs:`. It does not force a stable locale.

The AFS permissions page calls this method and renders the currently returned
normal and negative entries (`194b4d0:tinyfilemanager.php:1865-1937`). It does
not provide a control to add a new principal.

Known UI defects in the old tip include:

- Both normal and negative lock checkboxes test `$perms['l']` instead of
  `$perms['k']` (`194b4d0:tinyfilemanager.php:1919,1934`).
- ACL principal names and the full path are not consistently escaped in the
  generated HTML.
- The page is offered for regular files as well as directories. Actual
  `fs setacl` behavior for regular-file paths remains a live-AFS validation
  requirement.

### ACL writing

`Afs::changeAcl()` supports normal or negative ACLs and optionally recursive
changes. It shell-quotes the entity, rights, and path, then executes either:

```text
/usr/bin/fs sa [ -negative] <path> <entity> <rights>
```

or an unqualified `find ... -type d -exec /usr/bin/fs sa ...` command for
recursive operation (`194b4d0:afs.php:563-591`). It treats any output containing
`fs:` as failure.

Tiny File Manager disables the POSIX chmod GET and POST flows while AFS support
is enabled and substitutes ACL flows
(`194b4d0:tinyfilemanager.php:1025-1112,1793-1863`). The AFS POST handler:

- handles only `$_POST['normal']`;
- removes a synthetic `acl` field, concatenates checked right names, and sends
  `none` when a principal has no checked rights;
- constructs a new `Afs` object for every normal principal;
- short-circuits after the first failed update, so earlier ACL changes can
  remain applied while later principals are skipped; and
- leaves its redirect commented out.

Although the GET page renders negative rights, the POST handler ignores
`$_POST['negative']`. The UI also exposes neither recursive changes nor the
latent `negative=true` argument. These are incomplete features, not merely
untested ones.

`readAcl()`, `changeAcl()`, and `getACLAccess()` accept arbitrary path arguments
and do not independently call `pathSecurity()` or `makePathAFSlocal()`. An
`Afs` constructor that rejects its path still produces an object, and Tiny File
Manager then calls `getACLAccess()` on the original path. Consequently, enabling
AFS does not prevent ACL commands from being attempted on a non-AFS Tiny File
Manager root.

## Latent AFS helpers

The following behavior exists in `afs.php`, but it is not connected to Tiny
File Manager's forms or action handlers.

### Path and mount confinement primitives

`Afs` uses the device number returned by `stat('/afs/')` as its definition of
“in AFS.”

- `pathSecurity($path)` follows the path with `stat()`, accepts it only when its
  device matches `/afs`, and strips a trailing slash. Its own comment calls it
  a raceable initial check (`194b4d0:afs.php:804-830`).
- `makePathAFSlocal($path)` changes into a directory, stats `.`, and requires
  the same AFS device before later code operates on basenames
  (`194b4d0:afs.php:833-849`).
- `linkSafeFileExists($path)` uses `lstat()`, so a broken symlink counts as an
  existing entry (`194b4d0:afs.php:860-869`).
- `setPath()` treats literal `/afs` and `/afs/` as null, then attempts to run
  `pathSecurity()` on the null path. The AFS root therefore cannot be
  represented correctly (`194b4d0:afs.php:872-896`).

`Afs::__construct()` attempts to detect a missing AFS mount by rejecting the
case where `/afs` and `/` have the same device number
(`194b4d0:afs.php:56-68`). Failure of `stat('/afs/')` itself is not checked
before array access. This heuristic also assumes that all paths intended to be
managed share `/afs`'s device number.

There is no explicit OpenAFS/AuriStor volume-mount-point API. Real nested mounts
with another device are rejected by the helper checks. Whether OpenAFS and
AuriStor volume mount points present the expected `stat()` and `is_link()`
semantics must be established on live mounts.

### Legacy dispatcher

The constructor creates a session `formKey` and calls `processCommand()`. That
dispatcher requires `$_POST['command']` plus a matching form key and routes
these legacy commands:

| Command | Helper |
| --- | --- |
| `newfolder` | `Afs::createFolder()` |
| `rename` | `Afs::afsRename()` |
| `cut` | `Afs::moveFiles()` |
| `copy` | `Afs::copyFiles()` |
| `delete` | `Afs::deleteFiles()` |

See `194b4d0:afs.php:84-93,126-156`. No Tiny File Manager form or handler emits
`command`, `formKey`, `selectedItems`, `originPath`, or `newName`; those field
names occur only in `afs.php`. The dispatcher is therefore unreachable from the
Tiny File Manager UI as committed.

### Latent operation behavior

| Helper | Intended AFS behavior | Important limitations |
| --- | --- | --- |
| `Afs::createFolder()` (`afs.php:197-220`) | Changes into a verified AFS directory, reduces the requested value to a basename, uses `lstat()` collision detection, and creates the directory. | Uses mode `0644`, which lacks directory execute/search bits. |
| `Afs::removeFolder()` / `deleteFiles()` (`afs.php:223-324`) | Recursively checks directory devices, avoids descending through symlinked directories, and unlinks entries relative to a checked working directory. | Some unlink results are ignored; no Tiny delete flow calls these methods. |
| `Afs::afsRename()` (`afs.php:327-362`) | Rejects symlink rename, checks destination with `lstat()`, and delegates to a root-confined rename helper. | Calls undefined `filedrawers_rename()`. The `filedrawers` extension check is commented out at `afs.php:18-24`, and no implementation exists in the repository. |
| `Afs::moveFiles()` (`afs.php:364-390`) | Delegates moves to `filedrawers_rename(source,destination,'/afs')`. | Also depends on the missing function and is unreachable from Tiny forms. |
| `Afs::copyFiles()` / `copy_dirs()` (`afs.php:392-475`) | Recursively checks source and destination directories against the AFS device and dispatches files and links to `Afs::copy()`. | It creates the target directory before its self-copy equality check, can leave a directory after failure, and does not explicitly preserve ACLs. |
| `Afs::copy()` (`afs.php:478-541`) | For regular files, opens the source, verifies the opened handle's device, verifies the destination parent, opens the destination with exclusive `xb`, and copies in 1 MiB chunks. For symlinks, it reproduces the link without dereferencing it after checking both parent directories. | It preserves links whose target may resolve outside AFS; uses the source basename instead of the requested destination basename for link creation; does not check read/write results; and can report success after a short write. |
| `Afs::readfile()` (`afs.php:544-561`) | Opens the configured path, verifies the opened handle's device, and only then streams it to the client. | No Tiny download, view, or direct-link path calls it. |

Other latent helpers include symlink-aware type detection, JavaScript folder
listing, a breadcrumb rooted at `/afs`, Smarty assignments, and privilege/entry
JavaScript declarations (`194b4d0:afs.php:97-123,687-802,898-963`). They are
legacy FileDrawers-style code rather than Tiny File Manager integration.
`getType()` references an absent `Mime` class, `get_foldercontents_js()` uses a
commented-out MIME icon assignment, and `originPath` is created as an undeclared
dynamic property.

## Generic Tiny File Manager data-plane paths

The table below describes the operations actually reached from Tiny File
Manager. None of them invokes the corresponding AFS-safe helper.

| Operation | Active Tiny File Manager path at `194b4d0` | AFS and symlink coverage |
| --- | --- | --- |
| Root and navigation | `FM_ROOT_PATH` remains the configured document root; `FM_PATH` is lexically cleaned (`tinyfilemanager.php:347-386,2449-2459`). | No requirement that the root or resolved path be on the `/afs` device. Lexical cleanup does not establish a resolved-path device boundary. |
| Create file/folder | Ordinary `fopen()` and `fm_mkdir()` (`tinyfilemanager.php:600-633,2353-2364`). | No AFS device validation. `fm_mkdir()` creates recursively with mode `0777` subject to umask. |
| Copy/duplicate | `fm_rcopy()` and `fm_copy()` (`tinyfilemanager.php:635-704,2323-2387`). | Uses `is_dir()`, `scandir()`, and PHP `copy()`. Because `is_dir()` is tested before `is_link()`, a symlink to a directory is followed and can traverse outside AFS. |
| Move/rename | `fm_rename()` and PHP `rename()` (`tinyfilemanager.php:635-765,767-793,2306-2313`). | No device check and no AFS-specific link handling. Unlike latent `afsRename()`, symlinks are not categorically rejected. |
| Delete | Single and mass handlers call `fm_rdelete()` (`tinyfilemanager.php:578-598,890-918,2229-2250`). | `fm_rdelete()` checks `is_link()` first and unlinks the link instead of recursing through it, but applies no AFS device boundary to real directories or nested mounts. |
| Browser upload | Uses `$_REQUEST['fullpath']`, recursive `mkdir(0777)`, and `move_uploaded_file()` (`tinyfilemanager.php:823-888`). | No AFS resolved-path or device validation. No helper confines the requested full path to AFS. |
| URL upload | Downloads to `sys_get_temp_dir()` and then calls ordinary `rename()` into the destination (`tinyfilemanager.php:495-573`). | No AFS destination check. Moving a local temporary file into AFS is cross-filesystem-sensitive. The proxy commit affects only the HTTP fetch, not destination safety. |
| Download | Uses `is_file()`, `filesize()`, and built-in `readfile()` (`tinyfilemanager.php:795-821`). | Does not use opened-handle device verification and follows file symlinks. |
| View/quick view | Uses MIME/file inspection and `file_get_contents()` for text; media URLs point at the web-visible file URL (`tinyfilemanager.php:1502-1696`). | No AFS helper or device check. File symlinks are followed. Media and “Open” links move the read into the web server. |
| Edit/save/backup | Editors use `fopen(...,'w')`; AJAX save and backup use ordinary `fopen()`/`copy()` (`tinyfilemanager.php:398-445,1698-1789`). | No AFS device or opened-handle confinement. Symlink targets can be read or modified through normal PHP resolution. |
| Archive creation | Changes into the current path and calls `FM_Zipper` or `FM_Zipper_Tar` (`tinyfilemanager.php:920-967,3011-3185`). | Recursive archive creation uses `is_dir()`/`scandir()` without an AFS boundary and can follow symlinked directories. |
| Archive extraction | Calls `ZipArchive::extractTo()` or `PharData::extractTo()` (`tinyfilemanager.php:969-1023,3056-3067`). | The fork adds no AFS device validation or archive-entry confinement before extraction. |
| Direct link | Folder/file rows and the viewer emit `FM_ROOT_URL` links (`tinyfilemanager.php:1608-1609,2055,2133`). | Bypasses PHP and `Afs::readfile()` entirely. Authentication, token use, symlink resolution, and confinement become web-server concerns. |

Search, image preview, MIME probing, directory-size calculation, and other
ordinary Tiny File Manager reads likewise remain outside `Afs`.

## Mount-point and symlink behavior summary

### What the latent helpers attempt

- Define AFS membership as equality with `/afs`'s `st_dev`.
- Reject `/afs` when it appears to be part of `/` rather than a separate mount.
- Change into a verified parent and operate on basenames to reduce path races.
- Verify opened regular-file handles before copy or download.
- Use `lstat()` for destination collision checks.
- Unlink symlinks during deletion rather than walking through them.
- Preserve symlinks during copy rather than copying their targets.

### What the wired application actually does

- Does not require `FM_ROOT_PATH` to resolve inside AFS.
- Does not use device checks for create, copy, move, delete, upload, download,
  edit, archive, view, or direct-link paths.
- Follows directory symlinks during generic copy and archive creation.
- Follows file symlinks during generic download, view, and edit.
- Correctly unlinks a symlink rather than recursively deleting its target in
  the generic delete helper, but does not stop at real filesystem boundaries.
- Has no explicit handling for OpenAFS/AuriStor volume mount points.

AFS volume mount points, ordinary links within AFS, links out of AFS, broken
links, and any Unix mounts below the configured root require separate live
coverage. A test of one kind does not establish the behavior of the others.

## Other fork-local behavior

### Proxy commit `da98b2a`

The first fork-local commit adds a commented `$proxyServer = 'host:port'`
setting (`194b4d0:tinyfilemanager.php:129-132`). In the non-cURL URL-upload
branch it creates an HTTP stream context with:

```php
array('http' => array(
    'proxy' => 'tcp://' . $proxyServer,
    'request_fulluri' => true,
));
```

See `194b4d0:tinyfilemanager.php:541-547`. The code hardcodes
`$use_curl = false` at line 496, so the proxy is effective for the committed
path. If a later upstream path selects cURL, this setting does not configure a
cURL proxy.

### Non-AFS changes bundled into `194b4d0`

These changes are independent of ACL or AFS confinement and should be resolved
deliberately rather than treated as incidental conflict noise:

| Change | Old-tip evidence |
| --- | --- |
| Disable Tiny File Manager's built-in authentication | `tinyfilemanager.php:20-30` |
| Change date display from `d.m.y H:i` to `m/d/Y H:i:s` | `tinyfilemanager.php:70-72` |
| Disable the online office-document viewer | `tinyfilemanager.php:91-96` |
| Define `FM_EXCLUDE_ITEMS` only when the exclusion list is nonempty, and make an undefined constant mean allow-all | `tinyfilemanager.php:360-366,2480-2493` |
| Update the DataTables CDN from 1.10.20 to 1.10.21 | `tinyfilemanager.php:3692` |
| Add English AFS-right labels, including a duplicate `admin` assignment | `tinyfilemanager.php:4026-4033` |
| Change line endings on the first three lines | opening hunk of commit `194b4d0` |

## Compatibility blockers and claim boundary

The rebased result must not be described as AFS-compatible without resolving or
explicitly accepting the following points:

1. **The active data plane bypasses AFS confinement.** Copy, move, delete,
   upload, download, edit, archive, view, and direct-link behavior does not use
   the `Afs` safety helpers.
2. **No live AFS evidence exists in this inventory.** Device-number assumptions,
   ACL command output, volume mount points, symlinks, and actual kernel
   enforcement remain unverified.
3. **Caller credentials are external and undocumented.** The code does not
   establish an AFS/AuriStor token or PAG, and `REMOTE_USER` does not bind the
   PHP process to that user.
4. **The root and utility locations are fixed or unconstrained.** AFS helpers
   hardcode `/afs` and `/usr/bin/fs`, while Tiny File Manager's root remains the
   document root and is not required to be in AFS.
5. **Mount and link semantics are incomplete.** The helpers rely on `st_dev` and
   POSIX link predicates; generic Tiny paths can follow links outside AFS, and
   AFS/AuriStor volume mount-point behavior is unknown.
6. **Legacy move and rename cannot run as committed.** They depend on missing
   `filedrawers_rename()`.
7. **ACL editing is incomplete.** Negative changes are ignored, lock state is
   rendered incorrectly, partial normal-ACL updates are possible, and regular
   file ACL behavior has not been established.
8. **ACL command parsing and performance are fragile.** It assumes exact English
   output, does not set a stable locale, has limited error detection, and runs
   `getcalleraccess` twice per displayed entry.
9. **Some latent helpers have correctness defects.** Literal `/afs` path
   handling, directory creation mode, link-copy destination naming, unchecked
   stream writes, and self-copy cleanup all need decisions or fixes before use.
10. **Source provenance is incomplete.** The newly added file references a
    missing `COPYRIGHT` document.

At the old fork tip, it is accurate to claim only that Tiny File Manager has an
AFS-aware ACL display/editor and a collection of dormant AFS-oriented helper
methods. It is not accurate to claim that all managed paths are confined to AFS
or that all file operations are AFS-safe.

## Live-AFS validation targets

The following require a live OpenAFS/AuriStor environment and are intentionally
separate from mount-free static/regression tests:

- `/afs` absent, `/afs` accidentally local, and a correctly mounted `/afs`;
- configured root outside AFS, at `/afs`, and below `/afs`;
- traversal across real AFS/AuriStor volume mount points;
- ordinary in-AFS symlinks, links to another AFS volume, links outside AFS, and
  broken links for every read and mutation operation;
- `fs getcalleraccess`, `fs listacl`, and `fs setacl` output and exit behavior
  under the deployment locale and AuriStor/OpenAFS client version;
- normal, negative, and lock ACL round trips, including failure partway through
  a multi-principal update;
- file-versus-directory paths for ACL operations;
- copy, move, rename, delete, browser upload, URL upload, download, edit,
  archive, view, and direct-link behavior under restricted AFS rights;
- URL-upload movement from local temporary storage into AFS; and
- confirmation that the web request runs in the intended user's credential
  context and that direct web-server reads enforce the same policy.
