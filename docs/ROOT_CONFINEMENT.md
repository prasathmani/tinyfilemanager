# Filesystem root confinement

Tiny File Manager treats the configured root as a security boundary. Every
user-controlled file route resolves through `lib/fm_root_confinement.php`.

The guard:

- canonicalizes the configured root and rejects lexical or resolved paths
  outside it;
- permits a symbolic link only when its resolved target remains inside the
  root;
- requires existing objects and opened handles to remain on the root device,
  except for verified AFS volume-device transitions described below;
- rejects nested Linux mountpoints, including same-device bind mounts reported
  by `/proc/self/mountinfo`;
- rechecks the device and inode after opening read/write handles and delays
  truncation until that check succeeds;
- omits escaping links and nested mounts from listing and search results;
- sends direct file links back through an application-mediated streaming
  route; and
- validates archive members and extracts them one at a time instead of using
  whole-archive `extractTo()` operations.

In-root links and normal same-filesystem operation remain available. An
escaping link may be unlinked, renamed, or moved as a directory entry, but it
is never followed for data access. Nested mounts are intentionally unavailable
through the file manager.

Linux AuriStor and OpenAFS clients can report a different `st_dev` after
crossing an AFS volume mount point even though no nested Linux VFS mount exists.
The guard recognizes this automatically only when the canonical configured root
is exactly `/afs` or below it and the deepest, visible mountinfo record covering
that root has the exact filesystem type `auristorfs` or `afs`. Linux OpenAFS
registers its filesystem type as `afs`; aliases, case variants, and other
filesystem types are not accepted. There is no deployment opt-in.

Only descendant device transitions receive this treatment; the configured root
must retain its initial device. Canonical-path containment, escaping-symlink
rejection, opened-handle identity checks, and `/proc/self/mountinfo` nested-mount
rejection remain enforced, including for nested mounts of an allowlisted AFS
type.

Linux deployments must expose a complete, readable `/proc/self/mountinfo` to
PHP. Empty or malformed input, invalid path escaping, or a missing covering
record fails closed. This is required both to identify the AFS implementation
and to distinguish same-device bind mounts from ordinary directories. The
filesystem-root field must be nonempty but may be an opaque kernel identifier
(for example an `nsfs` `net:[...]` value); the mountpoint field must resolve to
an absolute path.

## Tests

Run the dependency-free behavior, static-route, and HTTP-route tests:

```sh
php tests/root_confinement.php
php tests/root_confinement_afs_multidevice.php
php tests/root_confinement_static.php
php -d phar.readonly=0 tests/http_route_confinement.php
php tests/afs_io_path_audit.php
```

The HTTP test starts a loopback-only PHP development server over synthetic
temporary files. It exercises list, view, download, direct streaming, create,
upload, edit, copy, move, rename, delete, TAR creation, and TAR extraction,
including a link to a synthetic delegated credential cache outside the root.

ZIP behavior additionally requires the PHP `zip` extension. The same member
validation and guarded extraction path is used for ZIP and TAR.
