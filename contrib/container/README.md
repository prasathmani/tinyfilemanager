# Tiny File Manager container

This builds a local-filesystem Tiny File Manager service. It requires an
external configuration file, stores managed files outside Apache's document
root, and listens on `127.0.0.1:8080` by default.

## Requirements

- Linux: a current Docker Engine with BuildKit and the `docker compose` plugin.
- macOS or Windows: a current Docker Desktop using Linux containers.

Run all commands from the repository root and include the shown `-f` option.

Choose a unique project name for this deployment. Compose refuses to run
without it, preventing separate checkouts from sharing a data volume:

Linux or macOS:

```sh
export TFM_PROJECT=tinyfilemanager-local
```

Windows PowerShell:

```powershell
$env:TFM_PROJECT = "tinyfilemanager-local"
```

## Build

```sh
docker compose -f contrib/container/compose.yaml build
```

## Configure

Create the ignored runtime configuration:

Linux or macOS:

```sh
cp contrib/container/config.php.example contrib/container/config.php
```

Windows PowerShell:

```powershell
Copy-Item contrib/container/config.php.example contrib/container/config.php
```

Generate a password hash without putting the password in the command line:

```sh
docker compose -f contrib/container/compose.yaml run --rm --no-deps --entrypoint tinyfilemanager-hash-password tinyfilemanager
```

Replace `REPLACE_WITH_PASSWORD_HASH` in `config.php` with the generated hash.
Edit the user name, read-only users, and time zone as needed. The application
upload limit may be lowered in `config.php`; raising the 256 MiB server limit
also requires editing `php.ini` and rebuilding. Keep `$root_path` at
`/srv/tinyfilemanager/data`; startup rejects missing credentials, placeholder
credentials, and baseline-policy mismatches. Per-user directory mappings are
not supported by this image.

The supplied configuration disables settings changes, direct links, media
previews, online document viewing, and URL uploads. Managed files remain
outside Apache's document root and downloads continue through the authenticated
application.

### Serve an existing host directory

Tiny File Manager's `$root_path` is separate from Apache's `DocumentRoot`.
Keep `$root_path` at `/srv/tinyfilemanager/data` and point that path at any
dedicated, unshared host directory with the supplied Compose override. Choose
this mode instead of the Docker-managed volume described below; do not mix the
commands for the two modes.

Linux:

These UID commands assume rootful Docker. With rootless or
user-namespace-remapped Docker, use the named volume unless UID 33 is mapped to
the correct host UID. For a new directory, `mkdir` must succeed; stop and review
permissions instead of continuing if the path already exists.

```sh
sudo mkdir -m 0750 /srv/tinyfilemanager-data &&
  sudo chown 33:33 /srv/tinyfilemanager-data &&
  export TFM_DATA_PATH=/srv/tinyfilemanager-data
```

For an existing dedicated tree, inspect and back up its ownership and ACLs,
then grant numeric UID 33 read, write, and directory-search access with the
host's ACL tools. Do not use recursive `chmod 0777` or blindly change ownership.

macOS:

```sh
mkdir -p "$HOME/tinyfilemanager-data"
export TFM_DATA_PATH="$HOME/tinyfilemanager-data"
```

Windows PowerShell:

```powershell
New-Item -ItemType Directory -Force "$HOME\tinyfilemanager-data" | Out-Null
$env:TFM_DATA_PATH = "$HOME\tinyfilemanager-data"
```

On macOS and Windows, ensure Docker Desktop can share the selected path. The
current host user must have read and write permission. If a Windows home
directory is redirected to a network share, select a local drive path instead.

On SELinux hosts, the override requests a private `Z` relabel. Never select
`/`, an entire home or system directory, or a path shared with another service
or container. Keep both `TFM_PROJECT` and `TFM_DATA_PATH` set in the same shell
for every host-directory command.

Start with the host directory:

```sh
docker compose -f contrib/container/compose.yaml -f contrib/container/compose.host-path.yaml up -d
```

Use both `-f` options for later `ps`, `logs`, and `down` commands. Do not mount
managed files below `/var/www/html`, where Apache could serve them without Tiny
File Manager authentication. Startup fails if the selected directory is not
readable, writable, and searchable by the Apache worker.

For a TLS reverse proxy, set `$container_tls_proxy = true` so session cookies
are marked `Secure`. Keep the container port on loopback, and configure the
proxy to replace rather than append forwarded headers.

## Start with a Docker-managed volume

Use this mode only when `TFM_DATA_PATH` is not being used:

```sh
docker compose -f contrib/container/compose.yaml up -d
docker compose -f contrib/container/compose.yaml ps
```

Open <http://127.0.0.1:8080>. To use another host port, set `TFM_PORT`, for
example:

Linux or macOS:

```sh
export TFM_PORT=8081
```

Windows PowerShell:

```powershell
$env:TFM_PORT = "8081"
```

Then run the applicable `up -d` command again.

View logs or stop the service with:

```sh
docker compose -f contrib/container/compose.yaml logs -f
docker compose -f contrib/container/compose.yaml down
```

The named data volume survives `down`. Running `down -v` deletes it.
`down -v` does not delete a bind-mounted host directory.

The built-in healthcheck is PHP/HTTP liveness only; it does not attest login,
data integrity, or production readiness.

## Scope

- This is a trusted-local, non-production image. Tiny File Manager follows
  filesystem symlinks, so the data mount is not a confinement boundary. Do not
  use restored/untrusted trees or trees containing symlinks.
- `config.php` is trusted executable PHP. Start from the supplied example; do
  not mount configuration obtained from another user or system.
- The image has no TLS terminator. Keep the loopback binding or use the TLS
  proxy mode above; do not expose it directly to an untrusted network.
- The current UI loads assets from public CDNs, so this image is unsuitable
  for controlled or protected data.
- Never put passwords, private keys, or other secrets in the image or build
  context. Mount runtime configuration read-only.
