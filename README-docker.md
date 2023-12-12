# tinyfilemanager

These docker images are the [tinyfilemanager](https://github.com/jpralves/tinyfilemanager) versions.
The original work of tinyfilemanager is from this [site](https://tinyfilemanager.github.io/)

There are two versions of the images:
- tinyfilemanager:VERSION - With the chown capability (php is run with root)
- tinyfilemanager:VERSION-user - php is run under a non-privileged user

There are two additional images, not published, tinyfilemanager:debug and tinyfilemanager:debug-user for debugging purposes.

## Options
- ADMIN_USER - (optional) The username of the admin user
- ADMIN_PASS - (optional) The password (This can be in clear-text or in the encrypted format)
- RO_USER - (optional) The username of the read/only user
- RO_PASS - (optional) The password (This can be in clear-text or in the encrypted format)
- ROOT_FS - (optional) The base of the viewed filesystem
- THEME - (optional) Set the default theme (light/dark)

### Syslog Specific
- SYSLOG_SERVER - Syslog server to send auditing messages
- SYSLOG_PROTO - (optional) Protocol (tcp/udp) for syslog server (default: udp)
- SYSLOG_PORT - (optional) Port for syslog server (default: 514)
- SYSLOG_JSON - (optional) Format messages in json format
- SYSLOG_FACILITY - (optional) Facility to use (default: 13)

### LDAP Specific
- LDAP_URL - URL to LDAP server (ldap://server:port)
- LDAP_BASE_SEARCH - Filter for LDAP search (dc=example,dc=org)
- LDAP_DOMAIN - (optional) LDAP domain prefix for authentication (ex: example)
- LDAP_ADMIN_GROUPS - (optional) LDAP admin groups to match separated by ';' (ex: CN=tinyfilemanager-admins,OU=GROUPS,DC=example,DC=org)
- LDAP_USER_GROUPS - (optional) LDAP user groups to match separated by ';' (ex: CN=tinyfilemanager-users,OU=GROUPS,DC=example,DC=org)
- LDAP_FILTER - (optional) - LDAP authentication attribute (default: "(|(sAMAccountName=%s)(UserPrincipalName=%s))")

For LDAP use the following Environment variables must be defined:
- LDAP_URL
- LDAP_BASE_SEARCH

If you want to use username without domain also define LDAP_DOMAIN (Users will be LDAP_DOMAIN \ username)
If you want to have admin users please define group or groups to match separated by ";"
If LDAP_ADMIN_GROUPS or LDAP_USER_GROUPS are not defined all authenticated users will be accepted as users.
If LDAP_USER_GROUPS is defined all authenticated users must belong to one of the groups in this list.

## Secrets/File support

Additionally the values used can be read from files appending _FILENAME to the environment variable.
Example:
```
ADMIN_PASS_FILENAME=/run/secrets/tinyfilemanager.admin_pass
```
Then the secret will be read from `filemanager.admin_pass` secret.

## Sample execution

With docker:
```
docker run -it -p 8111:8080 -v /opt:/opt -e ADMIN_USER=admin -e ADMIN_PASS=password -e ROOT_FS=/opt/ \
               -e SYSLOG_SERVER=192.168.1.131 -e SYSLOG_PORT=1514 -e SYSLOG_PROTO=udp -e SYSLOG_JSON=1 jpralvesatdocker/tinyfilemanager:2.5.2.3
```

With docker-compose:
```
version: '3.3'

services:
    tinyfilemanager:
        ports:
            - '8111:8080'
        volumes:
            - '/opt:/opt'
        environment:
            - ADMIN_USER=admin
            - ADMIN_PASS=pass
            - ROOT_FS=/opt
            - SYSLOG_SERVER=192.168.1.131
            - SYSLOG_PORT=1514
            - SYSLOG_PROTO=udp
            - SYSLOG_JSON=1
        image: jpralvesatdocker/tinyfilemanager:2.5.2.3
```

## Building images
```
git clone https://github.com/jpralves/tinyfilemanager
cd tinyfilemanager
docker build . -t jpralvesatdocker/tinyfilemanager:latest
docker build --build-arg RUNUSER=tinyuser . -t jpralvesatdocker/tinyfilemanager:latest-user
```

## Adding custom CA certificate to image (Option 1)

The trusted CA file is the one provided by alpine distro and it is located in `/etc/ssl/certs/ca-certificates.crt`.
Replacing this file with a copy of it with the self-signed certificate of the custom CA appended at the end works.

```
version: '3.3'

services:
    tinyfilemanager:
        ports:
            - '8111:8080'
        volumes:
            - '/opt:/opt'
            - './new-ca-certificates.crt:/etc/ssl/certs/ca-certificates.crt'
        environment:
            - ADMIN_USER=admin
            - ADMIN_PASS=pass
            - ROOT_FS=/opt
        image: jpralvesatdocker/tinyfilemanager:2.5.2.3
```

## Importing custom CA certs (Option 2)

With the base image (running with root) it is possible to import custom CAs to the trusted store.
The files with extension .pem or .crt are imported when container starts.

```
version: '3.3'

services:
    tinyfilemanager:
        ports:
            - '8111:8080'
        volumes:
            - '/opt:/opt'
            - './certs/my-custom-cert.crt:/certs/my-custom-cert.crt'
        environment:
            - ADMIN_USER=admin
            - ADMIN_PASS=pass
            - ROOT_FS=/opt
        image: jpralvesatdocker/tinyfilemanager:2.5.2.3
```
