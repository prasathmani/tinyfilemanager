# tinyfilemanager

These docker images are the [tinyfilemanager](https://github.com/jpralves/tinyfilemanager) versions.
The original work of tinyfilemanager is from this [site](https://tinyfilemanager.github.io/)

There are two versions of the images:
- 2.4.4-root - With the chown capability
- 2.4.4-user - php is run under a non-privileged user

## Options
- ADMIN_USER - (optional) The username of the admin user
- ADMIN_PASS - (optional) The password (This can be in clear-text or in the encrypted format)
- RO_USER - (optional) The username of the read/only user
- RO_PASS - (optional) The password (This can be in clear-text or in the encrypted format)
- ROOT_FS - (optional) The base of the viewed filesystem

## Sample execution

With docker:
```
docker run -it -p 8111:8080 -v /opt:/opt -e ADMIN_USER=admin -e ADMIN_PASS=password -e ROOT_FS=/opt/ jpralvesatdocker/tinyfilemanager:2.4.4-root
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
        image: jpralvesatdocker/tinyfilemanager:2.4.4-root
```

## Building images
```
git clone https://github.com/jpralves/tinyfilemanager
cd tinyfilemanager
docker build . -t jpralvesatdocker/tinyfilemanager-root:latest-root
docker build --build-arg RUNUSER=tinyuser . -t jpralvesatdocker/tinyfilemanager:latest-user
```

