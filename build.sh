#!/bin/bash

VERSION=$(grep "define('VERSION'" tinyfilemanager.php | sed "s/^.*'\([0-9.]*\)'.*$/\1/")
#docker build . -t jpralvesatdocker/tinyfilemanager:$(git log -1 --pretty=%h)-root
docker build . -t jpralvesatdocker/tinyfilemanager:$VERSION
#docker build -f Dockerfile.rootless . -t jpralvesatdocker/tinyfilemanager:$(git log -1 --pretty=%h)-user
docker build -f Dockerfile.user . -t jpralvesatdocker/tinyfilemanager:$VERSION-user \
       --build-arg="IMG_BASE=jpralvesatdocker/tinyfilemanager:$VERSION" --build-arg="RUNUSER=tinyfilemanager"
docker build -f Dockerfile.debug . -t jpralvesatdocker/tinyfilemanager:debug
docker build -f Dockerfile.user . -t jpralvesatdocker/tinyfilemanager:debug-user \
       --build-arg="IMG_BASE=jpralvesatdocker/tinyfilemanager:debug" --build-arg="RUNUSER=tinyfilemanager"
