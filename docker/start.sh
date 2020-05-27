#!/usr/bin/env bash

set -e

if [[ ! -f ".env" ]]; then
    echo "COMPOSE_PROJECT_NAME=tinyfilemanager" >> .env

    root_path=""
    while [[ "${root_path}" == "" ]]; do
        read -p "Define the root path: " root_path
    done

    echo "ROOT_PATH=${root_path}" >> .env
    echo "USER_ID=$(id -u)" >> .env
    echo "GROUP_ID=$(id -g)" >> .env
fi

docker-compose stop
docker-compose build --parallel
docker-compose up -d --remove-orphans
