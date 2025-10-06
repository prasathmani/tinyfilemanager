# how to use?
# docker run -d -v /absolute/path:/var/www/html/data -p 80:80 --restart=always --name tinyfilemanager tinyfilemanager/tinyfilemanager:master

FROM php:8.3.26-cli-alpine

RUN apk update && apk upgrade --no-cache

RUN apk add --no-cache \
    libzip-dev \
    oniguruma-dev

RUN docker-php-ext-install \
    zip 

WORKDIR /var/www/html

COPY tinyfilemanager.php index.php

CMD ["sh", "-c", "php -S 0.0.0.0:80"]
