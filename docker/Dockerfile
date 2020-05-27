FROM php:7.4-cli-alpine

RUN apk add \
    libzip-dev \
    oniguruma-dev

RUN docker-php-ext-install \
    zip \
    mbstring \
    iconv \
    fileinfo
