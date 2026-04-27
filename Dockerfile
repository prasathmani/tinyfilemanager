# how to build?
# docker build -t tinyfilemanager/tinyfilemanager:master .

FROM php:8.3-cli-alpine AS runtime

RUN apk add --no-cache curl libzip-dev oniguruma-dev \
    && docker-php-ext-install zip

WORKDIR /var/www/html

COPY tinyfilemanager.php ./index.php
COPY config.php ./config.php
COPY src ./src
COPY translation.json ./translation.json
COPY KatalogMD.webp ./KatalogMD.webp

RUN addgroup -S tfm && adduser -S -G tfm tfm \
    && mkdir -p /var/www/html/data /var/www/html/uploads \
    && chown -R tfm:tfm /var/www/html

USER tfm

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8080/ >/dev/null || exit 1

CMD ["php", "-S", "0.0.0.0:8080", "-t", "/var/www/html"]
