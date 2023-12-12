FROM php:8.2.13-zts-alpine3.18

STOPSIGNAL SIGINT

WORKDIR /var/www/html

RUN apk add --no-cache zip libzip openssl bzip2 \
&&  apk add --no-cache --virtual .build-deps libzip-dev openssl-dev bzip2-dev oniguruma-dev openldap-dev build-base autoconf linux-headers \
&&  pecl install xattr-1.4.0 \
&&  rm -rf /tmp/pear \
&&  docker-php-ext-install zip bz2 ldap sockets \
&&  runDeps="$( \
    scanelf --needed --nobanner --format '%n#p' --recursive /usr/local/lib/php/extensions \
      | tr ',' '\n' \
      | sort -u \
      | awk 'system("[ -e /usr/local/lib/" $1 " ]") == 0 { next } { print "so:" $1 }' \
  )" \
&&  apk add --virtual .phpexts-rundeps $runDeps \
&&  apk del .build-deps \
&&  rm -rf /var/cache/apk/*

COPY *.php /var/www/html/
COPY *.json /var/www/html/
COPY *.ini /usr/local/etc/php/conf.d/

RUN ln -sf tinyfilemanager.php index.php

RUN mkdir /certs
COPY startup.sh /

CMD [ "sh", "/startup.sh" ]

EXPOSE 8080

USER root

