# how to build?
# docker login
## .....input your docker id and password
#docker build . -t tinyfilemanager/tinyfilemanager:master
#docker push tinyfilemanager/tinyfilemanager:master

# how to use?
# docker run -d -v /absolute/path:/var/www/html/data -p 80:80 --restart=always --name tinyfilemanager tinyfilemanager/tinyfilemanager:master

FROM php:7.4-cli-alpine

# if run in China
# RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories

RUN apk add \
    libzip-dev \
    oniguruma-dev

RUN docker-php-ext-install \
    zip \
    mbstring \
    iconv \
    fileinfo

WORKDIR /var/www/html

COPY tinyfilemanager.php index.php
COPY config-sample.php config.php
RUN sed -i "s/\$root_path =.*;/\$root_path = \$_SERVER['DOCUMENT_ROOT'].'\/data';/g" config.php && \
    sed -i "s/\$root_url = '';/\$root_url = 'data\/';/g" config.php

CMD ["sh", "-c", "php -S 0.0.0.0:80"]
