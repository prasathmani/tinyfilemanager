# how to build?
# docker login
## .....input your docker id and password
#docker build . -t tinyfilemanager/tinyfilemanager:master
#docker push tinyfilemanager/tinyfilemanager:master

# how to use?
# docker run -d -v /absolute/path:/var/www/html/data -p 80:80 --restart=always --name tinyfilemanager tinyfilemanager/tinyfilemanager:master

# if run in China and Docker Hub times out, use Github Package instead
# FROM ghcr.io/serversideup/php:8.5-cli-alpine

FROM serversideup/php:8.5-cli-alpine

USER root

# if run in China
# RUN sed -i 's/dl-cdn.alpinelinux.org/://aliyun.com' /etc/apk/repositories

RUN install-php-extensions gd

WORKDIR /var/www/html

COPY tinyfilemanager.php index.php

CMD ["php", "-S", "0.0.0.0:80"]
