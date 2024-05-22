# 微型文件管理器

[![Live Demo](https://img.shields.io/badge/Live-Demo-brightgreen.svg?style=flat-square)](https://tinyfilemanager.github.io/demo/)
[![帮助文档](https://img.shields.io/badge/Help-Docs-lightgrey.svg?style=flat-square)](https://github.com/prasathmani/tinyfilemanager/wiki)
[![GitHub 发布版本](https://img.shields.io/github/release/prasathmani/tinyfilemanager.svg?style=flat-square)](https://github.com/prasathmani/tinyfilemanager/releases)
[![GitHub 许可证](https://img.shields.io/github/license/prasathmani/tinyfilemanager.svg?style=flat-square)](https://github.com/prasathmani/tinyfilemanager/blob/master/LICENSE)
[![PayPal 捐赠](https://img.shields.io/badge/Donate-Paypal-lightgrey.svg?style=flat-square)](https://www.paypal.me/prasathmani)
![GitHub 赞助者](https://img.shields.io/github/sponsors/prasathmani)

> TinyFileManager 是一个基于 web 的 PHP 文件管理器，它简单、快速且体积小巧，可以作为一个单文件 PHP 文件部署到服务器上的任何文件夹中。它是一个支持多语言的 web 应用程序，用于在线通过 web 浏览器存储、上传、编辑和管理文件和文件夹。该应用程序运行在 PHP 5.5+ 上，它允许创建多个用户，每个用户都可以有自己的目录，并内置了对使用 cloud9 IDE 管理文本文件的支持，支持超过 150 种语言的语法高亮和超过 35 种主题。

## 演示

[Demo](https://tinyfilemanager.github.io/demo/)

## 文档

Tinyfilemanager 的详细文档可以在 [中文文档网](https://fm.hestiamb.org) 上找到。

[![Tiny File Manager](screenshot.gif)](screenshot.gif)

## 需求

- PHP 5.5.0 或更高版本。
- 强烈建议使用 fileinfo、iconv、zip、tar 和 mbstring 扩展。

## 如何使用

从主分支下载最新版本的 ZIP 文件。

只需将 tinyfilemanager.php 复制到您的 web 空间即可。您还可以将文件名从 "tinyfilemanager.php" 更改为其他名称，您知道我的意思。

默认的用户名/密码是：**admin/admin@123** 和 **user/12345**。

:warning: 注意: 请在使用前在 `$auth_users` 中设置您自己的用户名和密码。密码使用 `password_hash()` 进行加密。要生成新的密码哈希，请访问 [哈希密码生成器](https://dns.hestiamb.org/password/pwd.html)。

要启用/禁用身份验证，请将 `$use_auth` 设置为 true 或 false。

:information_source: 信息：在相同的文件夹中添加您自己的配置文件 [config.php](https://tinyfilemanager.github.io/config-sample.txt) 以用作额外的配置文件。

:information_source: 信息：要在没有 CDN 资源的情况下离线工作，请使用 [offline](https://github.com/prasathmani/tinyfilemanager/tree/offline) 分支。

### :loudspeaker: 功能

- :cd: 开源、轻量级且极其简单
- :iphone: 适用于触摸设备的移动友好视图
- :information_source: 基础功能如创建、删除、修改、查看、下载、复制和移动文件
- :arrow_double_up: Ajax 上传，支持拖放、从 URL 上传、多文件上传及文件扩展名过滤
- :file_folder: 创建文件夹和文件的能力
- :gift: 支持文件压缩和解压（`zip`、`tar`）
- :sunglasses: 支持用户权限 - 基于会话和每个用户的根文件夹映射
- :floppy_disk: 复制文件直接 URL
- :pencil2: Cloud9 IDE - 支持 `150+` 种语言的语法高亮，超过 `35+` 种主题，满足您喜爱的编程风格
- :page_facing_up: Google/Microsoft 文档查看器帮助您预览 `PDF/DOC/XLS/PPT/etc`。Google Drive 查看器可预览高达 25 MB 的文件
- :zap: 文件备份和 IP 黑名单及白名单
- :mag_right: 搜索 - 使用 `datatable js` 搜索和过滤文件
- :file_folder: 从列表中排除文件夹和文件
- :globe_with_meridians: 支持多语言（超过 32 种），翻译语言需要 `translation.json` 文件
- :bangbang: 更多功能...

## 通过Docker部署

确保您已经**安装了docker**，[安装参考](https://docs.docker.com/engine/install/)

> **注意:** 您需要一个绝对路径，TinyFileManager将使用该路径提供服务。
> 
> 如果您想在**树莓派或其他特殊平台**上运行此项目，您可以下载项目并**自行构建镜像**。

您可以执行以下命令：

```shell
$ docker run -d -v /absolute/path:/var/www/html/data -p 80:80 --restart=always --name tinyfilemanager tinyfilemanager/tinyfilemanager:master
$ docker ps
CONTAINER ID   IMAGE                                COMMAND                  CREATED         STATUS         PORTS                                       NAMES
648dfba9c0ff   tinyfilemanager/tinyfilemanager:master   "docker-php-entrypoi…"   4 minutes ago   Up 4 minutes   0.0.0.0:80->80/tcp, :::80->80/tcp           tinyfilemanager
```

访问`http://127.0.0.1/`并输入默认的用户名和密码，然后开始使用。

DockerHub: [tinyfilemanager](https://hub.docker.com/r/tinyfilemanager/tinyfilemanager)

#### 如何在Docker中更改配置

原始配置：

```php
// 文件管理器的根路径
// 使用目录的绝对路径，例如：'/var/www/folder' 或 $_SERVER['DOCUMENT_ROOT'].'/folder'
$root_path = $_SERVER['DOCUMENT_ROOT'];

// 文件管理器中链接的根URL。相对于$http_host。变体：''，'path/to/subfolder'
// 如果$root_path在服务器文档根目录之外，将不起作用
$root_url = '';
```

修改后的配置：

```php
// 文件管理器的根路径
// 使用目录的绝对路径，例如：'/var/www/folder' 或 $_SERVER['DOCUMENT_ROOT'].'/folder'
$root_path = $_SERVER['DOCUMENT_ROOT'].'/data';

// 文件管理器中链接的根URL。相对于$http_host。变体：''，'path/to/subfolder'
// 如果$root_path在服务器文档根目录之外，将不起作用
$root_url = 'data/';
```

然后，您可以更改其他配置以满足您的需求。要应用这些更改，您通常需要在Dockerfile中构建自定义镜像，或者挂载包含修改后配置文件的卷到容器内。如果您选择挂载卷，请确保将包含修改后配置文件的目录挂载到容器内的适当位置。

例如，如果您将配置文件存储在本地机器上的`/path/to/config`目录中，您可以像这样挂载该目录：

```shell
$ docker run -d -v /absolute/path:/var/www/html/data -v /path/to/config:/path/to/mounted/config -p 80:80 --restart=always --name tinyfilemanager tinyfilemanager/tinyfilemanager:master
```

然后，在容器内部，您可能需要调整TinyFileManager的入口点或命令来引用挂载的配置文件目录。这取决于TinyFileManager的具体实现和您如何配置Docker容器。

#### 如何在Docker中更改配置

如果您想在Docker中更改配置，您不能直接编辑Docker容器内的文件，因为它们是只读的。但您可以通过以下几种方法来实现：

1. **使用Docker卷（Volume）挂载配置文件**：
   您可以创建一个配置文件（例如`config.php`），然后将其挂载到容器内的适当位置。这可以通过在`docker run`命令中添加另一个`-v`选项来实现。

   ```bash
   $ docker run -d -v /absolute/path:/var/www/html/data -v /path/to/your/config.php:/path/in/container/to/config.php -p 80:80 --restart=always --name tinyfilemanager tinyfilemanager/tinyfilemanager:master
   ```

   然后，在您的`config.php`文件中，设置`$root_path`和`$root_url`变量。

2. **构建自定义Docker镜像**：
   如果您经常需要更改配置或添加其他文件，那么构建一个自定义的Docker镜像可能更有意义。这可以通过编写一个Dockerfile来实现，该Dockerfile基于`tinyfilemanager/tinyfilemanager`镜像，并添加或覆盖所需的文件。

   例如，在Dockerfile中：

   ```Dockerfile
   FROM tinyfilemanager/tinyfilemanager:master
   COPY config.php /path/in/container/to/config.php
   ```

   然后构建并运行这个新的镜像。

3. **直接在容器中修改（不推荐）**：
   虽然不推荐这样做，但您可以使用`docker exec`命令进入正在运行的容器，并直接编辑文件。但是，请注意，这样做会使您的更改在容器重启后丢失，除非您将这些更改提交到新的镜像中。

然后，如果您想更改其他配置或添加新的卷，您可以在`docker run`命令中添加一个新的卷映射，比如这样：

```bash
$ docker run -d -v /absolute/path:/var/www/html/data -v /absolute/path/index.php:/var/www/html/index.php -p 80:80 --restart=always --name tinyfilemanager tinyfilemanager/tinyfilemanager:master
```

这条命令将会把宿主机上的`/absolute/path/index.php`文件映射到Docker容器内的`/var/www/html/index.php`位置。

#### 停止运行

如果您想停止正在运行的Docker服务，或者您想重启服务，您应该首先停止它，否则您可能会遇到“`docker: Error response from daemon: Conflict. The container name "/tinyfilemanager" is already in use by container ...`”的问题。您可以执行以下命令来强制停止并删除名为`tinyfilemanager`的容器：

```shell
$ docker stop tinyfilemanager
$ docker rm tinyfilemanager
```

或者，如果您想强制删除正在运行的容器（不推荐在生产环境中使用，因为可能会丢失数据），可以使用`-f`（或`--force`）选项：

```shell
$ docker rm -f tinyfilemanager
```

### 许可证与致谢

- 本软件在[GNU许可证](https://github.com/prasathmani/tinyfilemanager/blob/master/LICENSE)下可用
- 原始概念和开发由[Alex Yashkin](https://github.com/alexantr/filemanager)完成
- 使用的CDN服务包括：_jQuery, Bootstrap, Font Awesome, Highlight.js, ace.js, DropZone.js, 和 DataTable.js_
- 如果您发现了bug或希望请求新功能，请提交一个[issue](https://github.com/prasathmani/tinyfilemanager/issues)
- [贡献者](https://github.com/prasathmani/tinyfilemanager/wiki/Authors-and-Contributors)
