# Tiny File Manager

This repository is built on top of [prasathmani/tinyfilemanager](https://github.com/prasathmani/tinyfilemanager). The manager can be ran using PHP, Docker, or Kubernetes.

## Adding Users

> [!CAUTION]
> Do not use the example passwords in production environments, use the [Password Generator](pwd.html) to create unique passwords.
> Default username/password: **admin/admin@123** and **user/12345**.

1. If running locally users can be added by setting the `USERS` JSON object array environment variable in `sample.env`, rename this to `.env`. 

    ```bash
    #inside .env
    USERS='{"admin": "ADMIN_PASSWORD_HASH","user": "USER_PASSWORD_HAS"}'
    ```

2. Set the environment variable `USERS` using a JSON object array `'{"USER_NAME": "PASSWORD_HASH"}'`.

    a. Docker Compose - set in the `docker-compose.yml`
    b. Docker - set on the system or pass in the value
    c. Kubernetes - in the deployment YAML set using a secret with `envFrom` or as an environment variable

To enable/disable authentication set `$use_auth` to true or false.

## How to run

Run it locally within the directory with PHP.

    ```bash
    # use the development server
    php -S localhost:8080
    ```

For Docker, set the `USERS` environment variable in the system or pass in the value.

    ```bash
    docker run --name tfm -p 8080:80 britslampe/tfm:2.0

    # OR
    
    docker run --name tfm --env USERS='{"admin": "ADMIN_PASSWORD_HASH"}' -p 8080:80 britslampe/tfm:2.0
    
    ```
