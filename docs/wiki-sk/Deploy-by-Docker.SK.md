# Nasadenie cez Docker

Uisti sa, že máš nainštalovaný Docker:
https://docs.docker.com/engine/install/

> Poznámka: Potrebuješ absolútnu cestu k adresáru, ktorý bude TinyFileManager obsluhovať.
> Ak bežíš na špeciálnej platforme (napr. Raspberry Pi), môže byť vhodné stiahnuť projekt a buildnúť image lokálne.

## Spustenie kontajnera

```sh
docker run -d \
  -v /absolute/path:/var/www/html/data \
  -p 80:80 \
  --restart=always \
  --name tinyfilemanager \
  tinyfilemanager/tinyfilemanager:master
```

Potom otvor `http://127.0.0.1/` a prihlás sa.

DockerHub: https://hub.docker.com/r/tinyfilemanager/tinyfilemanager

## Ako zmeniť konfiguráciu v dockeri

Pôvodne:

```php
$root_path = $_SERVER['DOCUMENT_ROOT'];
$root_url = '';
```

Upravené:

```php
$root_path = $_SERVER['DOCUMENT_ROOT'].'/data';
$root_url = 'data/';
```

Ak upravuješ `index.php`, pridaj ďalší volume mapping:

```sh
docker run -d \
  -v /absolute/path:/var/www/html/data \
  -v /absolute/path/index.php:/var/www/html/index.php \
  -p 80:80 \
  --restart=always \
  --name tinyfilemanager \
  tinyfilemanager/tinyfilemanager:master
```

## Zastavenie bežiaceho kontajnera

```sh
docker rm -f tinyfilemanager
```

## Poznámka pre tento fork

Tento repozitár už obsahuje novšiu Docker konfiguráciu a odporúčaný port `8080`.
Pre aktuálny postup uprednostni `DEPLOYMENT.md` a `docker-compose.yml` v tomto projekte.
