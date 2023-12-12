#!/bin/sh

if [ "$(id -u)" -eq 0 ]; then
  update=0
  for f in /certs/*.pem /certs/*.crt; do
    if [ -f "$f" ]; then
      bn=$(basename "$f")
      update=1
      echo "import cert file ${bn}"
      cp "$f" "/usr/local/share/ca-certificates/${bn}.crt"
    fi
  done
  if [ "${update}" = "1" ]; then
    update-ca-certificates
  fi
else
  echo "User cannot import certs."
fi

exec php -S '[::]:8080' -t /var/www/html
