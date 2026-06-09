# App vlastnictvo suborov a chat inbox poznamky

Datum: 2026-06-09

## 1) Co znamena vlastnik suboru v aplikacii

Aplikacia teraz rozlisuje 2 vrstvy vlastnictva:

- Systemovy owner: OS/POSIX owner (`fileowner`, `posix_getpwuid`), napr. `www-data`, `root`, alebo hostingovy identifikator.
- App owner metadata: interny uzivatel TinyFileManager (`auth_users`), ktory subor vytvoril alebo naposledy upravil.

## 2) Ako sa metadata ukladaju

- Ukladanie: `.fm_usercfg/owner-meta.json`
- Scope: metadata su oddelene podla `FM_ROOT_PATH` (hash scope key), aby sa nemiesali medzi roznymi root priecinkami.
- Zaznam na subor/priecinok obsahuje:
  - `created_by`, `created_at`
  - `updated_by`, `updated_at`
  - `last_action`

## 3) Kedy sa metadata aktualizuju

- upload suboru (standard/chunk/url)
- vytvorenie suboru/priecinka
- editacia obsahu suboru
- copy/move/rename
- delete (mazanie metadat)

## 4) Zobrazenie v stlpci Vlastnik

- Preferovane je app owner (`created_by`) ak existuje metadata.
- Tooltip badge obsahuje doplnkove info:
  - `App owner: <user>`
  - `Last update: <user>` ked sa lisi od ownera
- Ak app metadata neexistuju, zobrazi sa fallback na systemoveho ownera.

## 5) Chat a offline spravy

- Spravy sa ukladaju do SQLite (`.fm_usercfg/chat.sqlite`) a preziju odhlasenie.
- Pridany je inbox unread badge (`Neprecitane`) s pocitadlom odosielatelov s neprecitanymi spravami.
- Read-state sa drzi per user v `localStorage` (`tfm-chat-read:<user>`).
- Po otvoreni konverzacie sa sender oznaci ako precitany.

## 6) Obmedzenia

- Chat endpoint akceptuje iba internych `auth_users`.
- Systemovy owner, ktory nie je interny app user, nemoze byt chat peer.
- V takom pripade je owner badge vizualne rovnaky, ale bez aktivneho chat prepojenia.
