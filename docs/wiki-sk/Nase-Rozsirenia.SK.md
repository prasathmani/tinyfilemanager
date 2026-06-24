# Naše rozšírenia TinyFileManager

Táto kapitola je vyhradená pre funkcionalitu, ktorá bola doplnená nad rámec pôvodného projektu.
Preklady pôvodnej wiki zostávajú bez zásahu, rozšírenia sú dokumentované samostatne.

## Ako čítať túto kapitolu

- Každá sekcia obsahuje stručný účel, stav a odkazy na súvisiace časti projektu.
- Ak je sekcia v stave návrhu, je označená ako plán alebo TODO.

## 1. Chat medzi online používateľmi

Stav: implementované

Rozsah:

- komunikácia medzi používateľmi cez popup chat
- história správ a inbox notifikácie
- zvýraznenie neprečítaných správ
- perzistencia správ v SQLite databáze

Súvisiace miesta v projekte:

- backend logika v hlavnom runtime
- UI prvky online používateľov a chat modal

## 2. Rozšírené Help a lokálna dokumentácia

Stav: implementované

Rozsah:

- lokálne Help dokumenty cez `help_doc`
- markdown renderovanie dokumentácie v aplikácii
- slovenská wiki navigácia v hlavičke + predošlá/nasledujúca kapitola v pätičke
- zachovanie kontextu priečinka pri prehliadaní dokumentácie

## 3. Release automatizácia

Stav: implementované

Rozsah:

- rozšírené prepínače release skriptu (`patch`, `mini`, ...)
- automatický commit release výstupu
- automatický push po release

## 4. API a integračné rozšírenia

Stav: implementované / priebežne rozširované

Rozsah:

- API endpointy a integračné body pre externé služby
- bridge vrstva pre interné workflow

TODO:

- doplniť prehľad endpointov a minimálne príklady request/response

## 5. Hardening a produkčné nasadenie

Stav: implementované / priebežne rozširované

Rozsah:

- bezpečnostné úpravy a pravidlá nasadenia
- smernice pre stabilnú prevádzku

TODO:

- doplniť checklist „pred produkčným nasadením“

## 6. Refaktor a testovanie

Stav: implementované / priebežne rozširované

Rozsah:

- extrakcia helperov a služieb do `src/`
- unit/integration testy pre kritické toky

TODO:

- doplniť mapu „modul -> testy -> coverage cieľ"

## Poznámka k ďalšiemu dopĺňaniu

Pri dopĺňaní nových sekcií odporúčame držať jednotný formát:

- Účel
- Stav
- Rozsah
- Súvisiace súbory
- TODO / ďalší krok
