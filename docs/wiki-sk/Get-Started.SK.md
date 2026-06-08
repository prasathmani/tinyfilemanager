# Nastavenie TinyFileManager (Get Started)

Táto dokumentácia pomáha s inštaláciou krok po kroku.
Odporúča sa prejsť ju pozorne, aby bolo jasné, ako je aplikácia navrhnutá a ako ju korektne konfigurovať.
Na pokročilé úpravy je potrebná základná znalosť PHP.

## Požiadavky

TinyFileManager je jednoduchý a rýchly správca súborov v jednom PHP súbore.
Funguje online aj lokálne na platformách Linux, Windows a Mac.
Minimálna požiadavka je PHP 5.5+.

- PHP 5.5.0 alebo vyššie
- Rozšírenia Zip a Tar pre zip/unzip akcie
- Rozšírenia Fileinfo, iconv a mbstring sú silno odporúčané

> Pri úpravách správcu súborov buď opatrný. Nesprávna úprava môže aplikáciu úplne rozbiť.
> Pri prispôsobovaní bez podpory odporúčame najprv skontrolovať Issues alebo vytvoriť novú požiadavku:
> https://github.com/prasathmani/tinyfilemanager/issues

## Ako začať najrýchlejšie

- Stiahni ZIP s aktuálnou verziou z hlavnej vetvy.
- Skopíruj `tinyfilemanager.php` na webhosting.
- Voliteľne premenuj súbor `tinyfilemanager.php` na iný názov.

## Poznámka pre tento fork

Tento fork obsahuje ďalšie rozšírené funkcie (roly, API, bridge, spevnenie nasadenia).
Pre produkčné nasadenie odporúčame postupovať podľa `DEPLOYMENT.md`.
