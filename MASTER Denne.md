Perfektné. Tu je jednoduchý, bezpečný mini-postup len pre master, aby ste mali pokoj:

Denný workflow (vždy rovnaký)
1. Prejdi do repozitára:
   cd /workspaces/tinyfilemanager
2. Over vetvu a stav:
   git status --short --branch
3. Stiahni najnovší master:
   git pull origin master
4. Urob zmeny, otestuj.
5. Commit:
   git add -A
   git commit -m "stručný popis zmeny"
6. Push:
   git push origin master

Rýchla kontrola pred a po pushi
1. Pred push:
   git status --short --branch
2. Po push:
   git status --short --branch
   Očakávaný pokojný stav: master...origin/master (bez ahead/behind)

Ako čítať stav bez stresu
1. master...origin/master = ste synchronizovaný.
2. master...origin/master [ahead 1] = máte 1 lokálny commit, ešte nepushnutý.
3. master...origin/master [behind 1] = na remote je novší commit, treba pull.

Núdzové pravidlo pri neistote
1. Zastaviť.
2. Spustiť:
   git status --short --branch
   git log --oneline --decorate -n 5
3. Podľa toho sa rozhodnúť (pull alebo push), nič nerobiť naslepo.

Ak chcete, v ďalšom kroku vám pripravím aj ultra-krátku verziu “3 príkazy pred prácou + 2 príkazy po práci” presne na tento repo.