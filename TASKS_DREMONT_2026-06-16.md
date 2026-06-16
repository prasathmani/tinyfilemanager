# DREMONT tinyfilemanager – zadanie úloh po prvom predstavení

**Dátum predstavenia:** 16.06.2026  
**Projekt:** DREMONT – tinyfilemanager  
**Repozitár:** https://github.com/slapiar/tinyfilemanager  
**Aktuálna pracovná verzia:** 3.0.10  
**Kontext:** Prvé predstavenie riešenia vo firme DREMONT počas údržby počítačov účtovníčky. Riešenie bolo osobitne predstavené dvom prítomným manažérom.

---

## 1. Kritické závady funkcionality

### 1.1 DataTables chyba po prihlásení

Po prihlásení sa zobrazuje hláška:

> DataTables warning: table id=main-table - Incorrect column count.  
> For more information about this error, please see http://datatables.net/tn/18

Predpokladaná príčina: tabuľka priečinkov/súborov má nesprávny počet stĺpcov alebo sa do nej vkladá riadok, ktorý nezodpovedá očakávanej štruktúre DataTables.

**Požiadavka:**
- nájsť presnú príčinu chyby,
- opraviť HTML výstup tabuľky,
- preveriť riadky pre súbory, priečinky, prázdny adresár, chybové hlásenia a navigáciu,
- zabezpečiť, aby DataTables nedostávali riadky s odlišným počtom buniek.

**Priorita:** P0 – kritická

---

### 1.2 Prerobiť zobrazovanie priečinkov na stromovú štruktúru

Súčasné zobrazovanie priečinkov nie je dostatočne prehľadné. Je potrebné ho prerobiť na stromovú rozbaľovaciu štruktúru podobnú správcovi súborov vo Windows.

**Požiadavka:**
- vytvoriť ľavý alebo samostatný strom priečinkov,
- umožniť rozbaľovanie a zbaľovanie vetiev,
- kliknutím na priečinok načítať jeho obsah v hlavnej tabuľke,
- zachovať oprávnenia používateľa,
- nezobraziť používateľovi priečinky, ku ktorým nemá prístup.

**Priorita:** P1 – vysoká

---

### 1.3 Root priečinok po prihlásení

Po prihlásení sa má používateľovi zobraziť iba jeho koreňový priečinok. V aktuálnom prípade ide o priečinok `Mirko`, ktorý sa chápe ako root používateľa.

**Požiadavka:**
- po prihlásení otvoriť používateľský root automaticky,
- nezobrazovať technický názov `Mirko` ako bežný priečinok,
- v slovenčine použiť označenie `Adresár:`,
- v angličtine použiť označenie `Root`,
- technický názov priečinka ponechať iba interne.

**Priorita:** P1 – vysoká

---

### 1.4 Oprava textu „Spat o uroven vyssie“

V navigácii smerom nahor sa zobrazuje text bez diakritiky:

> Spat o uroven vyssie

**Požiadavka:**
- opraviť text na `Späť`,
- namiesto formulácie `o úroveň vyššie` používať text:
  - `Späť na [názov nadradeného priečinka]`,
- ošetriť korektný názov nadradeného priečinka podľa aktuálnej cesty,
- ak nadradený priečinok predstavuje root, zobraziť vhodný text podľa jazykovej mutácie.

**Priorita:** P2 – stredná

---

### 1.5 Vlastné pravé tlačidlo myši

Aktuálne sa používa štandardné kontextové menu prehliadača.

**Požiadavka:**
- zablokovať štandardné pravé tlačidlo myši v používateľskom rozhraní aplikácie,
- pripraviť miesto pre vlastné kontextové menu,
- vlastné menu bude neskôr obsahovať funkcie podľa typu objektu:
  - súbor,
  - priečinok,
  - prázdna plocha,
  - strom priečinkov,
  - tabuľka súborov.

**Poznámka:**
Zatiaľ stačí bezpečne zablokovať štandardné menu a pripraviť technický rámec. Funkcie vlastného menu budú riešené v ďalšej fáze.

**Priorita:** P2 – stredná

---

### 1.6 Upload do nového priečinka neukladá súbor

Ak oprávnený používateľ, napríklad admin alebo manažér, založí nový priečinok a chce do neho nahrať súbor, súbor sa neuloží. Vo formulári chýba tlačidlo `SAVE / ULOŽIŤ`, alebo je tam tlačidlo `Späť`, ktorému treba priradiť správnu ukladaciu funkciu.

**Požiadavka:**
- preveriť tok po vytvorení nového priečinka,
- preveriť upload formulár v novom priečinku,
- doplniť alebo opraviť tlačidlo `Uložiť`,
- ak existuje tlačidlo `Späť`, nesmie nahrádzať ukladaciu akciu,
- upload musí fungovať aj bez reloadu celej aplikácie, ak to aktuálna architektúra umožňuje.

**Priorita:** P0 – kritická

---

### 1.7 Predvolený jazyk používateľa

Všetkým používateľom sa má v profile implicitne nastavovať slovenčina.

**Požiadavka:**
- nastaviť predvolený jazyk nového používateľa na `sk`,
- preveriť existujúcich používateľov,
- ak nemajú jazyk definovaný, použiť slovenčinu ako fallback,
- administrátor môže neskôr jazyk zmeniť manuálne, ak bude táto voľba dostupná.

**Priorita:** P2 – stredná

---

### 1.8 Upload z URL nereaguje

V hornej časti stránky v tlačidle `Upload / Nahrať` existuje voľba nahrania z URL, ktorá nereaguje.

**Požiadavka:**
- preveriť, či je funkcia implementovaná alebo len zobrazená v UI,
- ak má byť funkčná, opraviť handler,
- ak zatiaľ nemá byť používaná, dočasne ju skryť,
- nedržať v používateľskom rozhraní nefunkčnú voľbu.

**Priorita:** P1 – vysoká

---

### 1.9 Dokončiť vyhľadávaciu lištu a rozšírené vyhľadávanie

Vyhľadávacia lišta už reaguje počas zadávania písmen, ale aktuálne je nastavená len na práve otvorený priečinok. V predchádzajúcej fáze sa začalo s tvorbou celkovej mapy súborov a funkcie vyhľadávania boli prepojené s databázou, aby sa proces vyhľadávania zrýchlil a neprechádzal celý disk pri každom dotaze. Toto prepojenie však ešte nefunguje správne.

Zároveň nefunguje formulár rozšíreného vyhľadávania.

**Požiadavka:**
- dokončiť celkovú mapu všetkých dostupných súborov podľa oprávnení používateľa,
- vyhľadávanie nesmie byť obmedzené len na práve otvorený priečinok,
- pri prvom zadanom písmene sa má inicializovať alebo obnoviť úplná mapa súborov dostupných aktuálnemu používateľovi, bez ohľadu na hodnotu prvého písmena,
- prvé a druhé písmeno ešte nemusia spúšťať finálne vyhľadávanie výsledkov,
- približne od piateho zadaného znaku má lišta vedieť vyrolovať zoznam súborov, v ktorých sa zadaná kombinácia vyskytuje,
- vyhľadávanie musí používať databázovo uloženú mapu/index súborov, nie opakované plné skenovanie adresárov pri každom stlačení klávesy,
- výsledky musia rešpektovať oprávnenia používateľa a jeho root,
- opraviť alebo dokončiť formulár rozšíreného vyhľadávania,
- rozšírené vyhľadávanie má používať rovnaký vyhľadávací backend ako rýchla lišta, aby nevznikli dve odlišné logiky.

**Poznámka k výkonu:**
Mapa súborov sa má vytvárať alebo obnovovať kontrolovane. Cieľom je rýchle vyhľadávanie pri písaní, ale bez toho, aby každé stlačenie klávesy spúšťalo plný rekurzívny scan disku.

**Priorita:** P1 – vysoká

---

## 2. Dizajn, zobrazenie a používateľské rozhranie

### 2.1 Optimalizácia slovenských prekladov

V aplikácii sa stále nachádzajú neúplné alebo neaktuálne slovenské preklady.

**Požiadavka:**
- prejsť všetky texty používateľského rozhrania,
- opraviť chýbajúcu diakritiku,
- zjednotiť terminológiu,
- skontrolovať najmä:
  - tlačidlá,
  - systémové hlášky,
  - navigáciu,
  - upload formuláre,
  - správu používateľov,
  - chat,
  - hlavičku a footer.

**Priorita:** P2 – stredná

---

### 2.2 Zobrazenie čísla verzie vo footeri

V používateľskom rozhraní chýba zobrazenie aktuálnej verzie aplikácie.

**Požiadavka:**
- zobrazovať číslo verzie vo footeri každej stránky používateľského rozhrania,
- číslo verzie čítať zo súboru `RELEASE_VERSION`,
- formát napríklad:
  - `tinyfilemanager DREMONT v3.0.10`,
- zabezpečiť, aby sa verzia zobrazovala aj po nasadení nového release balíka.

**Priorita:** P1 – vysoká

---

### 2.3 Správa „Neprecitane: 1“

Vpravo dole sa po prihlásení ako admin alebo manažér zobrazuje správa:

> Neprecitane: 1

Správa nezmizne ani po resete cache.

**Požiadavka:**
- zistiť pôvod hlášky,
- opraviť diakritiku na `Neprečítané`,
- zistiť, či ide o chat, notifikáciu alebo testovací stav,
- ak správa nemá reálny význam, odstrániť ju,
- ak má význam, doplniť spôsob označenia ako prečítané.

**Priorita:** P2 – stredná

---

### 2.4 Tmavý režim chatu

V tmavom zobrazení komunikačného chatu je potrebné upraviť kontrast textu v okienkach došlých správ.

**Požiadavka:**
- stmaviť alebo inak upraviť písmo v okienkach došlých správ,
- zabezpečiť dobrú čitateľnosť v tmavom režime,
- preveriť aj odoslané správy, systémové správy a časové značky.

**Priorita:** P2 – stredná

---

### 2.5 Header tlačidlá – iba ikony

Tlačidlá v hlavičke stránky, napríklad `Nahrať` a `Nový súbor`, majú byť zobrazené iba ako ikony bez textového nadpisu.

**Požiadavka:**
- ponechať iba ikonu tlačidla,
- zväčšiť ikony približne na 150 % súčasnej veľkosti,
- text ponechať iba ako tooltip / alternatívny popis pri prejdení myšou,
- zabezpečiť zrozumiteľnosť aj pre používateľov bez technických znalostí.

**Priorita:** P2 – stredná

---

### 2.6 Mobilné zobrazenie loga

Pri mobilnom zobrazení je logo v hlavičke príliš veľké.

**Požiadavka:**
- zmenšiť logo v mobilnom zobrazení na približne 65 % súčasnej veľkosti,
- ponechať desktopové zobrazenie bez zbytočného zásahu,
- preveriť zobrazenie na bežných šírkach:
  - 360 px,
  - 390 px,
  - 414 px,
  - 768 px.

**Priorita:** P2 – stredná

---

## 3. Odporúčané poradie práce

### Fáza A – stabilizácia funkčnosti

1. Opraviť DataTables chybu `Incorrect column count`.
2. Opraviť upload do nového priečinka.
3. Preveriť a opraviť upload z URL alebo ho dočasne skryť.
4. Nastaviť predvolený jazyk používateľov na slovenčinu.

### Fáza B – vyhľadávanie a mapa súborov

1. Preveriť aktuálny stav rýchlej vyhľadávacej lišty.
2. Preveriť databázovú mapu/index súborov.
3. Dokončiť inicializáciu alebo obnovu úplnej mapy súborov pri prvom použití vyhľadávania.
4. Nastaviť vyhľadávanie tak, aby približne od piateho znaku vracalo relevantné výsledky naprieč dostupnými súbormi.
5. Opraviť formulár rozšíreného vyhľadávania.
6. Zjednotiť rýchle a rozšírené vyhľadávanie nad jedným backendom.

### Fáza C – navigácia a strom priečinkov

1. Definovať root priečinok používateľa.
2. Upraviť zobrazovanie rootu ako `Adresár:` / `Root`.
3. Opraviť text `Späť na [názov nadradeného priečinka]`.
4. Navrhnúť a implementovať stromovú štruktúru priečinkov.
5. Zabezpečiť, aby strom rešpektoval oprávnenia používateľa.

### Fáza D – UI a jazyk

1. Zobraziť verziu vo footeri.
2. Opraviť slovenské preklady.
3. Opraviť hlášku `Neprečítané: 1`.
4. Upraviť tmavý režim chatu.
5. Upraviť header tlačidlá na ikonové.
6. Upraviť veľkosť loga v mobilnom zobrazení.

### Fáza E – budúce rozšírenia

1. Pripraviť vlastné kontextové menu pre pravé tlačidlo myši.
2. Navrhnúť funkcie podľa kliknutého objektu.
3. Dopĺňať pokročilé používateľské akcie postupne, bez veľkého refactoru.

---

## 4. Technická zásada

Nezasahovať naraz do celej aplikácie.

Každá oprava má byť malá, čitateľná a samostatne testovateľná. Po každej dokončenej úlohe spraviť commit s jasným popisom.

Odporúčaná forma commitov:

- `fix(ui): resolve datatables column count warning`
- `fix(upload): restore save action after creating folder`
- `fix(i18n): set Slovak as default user language`
- `feat(search): complete database-backed file map search`
- `fix(search): repair advanced search form`
- `feat(ui): show release version in footer`
- `feat(nav): add folder tree navigation`
- `fix(chat): improve dark mode message contrast`
- `fix(header): use icon-only action buttons`
- `fix(mobile): reduce header logo size`

---

## 5. Poznámka k manažérom

Manažéri môžu používať pracovné a súborové funkcie podľa pridelených oprávnení, ale nemajú mať prístup do správy používateľov. Správa používateľov ostáva výhradne administrátorská funkcia, zatiaľ!
