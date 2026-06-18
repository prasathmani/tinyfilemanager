# DREMONT tinyfilemanager – zadanie úloh po prvom predstavení

**Dátum predstavenia:** 16.06.2026  
**Projekt:** DREMONT – tinyfilemanager  
**Repozitár:** https://github.com/slapiar/tinyfilemanager  
**Aktuálna pracovná verzia:** 3.0.22  
**Kontext:** Prvé predstavenie riešenia vo firme DREMONT počas údržby počítačov účtovníčky. Riešenie bolo osobitne predstavené dvom prítomným manažérom.

---

## 1. Kritické závady funkcionality

### 1.1 DataTables chyba po prihlásení

Po prihlásení sa zobrazovala hláška:

> DataTables warning: table id=main-table - Incorrect column count.  
> For more information about this error, please see http://datatables.net/tn/18

**Stav po teste:** Opravené. Po prihlásení sa už DataTables hláška nezobrazuje.

**Priorita:** P0 – splnené

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

Po prihlásení sa má používateľovi zobraziť jeho koreňový priečinok už otvorený. V aktuálnom prípade ide o priečinok `Mirko`, ktorý sa chápe ako root používateľa.

**Požiadavka:**
- po prihlásení automaticky otvoriť používateľský root `Mirko`,
- nezobrazovať technický názov `Mirko` ako bežný priečinok nad aktuálnym obsahom,
- v slovenčine použiť označenie `Adresár:`,
- v angličtine použiť označenie `Root`,
- technický názov priečinka ponechať iba interne.

**Aktuálny stav:** --- HOTOVO, nasadená a ručne overená verzia 3.0.18. Používateľský root sa po prihlásení otvára priamo a technický názov rootu sa v navigácii nahrádza virtuálnym označením `Adresár:` / `Root`.

**Priorita:** P1 – vysoká

---

### 1.4 Oprava textu „Spat o uroven vyssie“

V navigácii smerom nahor sa zobrazuje text bez diakritiky:

> Spat o uroven vyssie

**Požiadavka:**
- odstrániť text `Spat o uroven vyssie`,
- zobrazovať text `Späť` doplnený breadcrumb cestou nadradených priečinkov,
- breadcrumb za slovom `Späť` musí predstavovať cestu nad aktuálne otvoreným priečinkom,
- technický názov používateľského rootu, napríklad `Mirko`, sa v tejto ceste nesmie zobrazovať,
- ak je nadradeným priečinkom používateľský root, zobraziť namiesto jeho technického názvu text `Domov`,
- príklad pre priečinok `Mirko/Projekt/Dokumenty`: `Späť Domov / Projekt`,
- príklad pre priečinok `Mirko/Projekt`: `Späť Domov`,
- v samotnom používateľskom roote sa odkaz smerom vyššie nesmie zobraziť ani nesmie umožniť vstup nad povolený root,
- jednotlivé priečinky v zobrazenej nadradenej ceste majú byť klikateľné a musia rešpektovať oprávnenia používateľa,
- texty `Späť` a `Domov` riešiť cez existujúci prekladový systém, nie natvrdo iba pre slovenčinu.

**Aktuálny stav:** --- HOTOVO, nasadená a ručne overená verzia 3.0.22. Spoločný používateľský koreň sa vo všetkých navigačných miestach zobrazuje ako `Domov`, technický názov rootu sa bežnému používateľovi nezobrazuje, na úrovni Domov sa nezobrazuje `Späť` ani `..` a v podriadených priečinkoch smeruje `Späť` vždy na bezprostredného rodiča. Adminovi zostáva zachovaný jeho širší nakonfigurovaný root.

**Priorita:** P2 – splnené

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

Ak oprávnený používateľ, napríklad admin alebo manažér, založí nový priečinok a chce do neho nahrať súbor, súbor sa neuloží.

**Stav po teste:** Opravené a ručne overené. Normálny upload reálne ukladá súbor do aktuálne otvoreného nového priečinka.

**Požiadavka:**
- preveriť request po odoslaní upload formulára,
- overiť cieľovú cestu nového priečinka,
- overiť CSRF token, názov input poľa a submit handler,
- overiť, či request doputuje do správneho upload handlera,
- doplniť používateľovi jasnú úspešnú alebo chybovú hlášku,
- upload musí reálne uložiť súbor do aktuálne otvoreného nového priečinka.

**Priorita:** P0 – splnené

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

Voľba `Upload from URL` sa už dá otvoriť a zobrazí sa input pre URL aj tlačidlo `Nahrať`, ale súbor sa neuloží.

**Stav po teste:** Opravené a ručne overené vo verzii 3.0.17. URL upload úspešne uložil súbor `bazos.svg`.

**Požiadavka:**
- preveriť request z URL upload formulára,
- overiť, či sa odosiela správna URL, token a cieľová cesta,
- overiť backend handler pre stiahnutie a uloženie súboru,
- doplniť kontrolu HTTP odpovede, timeoutu a názvu súboru,
- doplniť úspešnú alebo chybovú hlášku,
- ak backend nie je bezpečne použiteľný, voľbu dočasne skryť; nefunkčná funkcia nesmie zostať aktívna.

**Priorita:** P1 – splnené

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

### 2.3 Evidencia neprečítanej komunikácie

Vpravo dole sa po prihlásení ako admin alebo manažér zobrazuje odznak:

> Neprecitane: 1

Odznak nezmizne ani po resete cache a používateľ z neho momentálne nevie otvoriť konkrétne neprečítané správy.

**Požiadavka:**
- opraviť diakritiku na `Neprečítané`,
- zistiť pôvod a dátový zdroj počtu neprečítaných správ,
- urobiť celý odznak klikateľný,
- kliknutím priamo na odznak otvoriť zoznam alebo panel neprečítaných správ,
- umožniť používateľovi otvoriť konkrétnu správu alebo komunikáciu,
- po otvorení alebo označení správy ako prečítanej aktualizovať počet bez nutnosti resetu cache,
- ak neexistujú neprečítané správy, odznak skryť alebo zobraziť nulový stav podľa návrhu UI,
- počet musí zodpovedať skutočnému stavu, nie testovacej alebo statickej hodnote.

**Priorita:** P1 – vysoká

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

### 2.7 Tlačidlo „Zatvoriť“ v Správcovi používateľov

V integrovanej administrátorskej stránke Správcu používateľov chýba zreteľná možnosť návratu späť do Správcu súborov.

**Požiadavka:**
- doplniť viditeľné tlačidlo `Zatvoriť` v slovenskej mutácii,
- v anglickej mutácii použiť `Cancel`,
- tlačidlo nesmie ukladať ani meniť žiadne údaje,
- po kliknutí sa má používateľ vrátiť do Správcu súborov na aktuálnu alebo poslednú platnú cestu,
- zachovať admin-only prístup do Správy používateľov,
- preveriť aj formuláre Nový/Upraviť používateľa, aby mali jasnú možnosť zrušenia bez uloženia,
- nepoužívať návrat cez globálny root, ak má administrátor otvorenú konkrétnu pracovnú cestu.

**Priorita:** P2 – stredná

---

## 3. Odporúčané poradie práce

### Fáza A – stabilizácia funkčnosti

1. DataTables chyba `Incorrect column count` – **opravené a ručne overené**. --- HOTOVO
2. Upload do nového priečinka – **opravené a ručne overené**. --- HOTOVO
3. Upload z URL – **opravené a ručne overené**. --- HOTOVO, nasadená pracovná verzia 3.0.17
4. Root po prihlásení – automaticky otvoriť priečinok `Mirko`. --- HOTOVO, nasadená a ručne overená verzia 3.0.18
5. Nastaviť predvolený jazyk používateľov na slovenčinu. --- HOTOVO, nasadená a ručne overená verzia 3.0.19

### Fáza B – vyhľadávanie a mapa súborov

1. Preveriť aktuálny stav rýchlej vyhľadávacej lišty.--- HOTOVO
2. Preveriť databázovú mapu/index súborov.--- HOTOVO
3. Dokončiť inicializáciu alebo obnovu úplnej mapy súborov pri prvom použití vyhľadávania. --- HOTOVO
4. Nastaviť vyhľadávanie tak, aby približne od piateho znaku vracalo relevantné výsledky naprieč dostupnými súbormi. --- HOTOVO
5. Opraviť formulár rozšíreného vyhľadávania.--- HOTOVO 
6. Zjednotiť rýchle a rozšírené vyhľadávanie nad jedným backendom.--- HOTOVO --- release verzia 3.0.21

### Fáza C – navigácia a strom priečinkov

Domov je spoločný nakonfigurovaný koreň inštancie pre bežných používateľov. Používateľské allowed_dirs určujú iba viditeľné a prístupné vetvy v rámci Domov; pridelený priečinok používateľa sa nestáva jeho Domov. Admin môže mať samostatne nakonfigurovaný širší root.

1. Definovať root priečinok používateľa.--- HOTOVO, nasadená a ručne overená verzia 3.0.18,
2. Upraviť zobrazovanie rootu ako `Adresár:` / `Root`.--- HOTOVO, nasadená a ručne overená verzia 3.0.18,
3. Zobraziť `Späť` + breadcrumb nadradenej cesty; používateľský root označiť ako `Domov`. --- HOTOVO, nasadená a ručne overená verzia 3.0.22
4. Navrhnúť a implementovať stromovú štruktúru priečinkov.
5. Zabezpečiť, aby strom rešpektoval oprávnenia používateľa.

### Fáza D – komunikácia, UI a jazyk

1. Zobraziť verziu vo footeri.
2. Opraviť slovenské preklady.
3. Opraviť evidenciu neprečítaných správ a klikateľný odznak.
4. Upraviť tmavý režim chatu.
5. Upraviť header tlačidlá na ikonové.
6. Upraviť veľkosť loga v mobilnom zobrazení.
7. Doplniť tlačidlo `Zatvoriť` / `Cancel` v Správcovi používateľov.

### Fáza E – budúce rozšírenia

1. Pripraviť vlastné kontextové menu pre pravé tlačidlo myši.
2. Navrhnúť funkcie podľa kliknutého objektu.
3. Dopĺňať pokročilé používateľské akcie postupne, bez veľkého refactoru.

---

## 4. Technická zásada

Nezasahovať naraz do celej aplikácie.

Každá oprava má byť malá, čitateľná a samostatne testovateľná. Po každej implementovanej a otestovanej úlohe pripraviť samostatný commit s jasným popisom. Push, release, nasadenie a označenie HOTOVO sa vykonávajú až po výstupnej kontrole a ručnom overení.

Odporúčaná forma commitov:

- `fix(ui): resolve datatables column count warning`
- `fix(upload): persist uploaded files in new folders`
- `fix(upload): persist files uploaded from URL`
- `fix(i18n): set Slovak as default user language`
- `feat(search): complete database-backed file map search`
- `fix(search): repair advanced search form`
- `feat(ui): show release version in footer`
- `fix(nav): show parent breadcrumb in back link`
- `feat(nav): add folder tree navigation`
- `fix(chat): open unread messages from notification badge`
- `fix(chat): improve dark mode message contrast`
- `fix(header): use icon-only action buttons`
- `fix(mobile): reduce header logo size`
- `fix(admin): add close action to user manager`

---

## 5. Rozdelenie zodpovednosti a výstupná kontrola

Pri ďalšom vývoji projektu DREMONT sa oddeľuje implementácia od výstupnej kontroly.

### Copilot

Copilot vykonáva iba:

- analýzu existujúceho kódu,
- implementáciu malej a samostatne testovateľnej úlohy,
- syntax kontroly,
- automatizované alebo lokálne integračné testy,
- vytvorenie lokálneho commitu iba vtedy, keď je to výslovne uvedené v konkrétnom zadaní,
- záverečný technický report.

Copilot nesmie svojvoľne:

- robiť push,
- vytvárať release,
- nasadzovať verziu,
- označovať úlohu ako `--- HOTOVO`,
- meniť poradie roadmapy,
- preskakovať na inú úlohu bez výslovného zadania.

### Joyee – výstupná kontrola

Joyee vykonáva alebo riadi:

- kontrolu technického reportu Copilota,
- kontrolu diffu a commitov dostupných na GitHube,
- posúdenie, či patch zodpovedá zadaniu,
- rozhodnutie, či je patch schválený na push, release a nasadenie,
- prípravu presných technických krokov pre commit, push a release,
- aktualizáciu TASK dokumentu po úspešnom nasadení a ručnom overení.

Označenie:

`--- HOTOVO, nasadená a ručne overená verzia X.Y.Z`

sa zapisuje až po splnení všetkých podmienok:

1. implementácia je dokončená,
2. patch je skontrolovaný,
3. commit je dostupný na GitHube,
4. release je vytvorený,
5. verzia je nasadená,
6. používateľ ju ručne overil na reálnom hostingu.

Copilot sám nesmie rozhodnúť, že úloha je HOTOVO.

### Používateľ

Používateľ:

- ručne overuje nasadenú verziu na reálnom hostingu,
- potvrdzuje funkčnosť z pohľadu používateľa,
- rozhoduje o obchodných, prevádzkových a projektových prioritách,
- môže schváliť alebo odmietnuť ďalší krok.

### Princíp štyroch stavov

Každá úloha môže mať postupne tieto stavy:

1. `ROZPRACOVANÉ`
2. `IMPLEMENTOVANÉ A OTESTOVANÉ`
3. `SCHVÁLENÉ NA RELEASE`
4. `--- HOTOVO, nasadená a ručne overená verzia X.Y.Z`

Tieto stavy sa nesmú zamieňať.

Úspešný lokálny test alebo lokálny commit ešte neznamená, že je úloha HOTOVO.

Aktualizácia stavu v `TASKS_DREMONT_2026-06-16.md` musí byť pravdivá a musí používať presné číslo reálne nasadenej verzie. Verzia sa nesmie odhadovať.

---

## 6. Poznámka k manažérom

Manažéri môžu používať pracovné a súborové funkcie podľa pridelených oprávnení, ale nemajú mať prístup do správy používateľov. Správa používateľov ostáva výhradne administrátorská funkcia, zatiaľ!
