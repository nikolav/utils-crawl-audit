# SEO analiza (kratko, ~1 A4) — centarinspera.rs

> Izvor: dostavljeni crawl izveštaj (status/robots/canonical/meta/heading/linking).

## ✅ Šta je dobro
- **Crawl & index signali su OK:** ključne stranice vraćaju **200**, bez redirekcija (redirect_chain_len = 0) i **robots_allowed = yes**.  
- **Nema `noindex`:** nema `X-Robots-Tag` ni `meta robots` zabrana (OK za javne stranice).  
- **Sitemap postoji:** pronađen je `/sitemap.xml`.

## 🚨 Glavni problemi (blokirajući)
### 1) H1 i heading struktura: **0 na svim stranicama**
U izveštaju je **h1_count = 0** i “No headings found”. To je veliki SEO minus: bez jasne hijerarhije Google slabije razume temu stranice.

**Šta uraditi**
- Dodaj **tačno 1× `<h1>` po stranici** (vidljiv korisnicima).
- Organizuj sadržaj kroz **H2/H3** (Usluge → vrste terapija → proces → cene → FAQ).

### 2) “Thin content” + “Low visible text for Googlebot” (indikator SPA/client-only renderinga)
Više URL-ova je označeno kao **Thin content (<80w)** i “Low visible text for Googlebot (possible client-only SPA)”. To tipično znači da crawler vidi minimalan HTML, a sadržaj dolazi tek kroz JS.

**Šta uraditi**
- Ako je SPA: uvedi **SSR ili prerender** za javne stranice (home/usluge/o-nama/kontakt/blog postovi).
- Proveri razliku: **View Source** (server HTML) vs **Inspect** (renderovan DOM).

### 3) Interno linkovanje je praktično “0”
Audit linkova prikazuje **0 outlink-ova**, **0 veza između stranica** i sve stranice kao **orphan**. To slabi crawl, UX i raspodelu autoriteta.

**Šta uraditi**
- Dodaj linkove koji postoje u HTML-u:
  - navigacija (header/footer) ka ključnim stranicama,
  - **breadcrumbs**,
  - “Povezane teme” na blog postovima,
  - kontekstualni linkovi ka uslugama/FAQ.

## ⚙️ Sekundarni (ali važni) problemi
### 4) Canonical doslednost (home konflikt)
Primećen je canonical koji nije “self” (razlika `/` vs bez `/`). To može praviti duplikate i razvodnjavati signale.

**Šta uraditi**
- Standardizuj jednu varijantu (npr. sa trailing slash) i:
  - svuda postavi canonical na nju,
  - 301 preusmeri drugu varijantu.

### 5) OG/Twitter meta tagovi nedostaju
Na više stranica nedostaju **og:title/og:description/og:image** i **twitter:card**.

**Šta uraditi**
- Minimalni set:
  - `og:title`, `og:description`, `og:image`, `og:url`, `og:type`
  - `twitter:card` (+ title/description/image)

### 6) Povremeni fetch timeout
Deo URL-ova je imao **Read timed out (15s)** (nestabilnost servera, zaštita, rate-limit ili slično).

**Šta uraditi**
- Proveri server/CDN/WAF logove i stabilnost response-a, posebno za bot user-agent.

## 🎯 Prioritet (redosled koji donosi najbrži rezultat)
1. **SSR/prerender za javne stranice** (da Google vidi sadržaj i linkove).  
2. Dodaj **H1 + H2/H3 hijerarhiju** i osnovnu semantiku.  
3. Uvedi **interno linkovanje + breadcrumbs** (u HTML-u).  
4. Sredi **canonical** dosledno + 301 za duplikate.  
5. Dodaj **OG/Twitter** meta tagove.

---

## ✅ Konačna ocena SEO validnosti
**Ocena: 4/10 (D)**

**Zašto?**  
Izveštaj snažno sugeriše **client-only SPA** (nizak vidljiv tekst za Googlebot), uz **0 H1** i praktično **0 internog linkovanja** iz perspektive crawler-a — to su blokatori koji mogu ozbiljno ograničiti indeksiranje i rangiranje, čak i kad su status kodovi i robots podešavanja “OK”.

**Kako do 8/10?**  
Reši render (SSR/prerender) + heading strukturu + interno linkovanje — to su najveći “SEO multiplikatori”.
