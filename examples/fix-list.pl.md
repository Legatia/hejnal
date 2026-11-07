<!-- Example output of `hejnal run` against test services that mimic a FortiGate VPN, WordPress on PHP and Jenkins, matched against the real CISA KEV catalog 2026.11.03 and NVD records, before ENISA's list was added, so it shows no EUVD IDs. Host names were changed to example.com. -->

# Lista poprawek Hejnal: Example Sp. z o.o.

Wygenerowano 2026-11-04 12:42 UTC · Hosty: 3 · Usługi: 3 · Rozpoznane produkty: 4

Źródła: katalog CISA Known Exploited Vulnerabilities 2026.11.03.

**Napraw teraz: 3 · W tym tygodniu: 0 · W tym miesiącu: 1 · Później: 1**

## Napraw teraz (krytyczne)

### 1. WordPress na www.example.com:443 · `f058ba93`

- **Dlaczego:** Znane, aktywnie wykorzystywane podatności w tym produkcie: 3. Najnowszą wpisano na listę wykorzystywanych podatności 2026-11-03.
- **Co zrobić:** Ustal zainstalowaną wersję, porównaj ją z biuletynami producenta poniżej i zaktualizuj do wersji z poprawką. Jeśli poprawki nie ma, zastosuj obejście zalecane przez producenta albo odłącz usługę od internetu.
- **Sprawdź, czy nie doszło do włamania:** Dla co najmniej jednej z tych podatności CISA zaleca analizę powłamaniową. Sama aktualizacja nie wystarczy, jeśli system był wystawiony przed poprawką: poszukaj śladów włamania, takich jak nieznane konta, pliki lub połączenia.
- **Wykryto pod adresem:** `https://www.example.com/` (`generator WordPress 6.8.1`) · wersja `6.8.1`
- **Podatności:**
  - **CVE-2026-119977**: WordPress WordPress Core Time-of-check Time-of-use (TOCTOU) Race Condition Vulnerability · dodana 2026-11-03 · analiza powłamaniowa · wersja podatna
  - **CVE-2026-87902**: WordPress Core Remote File Inclusion Vulnerability · dodana 2026-09-25 · analiza powłamaniowa · wersja podatna
  - **CVE-2026-60137**: WordPress Core SQL Injection Vulnerability · dodana 2026-07-21 · wersja podatna
- **Wykluczone na podstawie wersji:** CVE-2026-63030
- **Biuletyny:** <https://wordpress.org/news/2026/10/wordpress-7-1-4> · <https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-core/wordpress-core-470-713-unauthenticated-upgrade-window-staged-installer-remote-code-execution> · <https://nvd.nist.gov/vuln/detail/CVE-2026-119977> · <https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-7hp8-65ch-5whp>

> Hejnal porównał wersję `6.8.1` z wersjami podatnymi według NVD: ta wersja jest podatna.

### 2. PHP na www.example.com:443 · `cbf55259`

- **Dlaczego:** Znane, aktywnie wykorzystywane podatności w tym produkcie: 2. Najnowszą wpisano na listę wykorzystywanych podatności 2026-10-26.
- **Co zrobić:** Ustal zainstalowaną wersję, porównaj ją z biuletynami producenta poniżej i zaktualizuj do wersji z poprawką. Jeśli poprawki nie ma, zastosuj obejście zalecane przez producenta albo odłącz usługę od internetu.
- **Sprawdź, czy nie doszło do włamania:** Dla co najmniej jednej z tych podatności CISA zaleca analizę powłamaniową. Sama aktualizacja nie wystarczy, jeśli system był wystawiony przed poprawką: poszukaj śladów włamania, takich jak nieznane konta, pliki lub połączenia.
- **Wykryto pod adresem:** `https://www.example.com/` (`header X-Powered-By: PHP/8.3.12`) · wersja `8.3.12`
- **Podatności:**
  - **CVE-2026-109618**: PHP Memory Corruption Vulnerability · dodana 2026-10-26 · analiza powłamaniowa · wersja podatna
  - **CVE-2026-109619**: PHP Stale Internal Request-State Vulnerability · dodana 2026-10-26 · analiza powłamaniowa · wersja podatna
- **Wykluczone na podstawie wersji:** CVE-2024-4577, CVE-2012-1823, CVE-2019-11043
- **Biuletyny:** <https://www.php.net/> · <https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching> · <https://nvd.nist.gov/vuln/detail/CVE-2026-109618> · <https://nvd.nist.gov/vuln/detail/CVE-2026-109619>

> Hejnal porównał wersję `8.3.12` z wersjami podatnymi według NVD: ta wersja jest podatna.

### 3. Fortinet FortiGate SSL VPN na vpn.example.com:443 · `bfda06f4`

- **Dlaczego:** Znane, aktywnie wykorzystywane podatności w tym produkcie: 21. Najnowszą wpisano na listę wykorzystywanych podatności 2026-10-16.
- **Co zrobić:** Ustal zainstalowaną wersję, porównaj ją z biuletynami producenta poniżej i zaktualizuj do wersji z poprawką. Jeśli poprawki nie ma, zastosuj obejście zalecane przez producenta albo odłącz usługę od internetu.
- **Sprawdź, czy nie doszło do włamania:** Dla co najmniej jednej z tych podatności CISA zaleca analizę powłamaniową. Sama aktualizacja nie wystarczy, jeśli system był wystawiony przed poprawką: poszukaj śladów włamania, takich jak nieznane konta, pliki lub połączenia.
- **Wykryto pod adresem:** `https://vpn.example.com/remote/login?lang=en` (`path /remote/login`) · wersja nieujawniona
- **Podatności:**
  - **CVE-2025-61624**: Fortinet Multiple Products Path Traversal Vulnerability · dodana 2026-10-16 · analiza powłamaniowa
  - **CVE-2025-25249**: Fortinet Multiple Products Heap-based Buffer Overflow Vulnerability · dodana 2026-09-09 · analiza powłamaniowa
  - **CVE-2025-68686**: Fortinet FortiOS Exposure of Sensitive Information to an Unauthorized Actor Vulnerability · dodana 2026-07-27
  - **CVE-2026-24858**: Fortinet Multiple Products Authentication Bypass Using an Alternate Path or Channel Vulnerability · dodana 2026-01-27
  - **CVE-2025-59718**: Fortinet Multiple Products Improper Verification of Cryptographic Signature Vulnerability · dodana 2025-12-16
  - …oraz kolejne: 16 (pełna lista w findings.json)
- **Biuletyny:** <https://fortiguard.fortinet.com/psirt/FG-IR-26-122> · <https://nvd.nist.gov/vuln/detail/CVE-2025-61624> · <https://fortiguard.fortinet.com/psirt/FG-IR-25-084> · <https://nvd.nist.gov/vuln/detail/CVE-2025-25249>

> Hejnal rozpoznał produkt, ale nie zweryfikował jego wersji, więc może on być już załatany. Zamknij ten punkt, gdy potwierdzisz, że zainstalowana wersja zawiera poprawkę. Aby go zamknąć, uruchom `hejnal accept -item bfda06f4 -reason "..."`.

## W tym miesiącu (średnie)

### 4. Panel administracyjny Jenkins dostępny na ci.example.com:443 · `4dc28dd3`

- **Dlaczego:** Hejnal dotarł do tego panelu administracyjnego z miejsca, w którym działał. Wystawione panele administracyjne to częsta droga ataku.
- **Co zrobić:** Jeśli jest dostępny z internetu, ukryj go za VPN lub listą dozwolonych adresów IP i wymagaj logowania wieloskładnikowego.
- **Wykryto pod adresem:** `https://ci.example.com/` (`header X-Jenkins: 2.462.3`)

## Później (niskie)

### 5. Jenkins na ci.example.com:443 · `aa53d21c`

- **Dlaczego:** Znane, aktywnie wykorzystywane podatności w tym produkcie: 2. Najnowszą wpisano na listę wykorzystywanych podatności 2022-04-25.
- **Co zrobić:** Ustal zainstalowaną wersję, porównaj ją z biuletynami producenta poniżej i zaktualizuj do wersji z poprawką. Jeśli poprawki nie ma, zastosuj obejście zalecane przez producenta albo odłącz usługę od internetu.
- **Wykryto pod adresem:** `https://ci.example.com/` (`header X-Jenkins: 2.462.3`) · wersja `2.462.3`
- **Podatności:**
  - **CVE-2019-1003029**: Jenkins Script Security Plugin Sandbox Bypass Vulnerability · dodana 2022-04-25
  - **CVE-2019-1003030**: Jenkins Matrix Project Plugin Remote Code Execution Vulnerability · dodana 2022-03-25
- **Wykluczone na podstawie wersji:** CVE-2017-1000353, CVE-2024-23897, CVE-2015-5317, CVE-2018-1000861
- **Biuletyny:** <https://nvd.nist.gov/vuln/detail/CVE-2019-1003029> · <https://nvd.nist.gov/vuln/detail/CVE-2019-1003030>

> Hejnal rozpoznał produkt, ale nie zweryfikował jego wersji, więc może on być już załatany. Zamknij ten punkt, gdy potwierdzisz, że zainstalowana wersja zawiera poprawkę. Aby go zamknąć, uruchom `hejnal accept -item aa53d21c -reason "..."`.

---

Hejnal sprawdza tylko to, co widzi każdy odwiedzający, wysyłając zwykłe zapytania do usług WWW. Nigdy się nie loguje ani nie próbuje exploitów, więc może przeoczyć podatności, a sprawdzanie wersji opiera się na wersji, którą pokazuje produkt. Dane: katalog CISA Known Exploited Vulnerabilities (CC0), ENISA European Vulnerability Database (EUVD), FIRST EPSS i NVD. This product uses the NVD API but is not endorsed or certified by the NVD.
