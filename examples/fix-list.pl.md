<!-- Przykładowy wynik `hejnal run` dla usług testowych udających bramę FortiGate VPN, WordPress na PHP i Jenkinsa, porównanych z prawdziwym katalogiem CISA KEV 2026.11.03. Nazwy hostów zmieniono na example.com. -->

# Lista poprawek Hejnal: Example Sp. z o.o.

Wygenerowano 2026-11-04 12:42 UTC · Hosty: 3 · Usługi: 3 · Rozpoznane produkty: 4

Źródła: katalog CISA Known Exploited Vulnerabilities 2026.11.03.

**Napraw teraz: 3 · W tym tygodniu: 0 · W tym miesiącu: 2 · Później: 0**

## Napraw teraz (krytyczne)

### 1. Fortinet FortiGate SSL VPN na vpn.example.com:443

- **Dlaczego:** Znane, aktywnie wykorzystywane podatności w tym produkcie: 21. Najnowszą CISA dodała do katalogu 2026-10-16.
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

> Hejnal rozpoznał produkt, ale nie zweryfikował jego wersji, więc może on być już załatany. Zamknij ten punkt, gdy potwierdzisz, że zainstalowana wersja zawiera poprawkę.

### 2. WordPress na www.example.com:443

- **Dlaczego:** Znane, aktywnie wykorzystywane podatności w tym produkcie: 4. Najnowszą CISA dodała do katalogu 2026-11-03.
- **Co zrobić:** Ustal zainstalowaną wersję, porównaj ją z biuletynami producenta poniżej i zaktualizuj do wersji z poprawką. Jeśli poprawki nie ma, zastosuj obejście zalecane przez producenta albo odłącz usługę od internetu.
- **Sprawdź, czy nie doszło do włamania:** Dla co najmniej jednej z tych podatności CISA zaleca analizę powłamaniową. Sama aktualizacja nie wystarczy, jeśli system był wystawiony przed poprawką: poszukaj śladów włamania, takich jak nieznane konta, pliki lub połączenia.
- **Wykryto pod adresem:** `https://www.example.com/` (`generator WordPress 6.8.1`) · wersja `6.8.1`
- **Podatności:**
  - **CVE-2026-119977**: WordPress WordPress Core Time-of-check Time-of-use (TOCTOU) Race Condition Vulnerability · dodana 2026-11-03 · analiza powłamaniowa
  - **CVE-2026-87902**: WordPress Core Remote File Inclusion Vulnerability · dodana 2026-09-25 · analiza powłamaniowa
  - **CVE-2026-63030**: WordPress Core Interpretation Conflict Vulnerability · dodana 2026-07-21 · analiza powłamaniowa
  - **CVE-2026-60137**: WordPress Core SQL Injection Vulnerability · dodana 2026-07-21
- **Biuletyny:** <https://wordpress.org/news/2026/10/wordpress-7-1-4> · <https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-core/wordpress-core-470-713-unauthenticated-upgrade-window-staged-installer-remote-code-execution> · <https://nvd.nist.gov/vuln/detail/CVE-2026-119977> · <https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-7hp8-65ch-5whp>

> Hejnal rozpoznał produkt, ale nie zweryfikował jego wersji, więc może on być już załatany. Zamknij ten punkt, gdy potwierdzisz, że zainstalowana wersja zawiera poprawkę.

### 3. PHP na www.example.com:443

- **Dlaczego:** Znane, aktywnie wykorzystywane podatności w tym produkcie: 5. Najnowszą CISA dodała do katalogu 2026-10-26.
- **Co zrobić:** Ustal zainstalowaną wersję, porównaj ją z biuletynami producenta poniżej i zaktualizuj do wersji z poprawką. Jeśli poprawki nie ma, zastosuj obejście zalecane przez producenta albo odłącz usługę od internetu.
- **Sprawdź, czy nie doszło do włamania:** Dla co najmniej jednej z tych podatności CISA zaleca analizę powłamaniową. Sama aktualizacja nie wystarczy, jeśli system był wystawiony przed poprawką: poszukaj śladów włamania, takich jak nieznane konta, pliki lub połączenia.
- **Wykryto pod adresem:** `https://www.example.com/` (`header X-Powered-By: PHP/8.3.12`) · wersja `8.3.12`
- **Podatności:**
  - **CVE-2026-109618**: PHP Memory Corruption Vulnerability · dodana 2026-10-26 · analiza powłamaniowa
  - **CVE-2026-109619**: PHP Stale Internal Request-State Vulnerability · dodana 2026-10-26 · analiza powłamaniowa
  - **CVE-2024-4577**: PHP-CGI OS Command Injection Vulnerability · dodana 2024-06-12 · wykorzystywana w kampaniach ransomware
  - **CVE-2019-11043**: PHP FastCGI Process Manager (FPM) Buffer Overflow Vulnerability · dodana 2022-03-25 · wykorzystywana w kampaniach ransomware
  - **CVE-2012-1823**: PHP-CGI Query String Parameter Vulnerability · dodana 2022-03-25
- **Biuletyny:** <https://www.php.net/> · <https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching> · <https://nvd.nist.gov/vuln/detail/CVE-2026-109618> · <https://nvd.nist.gov/vuln/detail/CVE-2026-109619>

> Hejnal rozpoznał produkt, ale nie zweryfikował jego wersji, więc może on być już załatany. Zamknij ten punkt, gdy potwierdzisz, że zainstalowana wersja zawiera poprawkę.

## W tym miesiącu (średnie)

### 4. Panel administracyjny Jenkins dostępny na ci.example.com:443

- **Dlaczego:** Hejnal dotarł do tego panelu administracyjnego z miejsca, w którym działał. Wystawione panele administracyjne to częsta droga ataku.
- **Co zrobić:** Jeśli jest dostępny z internetu, ukryj go za VPN lub listą dozwolonych adresów IP i wymagaj logowania wieloskładnikowego.
- **Wykryto pod adresem:** `https://ci.example.com/` (`header X-Jenkins: 2.462.3`)

### 5. Jenkins na ci.example.com:443

- **Dlaczego:** Znane, aktywnie wykorzystywane podatności w tym produkcie: 6. Najnowszą CISA dodała do katalogu 2025-10-02.
- **Co zrobić:** Ustal zainstalowaną wersję, porównaj ją z biuletynami producenta poniżej i zaktualizuj do wersji z poprawką. Jeśli poprawki nie ma, zastosuj obejście zalecane przez producenta albo odłącz usługę od internetu.
- **Wykryto pod adresem:** `https://ci.example.com/` (`header X-Jenkins: 2.462.3`) · wersja `2.462.3`
- **Podatności:**
  - **CVE-2024-23897**: Jenkins Command Line Interface (CLI) Path Traversal Vulnerability · dodana 2024-08-19 · wykorzystywana w kampaniach ransomware
  - **CVE-2017-1000353**: Jenkins Remote Code Execution Vulnerability · dodana 2025-10-02
  - **CVE-2015-5317**: Jenkins User Interface (UI) Information Disclosure Vulnerability · dodana 2023-05-12
  - **CVE-2019-1003029**: Jenkins Script Security Plugin Sandbox Bypass Vulnerability · dodana 2022-04-25
  - **CVE-2019-1003030**: Jenkins Matrix Project Plugin Remote Code Execution Vulnerability · dodana 2022-03-25
  - …oraz kolejne: 1 (pełna lista w findings.json)
- **Biuletyny:** <https://www.jenkins.io/security/advisory/2024-01-24/#SECURITY-3314> · <https://nvd.nist.gov/vuln/detail/CVE-2024-23897> · <https://www.jenkins.io/security/advisory/2017-04-26/> · <https://nvd.nist.gov/vuln/detail/CVE-2017-1000353>

> Hejnal rozpoznał produkt, ale nie zweryfikował jego wersji, więc może on być już załatany. Zamknij ten punkt, gdy potwierdzisz, że zainstalowana wersja zawiera poprawkę.

---

Hejnal sprawdza tylko to, co widzi każdy odwiedzający: jedno zwykłe zapytanie na usługę WWW. Nigdy się nie loguje ani nie próbuje exploitów, więc może przeoczyć podatności i nie potwierdza wersji. Dane: katalog CISA Known Exploited Vulnerabilities (CC0) i FIRST EPSS.
