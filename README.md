# Domänanalys

## Översikt
Det här projektet är en liten PHP-applikation som analyserar en domäns konfiguration: registry/registrar (via WHOIS), DNS-leverantör (NS), DNS-poster och en sammanfattande analys av vanliga felaktigheter. Gränssnittet består av en enkel index-sida där du skriver in en domän och får resultat utan omladdning.

## Installation
1. **Krav**
   - PHP 8+ (inbyggd webserver räcker).
   - `dig` och `whois` installerade i systemet.

2. **Starta lokalt**
   ```bash
   php -S 0.0.0.0:8000 -t .
   ```

3. **Öppna i webbläsare**
   - `http://127.0.0.1:8000/index.php`

## Teknisk beskrivning
- **Frontend (`index.php`)**
  - Ett formulär med ett domänfält och knappen "Kontrollera".
  - JavaScript anropar API:t med `fetch` och renderar resultatet utan omladdning.

- **API (`api.php`)**
  - Validerar inmatad domän.
  - Hämtar WHOIS-information (registry, registrar, utgångsdatum, name servers).
  - Samlar DNS-poster för A/AAAA/MX/TXT/NS/SOA.
  - Använder `dns_get_record` först och faller tillbaka till `dig`.
  - Har DNS-over-HTTPS som extra fallback när lokala uppslag saknar svar.
  - Försöker hämta zondata via AXFR mot name servers (om tillåtet).
  - Skapar en analyslista med vanliga varningar (t.ex. saknad MX eller SPF).

- **Svarformat**
  - API:t returnerar JSON med `nameServers`, `dnsRecords`, `zoneRecords`,
    `analysis` och eventuella `dnsErrors` för diagnostik.
