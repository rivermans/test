# Domain Analysis

## Overview
This project is a lightweight PHP application that analyzes a domain configuration: registry/registrar (via WHOIS), DNS provider (NS), DNS records, and a summary analysis of common issues. The UI is a simple index page where you enter a domain and get results without a page reload.

## Installation
1. **Requirements**
   - PHP 8+ (the built-in web server is sufficient).
   - `dig` and `whois` installed on the system.

2. **Start locally**
   ```bash
   php -S 0.0.0.0:8000 -t .
   ```

3. **Open in your browser**
   - `http://127.0.0.1:8000/index.php`

## Technical overview
- **Frontend (`index.php`)**
  - A form with a domain input and the "Kontrollera" button.
  - JavaScript calls the API via `fetch` and renders results without reloading the page.

- **API (`api.php`)**
  - Validates the input domain.
  - Fetches WHOIS data (registry, registrar, expiry date, name servers).
  - Collects DNS records for A/AAAA/MX/TXT/NS/SOA.
  - Uses `dns_get_record` first and falls back to `dig`.
  - Uses DNS-over-HTTPS as an extra fallback when local lookups return no answers.
  - Attempts to fetch zone data via AXFR against name servers (if allowed).
  - Builds an analysis list with common warnings (e.g., missing MX or SPF).

- **Response format**
  - The API returns JSON with `nameServers`, `dnsRecords`, `zoneRecords`,
    `analysis`, and optional `dnsErrors` for diagnostics.
