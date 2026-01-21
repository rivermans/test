<?php
?>
<!DOCTYPE html>
<html lang="sv">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Domänanalys</title>
  <style>
    :root {
      color-scheme: light;
      font-family: "Inter", "Segoe UI", sans-serif;
      background: #f5f7fb;
      color: #1f2a44;
    }
    body {
      margin: 0;
      padding: 40px 20px;
    }
    .container {
      max-width: 960px;
      margin: 0 auto;
    }
    h1 {
      margin-bottom: 8px;
    }
    .subtitle {
      color: #51607a;
      margin-bottom: 24px;
    }
    .search-row {
      display: flex;
      gap: 12px;
      margin-bottom: 24px;
    }
    .search-row input {
      flex: 1;
      padding: 12px 16px;
      border-radius: 10px;
      border: 1px solid #d0d7e2;
      font-size: 16px;
    }
    .search-row button {
      padding: 12px 20px;
      border-radius: 10px;
      border: none;
      background: #2d6cdf;
      color: #fff;
      font-size: 16px;
      cursor: pointer;
      min-width: 140px;
    }
    .search-row button:disabled {
      opacity: 0.6;
      cursor: wait;
    }
    .card {
      background: #fff;
      border-radius: 16px;
      padding: 20px;
      box-shadow: 0 12px 28px rgba(15, 23, 42, 0.08);
      margin-bottom: 16px;
    }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 16px;
    }
    .label {
      font-size: 13px;
      color: #51607a;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    .value {
      font-size: 16px;
      margin-top: 4px;
    }
    ul {
      padding-left: 18px;
    }
    .status {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      font-weight: 600;
    }
    .badge {
      padding: 4px 10px;
      border-radius: 999px;
      font-size: 12px;
      background: #eaf0ff;
      color: #2d6cdf;
    }
    .error {
      color: #b42318;
      font-weight: 600;
    }
    .muted {
      color: #6b7280;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>Domänanalys</h1>
    <div class="subtitle">Analysera registry, DNS-leverantör och DNS-poster för en domän.</div>

    <form id="domain-form" class="search-row">
      <input type="text" id="domain-input" name="domain" placeholder="exempel.se" autocomplete="off" required />
      <button type="submit" id="submit-button">Kontrollera</button>
    </form>

    <div id="results"></div>
  </div>

  <script>
    const form = document.getElementById('domain-form');
    const input = document.getElementById('domain-input');
    const button = document.getElementById('submit-button');
    const results = document.getElementById('results');

    const renderList = (items) => {
      if (!items || items.length === 0) {
        return '<p class="muted">Ingen data hittades.</p>';
      }
      return `<ul>${items.map(item => `<li>${item}</li>`).join('')}</ul>`;
    };

    const renderRecordTable = (records) => {
      if (!records || records.length === 0) {
        return '<p class="muted">Inga poster hittades.</p>';
      }
      return `<ul>${records.map(record => `<li>${record}</li>`).join('')}</ul>`;
    };

    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      const domain = input.value.trim();
      if (!domain) {
        return;
      }
      button.disabled = true;
      button.textContent = 'Analyserar...';
      results.innerHTML = '';

      try {
        const response = await fetch(`api.php?domain=${encodeURIComponent(domain)}`);
        const data = await response.json();
        if (!response.ok) {
          throw new Error(data.error || 'Något gick fel.');
        }

        results.innerHTML = `
          <div class="card">
            <div class="status">
              <span class="badge">${data.domain}</span>
              <span>${data.summary}</span>
            </div>
          </div>
          <div class="grid">
            <div class="card">
              <div class="label">Registry</div>
              <div class="value">${data.registry || 'Okänt'}</div>
              <div class="label" style="margin-top: 12px;">Registrar</div>
              <div class="value">${data.registrar || 'Okänt'}</div>
              <div class="label" style="margin-top: 12px;">Utgångsdatum</div>
              <div class="value">${data.expiry || 'Okänt'}</div>
            </div>
            <div class="card">
              <div class="label">DNS-leverantör (NS)</div>
              <div class="value">${renderList(data.nameServers)}</div>
            </div>
          </div>
          <div class="card">
            <div class="label">DNS-poster</div>
            <div class="value">${renderRecordTable(data.dnsRecords)}</div>
          </div>
          <div class="card">
            <div class="label">Zonposter (AXFR)</div>
            <div class="value">
              ${data.zoneTransferSource ? `<p class="muted">Källa: ${data.zoneTransferSource}</p>` : ''}
              ${renderRecordTable(data.zoneRecords)}
            </div>
          </div>
          ${data.zoneTransferErrors && data.zoneTransferErrors.length > 0 ? `
            <div class="card">
              <div class="label">Zonöverföringsvarningar</div>
              <div class="value">${renderList(data.zoneTransferErrors)}</div>
            </div>
          ` : ''}
          ${data.dnsErrors && data.dnsErrors.length > 0 ? `
            <div class="card">
              <div class="label">DNS-varningar</div>
              <div class="value">${renderList(data.dnsErrors)}</div>
            </div>
          ` : ''}
          <div class="card">
            <div class="label">Analys</div>
            <div class="value">${renderList(data.analysis)}</div>
          </div>
        `;
      } catch (error) {
        results.innerHTML = `<div class="card"><p class="error">${error.message}</p></div>`;
      } finally {
        button.disabled = false;
        button.textContent = 'Kontrollera';
      }
    });
  </script>
</body>
</html>
