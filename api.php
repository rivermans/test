<?php
header('Content-Type: application/json; charset=utf-8');

$domainInput = $_GET['domain'] ?? '';
$domain = strtolower(trim($domainInput));
$domain = preg_replace('/^https?:\/\//', '', $domain);
$domain = preg_replace('/\/$/', '', $domain);

if (!$domain) {
    http_response_code(400);
    echo json_encode(['error' => 'Du måste ange en domän.']);
    exit;
}

if (!preg_match('/^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$/', $domain)) {
    http_response_code(400);
    echo json_encode(['error' => 'Ogiltigt domänformat.']);
    exit;
}

$whoisOutput = '';
$whoisRegistry = 'Okänt';
$whoisRegistrar = 'Okänt';
$whoisExpiry = 'Okänt';

$whoisCommand = sprintf('whois %s 2>&1', escapeshellarg($domain));
$whoisOutput = shell_exec($whoisCommand) ?? '';

if ($whoisOutput) {
    if (preg_match('/Registry Domain ID:\s*(.+)/i', $whoisOutput, $match)) {
        $whoisRegistry = trim($match[1]);
    }
    if (preg_match('/Registrar:\s*(.+)/i', $whoisOutput, $match)) {
        $whoisRegistrar = trim($match[1]);
    }
    if (preg_match('/Registrar Registration Expiration Date:\s*(.+)/i', $whoisOutput, $match)) {
        $whoisExpiry = trim($match[1]);
    } elseif (preg_match('/Expiry Date:\s*(.+)/i', $whoisOutput, $match)) {
        $whoisExpiry = trim($match[1]);
    }
}

$dnsRecords = [];
$analysis = [];
$dnsErrors = [];

$types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA'];
$recordsByType = [];
foreach ($types as $type) {
    $records = @dns_get_record($domain, constant('DNS_' . $type));
    if ($records === false) {
        $records = [];
    }
    if (empty($records)) {
        $digRecords = [];
        $digOutput = shell_exec(sprintf('dig +short %s %s 2>&1', escapeshellarg($domain), escapeshellarg($type)));
        if ($digOutput) {
            $lines = array_filter(array_map('trim', explode("\n", $digOutput)));
            foreach ($lines as $line) {
                switch ($type) {
                    case 'A':
                        $digRecords[] = ['ip' => $line];
                        break;
                    case 'AAAA':
                        $digRecords[] = ['ipv6' => $line];
                        break;
                    case 'MX':
                        $parts = preg_split('/\s+/', $line, 2);
                        if (count($parts) === 2) {
                            $digRecords[] = ['pri' => (int) $parts[0], 'target' => rtrim($parts[1], '.')];
                        }
                        break;
                    case 'TXT':
                        $digRecords[] = ['txt' => trim($line, '"')];
                        break;
                    case 'NS':
                    case 'CNAME':
                        $digRecords[] = ['target' => rtrim($line, '.')];
                        break;
                    case 'SOA':
                        $parts = preg_split('/\s+/', $line);
                        if (count($parts) >= 2) {
                            $digRecords[] = ['mname' => rtrim($parts[0], '.'), 'rname' => rtrim($parts[1], '.')];
                        }
                        break;
                }
            }
        }
        if (!empty($digRecords)) {
            $records = $digRecords;
        } else {
            $dnsErrors[] = sprintf('Kunde inte hämta %s-poster.', $type);
        }
    }
    $recordsByType[$type] = $records;
}

foreach ($recordsByType as $type => $records) {
    foreach ($records as $record) {
        switch ($type) {
            case 'A':
                if (!empty($record['ip'])) {
                    $dnsRecords[] = sprintf('A → %s', $record['ip']);
                }
                break;
            case 'AAAA':
                if (!empty($record['ipv6'])) {
                    $dnsRecords[] = sprintf('AAAA → %s', $record['ipv6']);
                }
                break;
            case 'MX':
                $dnsRecords[] = sprintf('MX (%d) → %s', $record['pri'], $record['target']);
                break;
            case 'TXT':
                $text = $record['txt'] ?? '';
                $dnsRecords[] = sprintf('TXT → %s', $text);
                break;
            case 'NS':
                $dnsRecords[] = sprintf('NS → %s', $record['target']);
                break;
            case 'CNAME':
                $dnsRecords[] = sprintf('CNAME → %s', $record['target']);
                break;
            case 'SOA':
                $dnsRecords[] = sprintf('SOA → %s (%s)', $record['mname'], $record['rname']);
                break;
        }
    }
}

$nameServers = array_values(array_unique(array_map(static function ($record) {
    return $record['target'] ?? '';
}, $recordsByType['NS'] ?? [])));
$nameServers = array_filter($nameServers);

if (empty($nameServers)) {
    $analysis[] = 'Inga NS-poster hittades. Domänen kan vara felkonfigurerad.';
} else {
    $analysis[] = 'DNS-leverantör identifierad via NS-poster.';
}

$hasA = !empty($recordsByType['A']);
$hasAAAA = !empty($recordsByType['AAAA']);
if (!$hasA && !$hasAAAA) {
    $analysis[] = 'Saknar A/AAAA-poster. Webbplats kan vara otillgänglig.';
}

$mxRecords = $recordsByType['MX'] ?? [];
if (empty($mxRecords)) {
    $analysis[] = 'Inga MX-poster hittades. E-post kommer inte fram.';
}

$txtRecords = $recordsByType['TXT'] ?? [];
$hasSpf = false;
foreach ($txtRecords as $record) {
    if (!empty($record['txt']) && stripos($record['txt'], 'v=spf1') !== false) {
        $hasSpf = true;
        break;
    }
}
if (!$hasSpf) {
    $analysis[] = 'Ingen SPF-post hittades. Rekommenderas för e-postsäkerhet.';
}

if ($whoisExpiry !== 'Okänt') {
    $analysis[] = sprintf('Registreringen löper ut: %s.', $whoisExpiry);
}

$dnsErrors = array_values(array_unique($dnsErrors));
if (!empty($dnsErrors)) {
    $analysis[] = 'DNS-uppslag misslyckades för en eller flera posttyper.';
}

$response = [
    'domain' => $domain,
    'summary' => 'Analys klar.',
    'registry' => $whoisRegistry,
    'registrar' => $whoisRegistrar,
    'expiry' => $whoisExpiry,
    'nameServers' => $nameServers,
    'dnsRecords' => $dnsRecords,
    'analysis' => $analysis,
    'dnsErrors' => $dnsErrors,
];

echo json_encode($response, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
