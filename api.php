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
$whoisNameServers = [];

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
    if (preg_match_all('/Name Server:\s*([^\s]+)/i', $whoisOutput, $matches)) {
        $whoisNameServers = array_map(static function (string $server) {
            return strtolower(rtrim($server, '.'));
        }, $matches[1]);
    }
}

$dnsRecords = [];
$analysis = [];
$dnsErrors = [];

$types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'SOA'];
$recordsByType = [];

$digLookup = static function (string $host, string $type, ?string &$error = null): array {
    $command = sprintf('dig +time=2 +tries=1 +noall +answer +comments %s %s 2>&1', escapeshellarg($host), escapeshellarg($type));
    $output = [];
    $status = 0;
    exec($command, $output, $status);
    if ($status !== 0) {
        $error = sprintf('dig misslyckades för %s (%s).', $host, $type);
        return [];
    }
    $lines = array_values(array_filter(array_map('trim', $output), static function (string $line) {
        return $line !== '';
    }));
    foreach ($lines as $line) {
        if (preg_match('/status:\s*([A-Z]+)/', $line, $matches)) {
            $statusText = strtoupper($matches[1]);
            $errorStatuses = ['SERVFAIL', 'REFUSED', 'FORMERR', 'NOTAUTH', 'NOTZONE'];
            if (in_array($statusText, $errorStatuses, true)) {
                $error = sprintf('dig status %s för %s (%s).', $statusText, $host, $type);
            }
            break;
        }
    }
    $answerLines = array_values(array_filter($lines, static function (string $line) {
        return !str_starts_with($line, ';;');
    }));
    return $answerLines;
};

$dohLookup = static function (string $host, string $type, ?string &$error = null): array {
    $url = sprintf('https://dns.google/resolve?name=%s&type=%s', rawurlencode($host), rawurlencode($type));
    $context = stream_context_create([
        'http' => [
            'timeout' => 3,
        ],
    ]);
    $response = @file_get_contents($url, false, $context);
    if ($response === false) {
        $error = sprintf('DNS-over-HTTPS misslyckades för %s (%s).', $host, $type);
        return [];
    }
    $payload = json_decode($response, true);
    if (!is_array($payload)) {
        $error = sprintf('DNS-over-HTTPS svar var ogiltigt för %s (%s).', $host, $type);
        return [];
    }
    if (!empty($payload['Status']) && (int) $payload['Status'] !== 0) {
        $status = (int) $payload['Status'];
        $errorStatuses = [2, 5, 9, 10];
        if (in_array($status, $errorStatuses, true)) {
            $error = sprintf('DNS-over-HTTPS status %d för %s (%s).', $status, $host, $type);
        }
        return [];
    }
    $answers = $payload['Answer'] ?? [];
    $lines = [];
    foreach ($answers as $answer) {
        if (!empty($answer['data'])) {
            $lines[] = $answer['data'];
        }
    }
    return $lines;
};

foreach ($types as $type) {
    $records = @dns_get_record($domain, constant('DNS_' . $type));
    if ($records === false) {
        $records = [];
    }
    if (empty($records)) {
        $digError = null;
        $lines = $digLookup($domain, $type, $digError);
        $digRecords = [];
        foreach ($lines as $line) {
            switch ($type) {
                case 'A':
                    if (preg_match('/\s+IN\s+A\s+(.+)$/i', $line, $match)) {
                        $digRecords[] = ['ip' => trim($match[1])];
                    } elseif (filter_var($line, FILTER_VALIDATE_IP)) {
                        $digRecords[] = ['ip' => $line];
                    }
                    break;
                case 'AAAA':
                    if (preg_match('/\s+IN\s+AAAA\s+(.+)$/i', $line, $match)) {
                        $digRecords[] = ['ipv6' => trim($match[1])];
                    } elseif (filter_var($line, FILTER_VALIDATE_IP)) {
                        $digRecords[] = ['ipv6' => $line];
                    }
                    break;
                case 'MX':
                    if (preg_match('/\s+IN\s+MX\s+(\d+)\s+(.+)$/i', $line, $match)) {
                        $digRecords[] = ['pri' => (int) $match[1], 'target' => rtrim($match[2], '.')];
                    } else {
                        $parts = preg_split('/\s+/', $line, 2);
                        if (count($parts) === 2) {
                            $digRecords[] = ['pri' => (int) $parts[0], 'target' => rtrim($parts[1], '.')];
                        }
                    }
                    break;
                case 'TXT':
                    if (preg_match_all('/"([^"]*)"/', $line, $matches) && !empty($matches[1])) {
                        $digRecords[] = ['txt' => implode('', $matches[1])];
                    } elseif (preg_match('/\s+IN\s+TXT\s+(.+)$/i', $line, $match)) {
                        $digRecords[] = ['txt' => trim($match[1], '"')];
                    } else {
                        $digRecords[] = ['txt' => trim($line, '"')];
                    }
                    break;
                case 'NS':
                    if (preg_match('/\s+IN\s+(NS|CNAME)\s+(.+)$/i', $line, $match)) {
                        $digRecords[] = ['target' => rtrim($match[2], '.')];
                    } else {
                        $digRecords[] = ['target' => rtrim($line, '.')];
                    }
                    break;
                case 'SOA':
                    if (preg_match('/\s+IN\s+SOA\s+(.+)$/i', $line, $match)) {
                        $parts = preg_split('/\s+/', $match[1]);
                    } else {
                        $parts = preg_split('/\s+/', $line);
                    }
                    if (count($parts) >= 2) {
                        $digRecords[] = ['mname' => rtrim($parts[0], '.'), 'rname' => rtrim($parts[1], '.')];
                    }
                    break;
            }
        }
        if (!empty($digRecords)) {
            $records = $digRecords;
        } else {
            $dohError = null;
            $dohLines = $dohLookup($domain, $type, $dohError);
            $dohRecords = [];
            foreach ($dohLines as $line) {
                switch ($type) {
                    case 'A':
                        if (filter_var($line, FILTER_VALIDATE_IP)) {
                            $dohRecords[] = ['ip' => $line];
                        }
                        break;
                    case 'AAAA':
                        if (filter_var($line, FILTER_VALIDATE_IP)) {
                            $dohRecords[] = ['ipv6' => $line];
                        }
                        break;
                    case 'MX':
                        $parts = preg_split('/\s+/', $line, 2);
                        if (count($parts) === 2) {
                            $dohRecords[] = ['pri' => (int) $parts[0], 'target' => rtrim($parts[1], '.')];
                        }
                        break;
                    case 'TXT':
                        $dohRecords[] = ['txt' => trim($line, '"')];
                        break;
                    case 'NS':
                        $dohRecords[] = ['target' => rtrim($line, '.')];
                        break;
                    case 'SOA':
                        $parts = preg_split('/\s+/', $line);
                        if (count($parts) >= 2) {
                            $dohRecords[] = ['mname' => rtrim($parts[0], '.'), 'rname' => rtrim($parts[1], '.')];
                        }
                        break;
                }
            }
            if (!empty($dohRecords)) {
                $records = $dohRecords;
            }
            if ($dohError) {
                $dnsErrors[] = $dohError;
            }
        }
        if ($digError) {
            $dnsErrors[] = $digError;
        }
    }
    $recordsByType[$type] = $records;
}

if (empty($recordsByType['CNAME'])) {
    $wwwHost = 'www.' . $domain;
    $digError = null;
    $lines = $digLookup($wwwHost, 'CNAME', $digError);
    $digRecords = [];
    foreach ($lines as $line) {
        if (preg_match('/\s+IN\s+CNAME\s+(.+)$/i', $line, $match)) {
            $digRecords[] = ['target' => rtrim($match[1], '.')];
        } else {
            $digRecords[] = ['target' => rtrim($line, '.')];
        }
    }
    if (empty($digRecords)) {
        $dohError = null;
        $dohLines = $dohLookup($wwwHost, 'CNAME', $dohError);
        foreach ($dohLines as $line) {
            $digRecords[] = ['target' => rtrim($line, '.')];
        }
        if ($dohError) {
            $dnsErrors[] = $dohError;
        }
    }
    if (!empty($digRecords)) {
        foreach ($digRecords as $record) {
            $record['host'] = $wwwHost;
            $recordsByType['CNAME'][] = $record;
        }
    }
    if ($digError) {
        $dnsErrors[] = $digError;
    }
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
                if (!empty($record['host'])) {
                    $dnsRecords[] = sprintf('CNAME (%s) → %s', $record['host'], $record['target']);
                } else {
                    $dnsRecords[] = sprintf('CNAME → %s', $record['target']);
                }
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
if (empty($nameServers) && !empty($whoisNameServers)) {
    $nameServers = array_values(array_unique($whoisNameServers));
    $analysis[] = 'NS-poster hämtade från WHOIS eftersom DNS-uppslag saknade data.';
}

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

$zoneRecords = [];
$zoneTransferErrors = [];
$zoneTransferSource = null;
if (!empty($nameServers)) {
    foreach ($nameServers as $nameServer) {
        $command = sprintf('dig +noall +answer @%s %s AXFR 2>&1', escapeshellarg($nameServer), escapeshellarg($domain));
        $output = [];
        $status = 0;
        exec($command, $output, $status);
        $lines = array_values(array_filter(array_map('trim', $output), static function (string $line) {
            return $line !== '';
        }));
        $transferFailed = false;
        foreach ($lines as $line) {
            if (preg_match('/(Transfer failed|REFUSED|timed out|no servers could be reached)/i', $line)) {
                $transferFailed = true;
                break;
            }
        }
        if ($status === 0 && !$transferFailed && !empty($lines)) {
            $zoneRecords = array_slice($lines, 0, 1000);
            $zoneTransferSource = $nameServer;
            break;
        }
        if ($transferFailed || $status !== 0) {
            $zoneTransferErrors[] = sprintf('Zonöverföring misslyckades via %s.', $nameServer);
        }
    }
}

if (empty($zoneRecords)) {
    $analysis[] = 'Full zonlista (AXFR) kunde inte hämtas. Det är normalt om zonöverföring är avstängd.';
}

$response = [
    'domain' => $domain,
    'summary' => 'Analys klar.',
    'registry' => $whoisRegistry,
    'registrar' => $whoisRegistrar,
    'expiry' => $whoisExpiry,
    'nameServers' => $nameServers,
    'dnsRecords' => $dnsRecords,
    'zoneRecords' => $zoneRecords,
    'zoneTransferSource' => $zoneTransferSource,
    'zoneTransferErrors' => array_values(array_unique($zoneTransferErrors)),
    'analysis' => $analysis,
    'dnsErrors' => $dnsErrors,
];

echo json_encode($response, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
