<?php

declare(strict_types=1);

// CLI entry point for the alert check, run from cron. Shares the
// AlertChecker with POST /api/alerts/check; the CLI exists because
// cron cannot call an HTTP endpoint that needs a service token.
//
//   */5 * * * * cd /path/to/logbanner/admin-service && /usr/bin/php bin/check-alerts.php >> /var/log/logbanner/alerts.log 2>&1
//
// Env comes from the environment, or from ../../.env when a variable
// is not already set (the file is never committed; see README).

require __DIR__ . '/../vendor/autoload.php';

use Logbanner\Admin\AlertChecker;
use Logbanner\Admin\Database;

$envFile = __DIR__ . '/../../.env';
if (is_readable($envFile)) {
    foreach (file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        $line = trim($line);
        if ($line === '' || str_starts_with($line, '#')) {
            continue;
        }
        $pos = strpos($line, '=');
        if ($pos === false) {
            continue;
        }
        $key = trim(substr($line, 0, $pos));
        $value = trim(substr($line, $pos + 1));
        if ($key !== '' && getenv($key) === false) {
            putenv($key . '=' . $value);
        }
    }
}

try {
    $summary = (new AlertChecker(Database::connect()))->check();
    echo json_encode(['alerts' => $summary], JSON_THROW_ON_ERROR) . PHP_EOL;
    exit(0);
} catch (Throwable $e) {
    fwrite(STDERR, 'check-alerts failed: ' . $e->getMessage() . PHP_EOL);
    exit(1);
}
