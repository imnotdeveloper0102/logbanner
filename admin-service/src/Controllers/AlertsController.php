<?php

declare(strict_types=1);

namespace Logbanner\Admin\Controllers;

use Logbanner\Admin\AlertChecker;
use Logbanner\Admin\Database;

// POST /api/alerts/check — runs the alert check once and reports
// what it did. The same check runs from bin/check-alerts.php for
// cron; this endpoint exists so the gateway or an operator can
// trigger it on demand. A mail failure never turns this into a 500:
// the summary says what was sent, throttled, or failed, and why.
final class AlertsController
{
    public function check(): void
    {
        $pdo = Database::connect();
        $summary = (new AlertChecker($pdo))->check();
        http_response_code(200);
        header('Content-Type: application/json');
        echo json_encode(['alerts' => $summary], JSON_THROW_ON_ERROR);
    }
}
