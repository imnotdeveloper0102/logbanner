<?php

declare(strict_types=1);

namespace Logbanner\Admin\Controllers;

use DateTimeImmutable;
use Dompdf\Dompdf;
use Logbanner\Admin\Database;
use PDO;

// Daily and weekly reports, built from real rows only.
//
//   GET /api/reports/daily?date=YYYY-MM-DD
//   GET /api/reports/weekly?start=YYYY-MM-DD   (a 7-day window
//     starting on that date; default is the Monday of this week)
// Dates are UTC days; a bad date is a 400. ?format=csv downloads
// the same data as CSV, ?format=pdf as a PDF (plain tables, no
// decorative styling). Without format the response is JSON.
//
// Top countries are honestly unavailable: events carry no country
// — the gateway does GeoIP lookups live (stage 6) but never stores
// the result, and events.raw does not include it. The report says
// so instead of inventing countries; capturing the country at event
// time is gateway/agent work and out of stage-7 scope.
final class ReportsController
{
    public function daily(array $query): void
    {
        $date = $this->parseDate($query['date'] ?? gmdate('Y-m-d'));
        if ($date === null) {
            $this->json(400, ['error' => ['message' => 'date must be YYYY-MM-DD']]);
            return;
        }
        $end = $date->modify('+1 day');
        $this->respond($query, 'daily', $date, $end, 'hour');
    }

    public function weekly(array $query): void
    {
        if (isset($query['start']) && $query['start'] !== '') {
            $start = $this->parseDate($query['start']);
            if ($start === null) {
                $this->json(400, ['error' => ['message' => 'start must be YYYY-MM-DD']]);
                return;
            }
        } else {
            // Monday of the current week, UTC.
            $today = new DateTimeImmutable('today', new \DateTimeZone('UTC'));
            $start = $today->modify('Monday this week');
        }
        $end = $start->modify('+7 days');
        $this->respond($query, 'weekly', $start, $end, 'day');
    }

    private function respond(array $query, string $kind, DateTimeImmutable $start, DateTimeImmutable $end, string $bucket): void
    {
        $format = $query['format'] ?? 'json';
        if ($format !== 'json' && $format !== 'csv' && $format !== 'pdf') {
            $this->json(400, ['error' => ['message' => 'format must be json, csv, or pdf']]);
            return;
        }
        $pdo = Database::connect();
        $report = $this->build($pdo, $kind, $start, $end, $bucket);
        if ($format === 'csv') {
            $this->respondCsv($kind, $start, $report);
            return;
        }
        if ($format === 'pdf') {
            $this->respondPdf($kind, $start, $report);
            return;
        }
        $this->json(200, ['report' => $report]);
    }

    private function build(PDO $pdo, string $kind, DateTimeImmutable $start, DateTimeImmutable $end, string $bucket): array
    {
        $startStr = $start->format('Y-m-d H:i:s');
        $endStr = $end->format('Y-m-d H:i:s');

        $total = $this->count($pdo, 'SELECT count(*) FROM events WHERE occurred_at >= :start AND occurred_at < :end', $startStr, $endStr);

        $buckets = [];
        if ($bucket === 'hour') {
            $stmt = $pdo->prepare(
                "SELECT date_trunc('hour', occurred_at) AS bucket, count(*) AS count FROM events " .
                'WHERE occurred_at >= :start AND occurred_at < :end ' .
                'GROUP BY 1 ORDER BY 1'
            );
            $stmt->execute([':start' => $startStr, ':end' => $endStr]);
            $byHour = [];
            foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
                $byHour[(int) (new DateTimeImmutable($row['bucket']))->format('G')] = (int) $row['count'];
            }
            for ($hour = 0; $hour < 24; $hour++) {
                $buckets[] = ['hour' => $hour, 'count' => $byHour[$hour] ?? 0];
            }
        } else {
            $stmt = $pdo->prepare(
                "SELECT date_trunc('day', occurred_at) AS bucket, count(*) AS count FROM events " .
                'WHERE occurred_at >= :start AND occurred_at < :end ' .
                'GROUP BY 1 ORDER BY 1'
            );
            $stmt->execute([':start' => $startStr, ':end' => $endStr]);
            $byDay = [];
            foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
                $byDay[(new DateTimeImmutable($row['bucket']))->format('Y-m-d')] = (int) $row['count'];
            }
            for ($i = 0; $i < 7; $i++) {
                $day = $start->modify('+' . $i . ' days')->format('Y-m-d');
                $buckets[] = ['date' => $day, 'count' => $byDay[$day] ?? 0];
            }
        }

        $stmt = $pdo->prepare(
            'SELECT host(ip) AS ip, count(*) AS count FROM bans ' .
            'WHERE created_at >= :start AND created_at < :end ' .
            'GROUP BY ip ORDER BY count DESC, ip ASC LIMIT 10'
        );
        $stmt->execute([':start' => $startStr, ':end' => $endStr]);
        $topBannedIps = array_map(
            fn (array $r) => ['ip' => $r['ip'], 'count' => (int) $r['count']],
            $stmt->fetchAll(PDO::FETCH_ASSOC)
        );

        $stmt = $pdo->prepare(
            'SELECT r.name AS rule, count(*) AS count FROM events e ' .
            'LEFT JOIN rules r ON r.id = e.rule_id ' .
            'WHERE e.occurred_at >= :start AND e.occurred_at < :end ' .
            'GROUP BY r.name ORDER BY count DESC, r.name ASC NULLS LAST LIMIT 10'
        );
        $stmt->execute([':start' => $startStr, ':end' => $endStr]);
        $topRules = array_map(
            fn (array $r) => ['rule' => $r['rule'], 'count' => (int) $r['count']],
            $stmt->fetchAll(PDO::FETCH_ASSOC)
        );

        $bansCreated = $this->count($pdo, 'SELECT count(*) FROM bans WHERE created_at >= :start AND created_at < :end', $startStr, $endStr);
        $bansRevoked = $this->count($pdo, 'SELECT count(*) FROM bans WHERE revoked_at >= :start AND revoked_at < :end', $startStr, $endStr);

        return [
            'kind' => $kind,
            'period' => ['start' => $start->format('Y-m-d'), 'end' => $end->format('Y-m-d')],
            'total_events' => $total,
            'events_by_' . $bucket => $buckets,
            'top_banned_ips' => $topBannedIps,
            'most_triggered_rules' => $topRules,
            'bans_created' => $bansCreated,
            'bans_revoked' => $bansRevoked,
            'top_countries' => null,
            'top_countries_note' => 'Country data is not stored with events: the gateway ' .
                'does GeoIP lookups live (stage 6) but never persists the result, and ' .
                'events.raw carries no country. This section is unavailable until the ' .
                'country is captured at event time (gateway/agent work, out of stage-7 scope).',
        ];
    }

    private function count(PDO $pdo, string $sql, string $start, string $end): int
    {
        $stmt = $pdo->prepare($sql);
        $stmt->execute([':start' => $start, ':end' => $end]);
        return (int) $stmt->fetchColumn();
    }

    private function respondCsv(string $kind, DateTimeImmutable $start, array $report): void
    {
        $filename = 'logbanner-report-' . $kind . '-' . $start->format('Y-m-d') . '.csv';
        header('Content-Type: text/csv; charset=utf-8');
        header('Content-Disposition: attachment; filename="' . $filename . '"');
        $out = fopen('php://output', 'w');
        fputcsv($out, ['report', $kind, $report['period']['start'], $report['period']['end']]);
        fputcsv($out, ['total_events', $report['total_events']]);
        fputcsv($out, ['bans_created', $report['bans_created']]);
        fputcsv($out, ['bans_revoked', $report['bans_revoked']]);
        fputcsv($out, []);
        $bucketKey = 'events_by_' . ($kind === 'daily' ? 'hour' : 'day');
        $bucketLabel = $kind === 'daily' ? 'hour' : 'date';
        fputcsv($out, ['events_by_' . $bucketLabel, $bucketLabel, 'count']);
        foreach ($report[$bucketKey] as $row) {
            fputcsv($out, ['events', $row[$bucketLabel], $row['count']]);
        }
        fputcsv($out, []);
        fputcsv($out, ['top_banned_ips', 'ip', 'count']);
        foreach ($report['top_banned_ips'] as $row) {
            fputcsv($out, ['top_banned_ip', $row['ip'], $row['count']]);
        }
        fputcsv($out, []);
        fputcsv($out, ['most_triggered_rules', 'rule', 'count']);
        foreach ($report['most_triggered_rules'] as $row) {
            fputcsv($out, ['rule', $row['rule'] ?? '(no rule)', $row['count']]);
        }
        fputcsv($out, []);
        fputcsv($out, ['top_countries', 'unavailable', $report['top_countries_note']]);
        fclose($out);
    }

    private function respondPdf(string $kind, DateTimeImmutable $start, array $report): void
    {
        if (!class_exists(Dompdf::class)) {
            $this->json(501, ['error' => ['message' =>
                'PDF export is unavailable: Dompdf is not installed. ' .
                'Run `composer require dompdf/dompdf` in admin-service (it needs the php-dom extension) ' .
                'and restart the service.',
            ]]);
            return;
        }
        $esc = fn ($value) => htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $html = '<html><head><meta charset="utf-8"><title>logbanner ' . $esc($kind) . ' report</title></head><body>';
        $html .= '<h1>logbanner ' . $esc($kind) . ' report</h1>';
        $html .= '<p>Period: ' . $esc($report['period']['start']) . ' to ' . $esc($report['period']['end']) . ' (UTC)</p>';
        $html .= '<p>Total events: ' . $report['total_events'] . '. Bans created: ' . $report['bans_created'] .
            '. Bans revoked: ' . $report['bans_revoked'] . '.</p>';
        $bucketKey = 'events_by_' . ($kind === 'daily' ? 'hour' : 'day');
        $bucketLabel = $kind === 'daily' ? 'Hour' : 'Date';
        $html .= '<h2>Events</h2><table border="1" cellpadding="4"><tr><th>' . $bucketLabel . '</th><th>Count</th></tr>';
        foreach ($report[$bucketKey] as $row) {
            $html .= '<tr><td>' . $esc($row[$kind === 'daily' ? 'hour' : 'date']) . '</td><td>' . $row['count'] . '</td></tr>';
        }
        $html .= '</table>';
        $html .= '<h2>Top banned IPs</h2><table border="1" cellpadding="4"><tr><th>IP</th><th>Bans</th></tr>';
        foreach ($report['top_banned_ips'] as $row) {
            $html .= '<tr><td>' . $esc($row['ip']) . '</td><td>' . $row['count'] . '</td></tr>';
        }
        $html .= '</table>';
        $html .= '<h2>Most triggered rules</h2><table border="1" cellpadding="4"><tr><th>Rule</th><th>Events</th></tr>';
        foreach ($report['most_triggered_rules'] as $row) {
            $html .= '<tr><td>' . $esc($row['rule'] ?? '(no rule)') . '</td><td>' . $row['count'] . '</td></tr>';
        }
        $html .= '</table>';
        $html .= '<p>' . $esc($report['top_countries_note']) . '</p>';
        $html .= '</body></html>';

        $dompdf = new Dompdf();
        $dompdf->loadHtml($html);
        $dompdf->render();
        $filename = 'logbanner-report-' . $kind . '-' . $start->format('Y-m-d') . '.pdf';
        header('Content-Type: application/pdf');
        header('Content-Disposition: attachment; filename="' . $filename . '"');
        echo $dompdf->output();
    }

    // Strict YYYY-MM-DD: createFromFormat alone accepts '2026-13-40'
    // by rolling over, so the formatted value must round-trip.
    private function parseDate(string $value): ?DateTimeImmutable
    {
        if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $value)) {
            return null;
        }
        $date = DateTimeImmutable::createFromFormat('!Y-m-d', $value, new \DateTimeZone('UTC'));
        if ($date === false || $date->format('Y-m-d') !== $value) {
            return null;
        }
        return $date;
    }

    private function json(int $status, array $payload): void
    {
        http_response_code($status);
        header('Content-Type: application/json');
        echo json_encode($payload, JSON_THROW_ON_ERROR);
    }
}
