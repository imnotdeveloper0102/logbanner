<?php

declare(strict_types=1);

namespace Logbanner\Admin;

use PDO;

// Decides whether an alert email is due and sends it, recording what
// was sent in alert_state so a repeated check never re-sends.
//
// Three alerts, all driven by real rows, never by invented data:
//   - critical ban: a ban created in the last hour for which a
//     critical-severity event exists for the same IP (and the same
//     rule, when the ban names one) in the hour before the ban. A
//     ban with no matching critical event is not a critical ban and
//     sends nothing. Sent once per ban id.
//   - attack wave: at least ALERT_WAVE_THRESHOLD events (default 50)
//     in the last ALERT_WAVE_WINDOW_MINUTES minutes (default 10).
//     Throttled to at most one mail per ALERT_WAVE_THROTTLE_MINUTES
//     minutes (default 60) so an ongoing attack cannot spam the
//     admin; a suppressed wave is reported as throttled, not sent.
//   - circuit breaker (stage 8): the agent's latest breaker event
//     (source 'agent', raw.type 'circuit_breaker') is still open.
//     Sent once per trip, keyed on the trip's opened_at; a re-arm
//     followed by a new trip is a new opened_at and mails again.
//     The breaker re-arms itself after its cooldown, so this mail
//     is a "look now" notice, not a request to intervene.
final class AlertChecker
{
    private PDO $pdo;

    public function __construct(PDO $pdo)
    {
        $this->pdo = $pdo;
    }

    public function check(): array
    {
        $summary = [
            'checked_at' => gmdate('c'),
            'mail_configured' => Mailer::configured(),
            'critical_bans_alerted' => [],
            'critical_bans_skipped_already_sent' => 0,
            'wave' => [
                'events_in_window' => 0,
                'threshold' => $this->waveThreshold(),
                'window_minutes' => $this->waveWindowMinutes(),
                'alert_sent' => false,
                'throttled' => false,
                'reason' => '',
            ],
            'circuit_breaker' => [
                'open' => false,
                'opened_at' => null,
                'bans_in_window' => 0,
                'alert_sent' => false,
                'reason' => '',
            ],
        ];

        foreach ($this->criticalBansNeedingAlert() as $ban) {
            $key = 'critical_ban:' . $ban['id'];
            if ($this->stateGet($key) !== null) {
                $summary['critical_bans_skipped_already_sent']++;
                continue;
            }
            $result = Mailer::send(
                '[logbanner] Critical ban: ' . $ban['ip'],
                "A critical ban was created.\n\n" .
                'IP: ' . $ban['ip'] . "\n" .
                'Rule: ' . ($ban['rule_name'] ?? '(none)') . "\n" .
                'Reason: ' . $ban['reason'] . "\n" .
                'Created: ' . $ban['created_at'] . "\n" .
                'Dry run: ' . ($ban['dry_run'] ? 'yes (simulated, not enforced)' : 'no') . "\n"
            );
            if ($result['sent']) {
                $this->stateSet($key, 'sent');
                $summary['critical_bans_alerted'][] = $ban['id'];
            } else {
                $summary['critical_bans_alerted_error'] = $result['reason'];
            }
        }

        $count = $this->eventsInWaveWindow();
        $summary['wave']['events_in_window'] = $count;
        if ($count >= $this->waveThreshold()) {
            $lastSent = $this->stateGet('wave_alert_last_sent');
            $throttleSeconds = $this->waveThrottleMinutes() * 60;
            if ($lastSent !== null && (time() - strtotime($lastSent)) < $throttleSeconds) {
                $summary['wave']['throttled'] = true;
                $summary['wave']['reason'] = 'Wave alert already sent at ' . $lastSent .
                    '; throttled to at most one per ' . $this->waveThrottleMinutes() . ' minutes';
            } else {
                $result = Mailer::send(
                    '[logbanner] Attack wave: ' . $count . ' detections in ' .
                    $this->waveWindowMinutes() . ' minutes',
                    $count . ' detections were recorded in the last ' .
                    $this->waveWindowMinutes() . " minutes (threshold " .
                    $this->waveThreshold() . ").\n\n" .
                    "Check the reports page for the top IPs and rules.\n"
                );
                if ($result['sent']) {
                    $this->stateSet('wave_alert_last_sent', gmdate('c'));
                    $summary['wave']['alert_sent'] = true;
                } else {
                    $summary['wave']['reason'] = $result['reason'];
                }
            }
        }

        // Circuit breaker: the latest breaker event is the current
        // state — an open event with no later re-arm means auto-bans
        // are still paused. No time bound: an open breaker is a
        // current condition, not a past event, and the per-trip
        // dedup key below is what stops repeat mails.
        $breaker = $this->latestCircuitBreakerEvent();
        if ($breaker !== null && ($breaker['state'] ?? null) === 'open') {
            $openedAt = $breaker['opened_at'] ?? $breaker['occurred_at'];
            $summary['circuit_breaker']['open'] = true;
            $summary['circuit_breaker']['opened_at'] = $openedAt;
            $summary['circuit_breaker']['bans_in_window'] = (int) ($breaker['bans_in_window'] ?? 0);
            $key = 'circuit_breaker:' . $openedAt;
            if ($this->stateGet($key) !== null) {
                $summary['circuit_breaker']['reason'] = 'Already alerted for the trip at ' . $openedAt;
            } else {
                $result = Mailer::send(
                    '[logbanner] Circuit breaker open: ' . $breaker['bans_in_window'] .
                    ' auto-bans in ' . $breaker['window_seconds'] . ' seconds',
                    'The circuit breaker tripped at ' . $openedAt . ".\n\n" .
                    'Auto-bans in window: ' . $breaker['bans_in_window'] .
                    ' (max ' . $breaker['max_bans'] . ' in ' . $breaker['window_seconds'] . " seconds).\n" .
                    "Automatic banning is paused while the breaker is open; detections are still recorded.\n" .
                    "Manual bans by an admin still work.\n" .
                    'The breaker re-arms itself after its cooldown (' . $breaker['cooldown_seconds'] .
                    " seconds); check the dashboard for the current state.\n"
                );
                if ($result['sent']) {
                    $this->stateSet($key, 'sent');
                    $summary['circuit_breaker']['alert_sent'] = true;
                } else {
                    $summary['circuit_breaker']['reason'] = $result['reason'];
                }
            }
        }

        return $summary;
    }

    // Bans from the last hour with a matching critical event. The
    // one-hour lookback bounds the scan; older bans were either
    // already alerted on an earlier check or predate alerting.
    private function criticalBansNeedingAlert(): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT b.id, host(b.ip) AS ip, b.reason, b.dry_run, b.created_at, r.name AS rule_name ' .
            'FROM bans b LEFT JOIN rules r ON r.id = b.rule_id ' .
            'WHERE b.created_at >= now() - interval \'1 hour\' ' .
            'AND EXISTS (SELECT 1 FROM events e ' .
            'WHERE e.ip = b.ip AND e.severity = \'critical\' ' .
            'AND e.occurred_at <= b.created_at ' .
            'AND e.occurred_at >= b.created_at - interval \'1 hour\' ' .
            'AND (b.rule_id IS NULL OR e.rule_id = b.rule_id)) ' .
            'ORDER BY b.created_at ASC'
        );
        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    // Latest breaker event, with its raw JSON decoded: the current
    // breaker state. Returns null when the agent has never tripped
    // (no stage 8 event recorded yet).
    private function latestCircuitBreakerEvent(): ?array
    {
        $stmt = $this->pdo->prepare(
            'SELECT occurred_at, raw FROM events ' .
            'WHERE source = \'agent\' AND raw->>\'type\' = \'circuit_breaker\' ' .
            'ORDER BY occurred_at DESC LIMIT 1'
        );
        $stmt->execute();
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($row === false) {
            return null;
        }
        $raw = json_decode((string) $row['raw'], true);
        if (!is_array($raw)) {
            return null;
        }
        $raw['occurred_at'] = $row['occurred_at'];
        return $raw;
    }

    private function eventsInWaveWindow(): int
    {
        $stmt = $this->pdo->prepare(
            'SELECT count(*) FROM events WHERE occurred_at >= now() - make_interval(mins => :mins) ' .
            'AND occurred_at <= now()'
        );
        $stmt->execute([':mins' => $this->waveWindowMinutes()]);
        return (int) $stmt->fetchColumn();
    }

    private function waveThreshold(): int
    {
        $value = (int) (getenv('ALERT_WAVE_THRESHOLD') ?: 50);
        return $value > 0 ? $value : 50;
    }

    private function waveWindowMinutes(): int
    {
        $value = (int) (getenv('ALERT_WAVE_WINDOW_MINUTES') ?: 10);
        return $value > 0 ? $value : 10;
    }

    private function waveThrottleMinutes(): int
    {
        $value = (int) (getenv('ALERT_WAVE_THROTTLE_MINUTES') ?: 60);
        return $value > 0 ? $value : 60;
    }

    private function stateGet(string $key): ?string
    {
        $stmt = $this->pdo->prepare('SELECT value FROM alert_state WHERE key = :key');
        $stmt->execute([':key' => $key]);
        $value = $stmt->fetchColumn();
        return $value === false ? null : (string) $value;
    }

    private function stateSet(string $key, string $value): void
    {
        $stmt = $this->pdo->prepare(
            'INSERT INTO alert_state (key, value, updated_at) VALUES (:key, :value, now()) ' .
            'ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()'
        );
        $stmt->execute([':key' => $key, ':value' => $value]);
    }
}
