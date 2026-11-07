<?php

declare(strict_types=1);

namespace Logbanner\Admin\Controllers;

use Logbanner\Admin\Audit;
use Logbanner\Admin\Database;
use PDO;

final class ListsController
{
    public function index(array $query): void
    {
        $kind = $query['kind'] ?? '';
        if ($kind !== '' && $kind !== 'whitelist' && $kind !== 'blacklist') {
            $this->json(400, ['error' => ['message' => 'kind must be whitelist or blacklist']]);
            return;
        }
        $pdo = Database::connect();
        if ($kind === '') {
            $stmt = $pdo->query(
                'SELECT id, kind, value, reason, created_by, created_at ' .
                'FROM manual_lists ORDER BY kind, created_at DESC'
            );
        } else {
            $stmt = $pdo->prepare(
                'SELECT id, kind, value, reason, created_by, created_at ' .
                'FROM manual_lists WHERE kind = :kind ORDER BY created_at DESC'
            );
            $stmt->execute([':kind' => $kind]);
        }
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
        $this->json(200, ['lists' => $rows]);
    }

    public function create(array $body): void
    {
        $kind = $body['kind'] ?? '';
        $value = trim((string) ($body['value'] ?? ''));
        $reason = trim((string) ($body['reason'] ?? ''));

        if ($kind !== 'whitelist' && $kind !== 'blacklist') {
            $this->json(400, ['error' => ['message' => 'kind must be whitelist or blacklist']]);
            return;
        }
        $error = $this->validateValue($value);
        if ($error !== null) {
            $this->json(400, ['error' => ['message' => $error]]);
            return;
        }
        if (mb_strlen($reason) > 500) {
            $this->json(400, ['error' => ['message' => 'reason must be at most 500 characters']]);
            return;
        }

        $pdo = Database::connect();
        $actorId = Audit::actorId($pdo);
        $stmt = $pdo->prepare(
            'INSERT INTO manual_lists (kind, value, reason, created_by) ' .
            'VALUES (:kind, :value, :reason, :created_by) ' .
            'RETURNING id, kind, value, reason, created_by, created_at'
        );
        try {
            $stmt->execute([
                ':kind' => $kind,
                ':value' => $value,
                ':reason' => $reason,
                ':created_by' => $actorId,
            ]);
        } catch (\PDOException $e) {
            if ($e->getCode() === '23505') {
                $this->json(409, ['error' => ['message' => 'That entry already exists']]);
                return;
            }
            throw $e;
        }
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        Audit::write($pdo, $actorId, 'list.create', 'manual_list', (string) $row['id'], [
            'kind' => $row['kind'],
            'value' => $row['value'],
            'reason' => $row['reason'],
        ]);
        $this->json(201, ['entry' => $row]);
    }

    public function delete(string $id): void
    {
        if (!preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i', $id)) {
            $this->json(400, ['error' => ['message' => 'id must be a UUID']]);
            return;
        }
        $pdo = Database::connect();
        $stmt = $pdo->prepare(
            'DELETE FROM manual_lists WHERE id = :id ' .
            'RETURNING id, kind, value, reason, created_at'
        );
        $stmt->execute([':id' => $id]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($row === false) {
            $this->json(404, ['error' => ['message' => 'List entry not found']]);
            return;
        }
        Audit::write($pdo, Audit::actorId($pdo), 'list.delete', 'manual_list', (string) $row['id'], [
            'kind' => $row['kind'],
            'value' => $row['value'],
            'reason' => $row['reason'],
        ]);
        $this->json(200, ['entry' => $row]);
    }

    // Import one entry per line. Body is plain text or CSV: each line
    // is `value` or `value,reason` (CSV quoting rules apply, so a
    // reason may contain a comma when quoted). kind comes from the
    // ?kind= query parameter and applies to every line. A bad line
    // is reported with its line number and skipped; a duplicate is
    // counted and skipped; the import never fails as a whole because
    // of one bad line.
    public function import(array $query, string $rawBody): void
    {
        $kind = $query['kind'] ?? '';
        if ($kind !== 'whitelist' && $kind !== 'blacklist') {
            $this->json(400, [
                'error' => ['message' => 'kind query parameter must be whitelist or blacklist'],
            ]);
            return;
        }
        $trimmed = ltrim($rawBody);
        if (str_starts_with($trimmed, '{') || str_starts_with($trimmed, '[')) {
            $this->json(400, [
                'error' => ['message' => 'Import body must be plain text or CSV, one entry per line, not JSON'],
            ]);
            return;
        }

        $pdo = Database::connect();
        $actorId = Audit::actorId($pdo);
        $insert = $pdo->prepare(
            'INSERT INTO manual_lists (kind, value, reason, created_by) ' .
            'VALUES (:kind, :value, :reason, :created_by)'
        );
        $imported = 0;
        $skippedDuplicates = 0;
        $errors = [];
        $errorLines = [];
        foreach (explode("\n", $rawBody) as $index => $line) {
            $lineNo = $index + 1;
            $line = trim($line, " \t\r");
            if ($line === '') {
                continue;
            }
            $fields = str_getcsv($line);
            if (count($fields) > 2) {
                $errors[] = [
                    'line' => $lineNo,
                    'value' => $line,
                    'message' => 'Expected "value" or "value,reason"',
                ];
                $errorLines[] = $lineNo;
                continue;
            }
            $value = trim((string) $fields[0]);
            $reason = trim((string) ($fields[1] ?? ''));
            $error = $this->validateValue($value);
            if ($error === null && mb_strlen($reason) > 500) {
                $error = 'reason must be at most 500 characters';
            }
            if ($error !== null) {
                $errors[] = ['line' => $lineNo, 'value' => $value, 'message' => $error];
                $errorLines[] = $lineNo;
                continue;
            }
            try {
                $insert->execute([
                    ':kind' => $kind,
                    ':value' => $value,
                    ':reason' => $reason,
                    ':created_by' => $actorId,
                ]);
                $imported++;
            } catch (\PDOException $e) {
                if ($e->getCode() === '23505') {
                    $skippedDuplicates++;
                    continue;
                }
                throw $e;
            }
        }
        Audit::write($pdo, $actorId, 'list.import', 'manual_list', null, [
            'kind' => $kind,
            'imported' => $imported,
            'skipped_duplicates' => $skippedDuplicates,
            'error_count' => count($errors),
            'error_lines' => $errorLines,
        ]);
        $this->json(200, [
            'kind' => $kind,
            'imported' => $imported,
            'skipped_duplicates' => $skippedDuplicates,
            'errors' => $errors,
        ]);
    }

    // CSV download of the current entries, written with fputcsv so
    // values containing commas or quotes are escaped properly.
    public function export(array $query): void
    {
        $kind = $query['kind'] ?? '';
        if ($kind !== '' && $kind !== 'whitelist' && $kind !== 'blacklist') {
            $this->json(400, ['error' => ['message' => 'kind must be whitelist or blacklist']]);
            return;
        }
        $pdo = Database::connect();
        if ($kind === '') {
            $stmt = $pdo->query(
                'SELECT kind, value, reason, created_at FROM manual_lists ORDER BY kind, created_at DESC'
            );
        } else {
            $stmt = $pdo->prepare(
                'SELECT kind, value, reason, created_at FROM manual_lists ' .
                'WHERE kind = :kind ORDER BY created_at DESC'
            );
            $stmt->execute([':kind' => $kind]);
        }
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
        $filename = 'logbanner-lists' . ($kind !== '' ? '-' . $kind : '') . '.csv';
        header('Content-Type: text/csv; charset=utf-8');
        header('Content-Disposition: attachment; filename="' . $filename . '"');
        $out = fopen('php://output', 'w');
        fputcsv($out, ['kind', 'value', 'reason', 'created_at']);
        foreach ($rows as $row) {
            fputcsv($out, [$row['kind'], $row['value'], $row['reason'], $row['created_at']]);
        }
        fclose($out);
    }

    private function validateValue(string $value): ?string
    {
        if ($value === '') {
            return 'value must not be empty';
        }
        if (!$this->isIpOrCidr($value)) {
            return 'value must be an IP address or CIDR range';
        }
        return null;
    }

    private function isIpOrCidr(string $value): bool
    {
        if (filter_var($value, FILTER_VALIDATE_IP) !== false) {
            return true;
        }
        $parts = explode('/', $value, 2);
        if (count($parts) !== 2) {
            return false;
        }
        [$ip, $prefix] = $parts;
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
            return ctype_digit($prefix) && (int) $prefix >= 0 && (int) $prefix <= 32;
        }
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
            return ctype_digit($prefix) && (int) $prefix >= 0 && (int) $prefix <= 128;
        }
        return false;
    }

    private function json(int $status, array $payload): void
    {
        http_response_code($status);
        header('Content-Type: application/json');
        echo json_encode($payload, JSON_THROW_ON_ERROR);
    }
}
