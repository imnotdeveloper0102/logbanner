<?php

declare(strict_types=1);

// Front controller for the admin service. Stage 7: full manual
// whitelist/blacklist management (including import/export), daily
// and weekly reports (JSON, CSV, PDF), and the alert check.
//
// Authentication: every /api/* route requires the shared
// X-Service-Token. When the gateway calls on behalf of a logged-in
// user it also forwards X-User-Id and X-User-Role; those headers
// are only trusted alongside a valid service token (see
// Logbanner\Admin\Audit), never from an unauthenticated caller.

require __DIR__ . '/../vendor/autoload.php';

use Logbanner\Admin\Controllers\AlertsController;
use Logbanner\Admin\Controllers\ListsController;
use Logbanner\Admin\Controllers\ReportsController;

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);

function jsonResponse(int $status, array $payload): void
{
    http_response_code($status);
    header('Content-Type: application/json');
    echo json_encode($payload, JSON_THROW_ON_ERROR);
}

function requireServiceToken(): bool
{
    $expected = getenv('SERVICE_TOKEN');
    if ($expected === false || $expected === '') {
        jsonResponse(500, ['error' => ['message' => 'SERVICE_TOKEN is not configured']]);
        return false;
    }
    $given = $_SERVER['HTTP_X_SERVICE_TOKEN'] ?? '';
    if (!hash_equals($expected, $given)) {
        jsonResponse(403, ['error' => ['message' => 'Invalid service token']]);
        return false;
    }
    return true;
}

function queryParams(): array
{
    $query = [];
    parse_str($_SERVER['QUERY_STRING'] ?? '', $query);
    return $query;
}

try {
    if ($method === 'GET' && $path === '/health') {
        jsonResponse(200, ['status' => 'ok']);
        exit;
    }

    if (str_starts_with($path, '/api/')) {
        if (!requireServiceToken()) {
            exit;
        }

        if ($path === '/api/lists') {
            $controller = new ListsController();
            if ($method === 'GET') {
                $controller->index(queryParams());
                exit;
            }
            if ($method === 'POST') {
                $body = json_decode(file_get_contents('php://input'), true);
                if (!is_array($body)) {
                    jsonResponse(400, ['error' => ['message' => 'Request body must be JSON']]);
                    exit;
                }
                $controller->create($body);
                exit;
            }
        }

        if ($path === '/api/lists/import' && $method === 'POST') {
            (new ListsController())->import(queryParams(), (string) file_get_contents('php://input'));
            exit;
        }

        if ($path === '/api/lists/export' && $method === 'GET') {
            (new ListsController())->export(queryParams());
            exit;
        }

        if (preg_match('#^/api/lists/([^/]+)$#', $path, $matches) && $method === 'DELETE') {
            (new ListsController())->delete($matches[1]);
            exit;
        }

        if ($path === '/api/reports/daily' && $method === 'GET') {
            (new ReportsController())->daily(queryParams());
            exit;
        }

        if ($path === '/api/reports/weekly' && $method === 'GET') {
            (new ReportsController())->weekly(queryParams());
            exit;
        }

        if ($path === '/api/alerts/check' && $method === 'POST') {
            (new AlertsController())->check();
            exit;
        }
    }

    jsonResponse(404, ['error' => ['message' => 'Route not found']]);
} catch (Throwable $e) {
    error_log('admin-service error: ' . $e->getMessage());
    jsonResponse(500, ['error' => ['message' => 'Internal server error']]);
}
