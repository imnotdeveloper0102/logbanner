<?php

declare(strict_types=1);

namespace Logbanner\Admin;

use PDO;
use PDOException;

final class Database
{
    public static function connect(): PDO
    {
        $url = getenv('DATABASE_URL');
        if ($url === false || $url === '') {
            throw new PDOException('DATABASE_URL is not set');
        }
        $parts = parse_url($url);
        if ($parts === false || !isset($parts['host'], $parts['path'])) {
            throw new PDOException('DATABASE_URL is not a valid Postgres URL');
        }
        $dsn = sprintf(
            'pgsql:host=%s;port=%d;dbname=%s',
            $parts['host'],
            $parts['port'] ?? 5432,
            ltrim($parts['path'], '/')
        );
        $pdo = new PDO(
            $dsn,
            $parts['user'] ?? '',
            $parts['pass'] ?? '',
            [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
        );
        return $pdo;
    }
}
