<?php

declare(strict_types=1);

namespace Logbanner\Admin;

use PDO;

// Writes rows to audit_logs and resolves the acting user for them.
//
// The admin service never authenticates a user itself: it trusts the
// shared SERVICE_TOKEN (checked in public/index.php) plus, when the
// gateway calls on behalf of a logged-in user, the X-User-Id and
// X-User-Role headers the gateway forwards. Those headers are only
// meaningful alongside a valid service token, so an unauthenticated
// caller cannot invent an actor by sending them alone. An id that is
// not a UUID, or not a row in users, is never written to the
// actor_id column (it would break the foreign key); it is kept in
// the details JSON instead, so the audit trail still says who the
// gateway claimed the actor was.
final class Audit
{
    public static function actorId(PDO $pdo): ?string
    {
        $id = $_SERVER['HTTP_X_USER_ID'] ?? '';
        if (!is_string($id) || !preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i', $id)) {
            return null;
        }
        $stmt = $pdo->prepare('SELECT id FROM users WHERE id = :id');
        $stmt->execute([':id' => $id]);
        return $stmt->fetchColumn() !== false ? $id : null;
    }

    public static function forwardedUserId(): ?string
    {
        $id = $_SERVER['HTTP_X_USER_ID'] ?? '';
        return is_string($id) && $id !== '' ? $id : null;
    }

    public static function forwardedUserRole(): ?string
    {
        $role = $_SERVER['HTTP_X_USER_ROLE'] ?? '';
        return is_string($role) && $role !== '' ? $role : null;
    }

    public static function write(
        PDO $pdo,
        ?string $actorId,
        string $action,
        string $targetType,
        ?string $targetId,
        array $details
    ): void {
        $forwarded = self::forwardedUserId();
        if ($forwarded !== null && $forwarded !== $actorId) {
            $details['forwarded_user_id'] = $forwarded;
        }
        $role = self::forwardedUserRole();
        if ($role !== null) {
            $details['forwarded_user_role'] = $role;
        }
        $stmt = $pdo->prepare(
            'INSERT INTO audit_logs (actor_id, action, target_type, target_id, details) ' .
            'VALUES (:actor_id, :action, :target_type, :target_id, :details::jsonb)'
        );
        $stmt->execute([
            ':actor_id' => $actorId,
            ':action' => $action,
            ':target_type' => $targetType,
            ':target_id' => $targetId,
            ':details' => json_encode($details, JSON_THROW_ON_ERROR),
        ]);
    }
}
