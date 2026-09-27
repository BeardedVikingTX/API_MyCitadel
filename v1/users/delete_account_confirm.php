<?php
/* ============================================================================
 * ███ USERS/DELETE_ACCOUNT_CONFIRM.PHP ███
 * Route : POST /v1/users/delete_account_confirm
 * Body  : { "token": "..." }
 *
 * STEP 2 OF 2. Consumes the token and destroys the account.
 *
 * WHAT HAPPENS (in order):
 *   1. Validate + consume the token
 *   2. Adjust reputation for all connections (−25 each) + decrement counters
 *   3. Destroy media files (no-op until uploads ship)
 *   4. DELETE FROM users (FK cascade wipes everything else)
 *   5. Kill the session
 * ========================================================================== */

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';
require_once CITADEL_CONFIG . '/db.php';
require_once CITADEL_CONFIG . '/deletion.php';
require_once CITADEL_CONFIG . '/reputation.php';

citadel_rate_limit('delete_account_confirm', 10, 3600);
citadel_require_csrf();
citadel_require_auth('json');

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    header('Allow: POST');
    citadel_json_error('method_not_allowed', 'POST only.', 405);
}

$me    = (int) citadel_current_user_id();
$token = citadel_input_string('token', null, 128);

if ($token === null || !preg_match('/^[a-f0-9]{64}$/i', $token)) {
    citadel_json_error('invalid_token', 'Invalid or expired deletion link.', 400);
}

$tokenHash = hash('sha256', $token);
$db        = db();

$db->beginTransaction();

try {
    // ── 1. Atomically consume the token ─────────────────────────────────
    $stmt = $db->prepare(
        "UPDATE email_verification_tokens
            SET consumed_at = UTC_TIMESTAMP()
          WHERE token_hash = ?
            AND purpose = 'account_deletion'
            AND consumed_at IS NULL
            AND expires_at > UTC_TIMESTAMP()
            AND user_id = ?"
    );
    $stmt->execute([$tokenHash, $me]);

    if ($stmt->rowCount() !== 1) {
        $db->rollBack();
        citadel_json_error('invalid_token', 'Invalid or expired deletion link.', 400);
    }

    // ── 2. Adjust reputation for all connections ────────────────────────
    // Must happen BEFORE the user row is deleted, because after that the
    // relationship rows are cascade-deleted and we lose the info.
    $connectionsAdjusted = citadel_adjust_connections_on_delete($me);

    // ── 3. Destroy media (no-op for now) ────────────────────────────────
    $mediaDestroyed = citadel_destroy_user_media($me);

    // ── 4. Delete the user (FK cascade wipes everything else) ───────────
    // This removes: posts, comments, reactions, relationships, notifications,
    // push_subscriptions, email_verification_tokens, referrals, user_profiles,
    // user_stats, user_badges, reputation_ledger, username_history.
    db_query('DELETE FROM users WHERE id = ?', [$me]);

    $db->commit();

} catch (Throwable $e) {
    if ($db->inTransaction()) $db->rollBack();
    citadel_log('security', 'error', 'Account deletion failed', [
        'user_id' => $me, 'error' => $e->getMessage(),
    ]);
    citadel_json_error('internal_error', 'Could not delete account.', 500);
}

// ── 5. Kill the session ────────────────────────────────────────────────
try {
    citadel_session_destroy();
} catch (Throwable $e) {
    // Best-effort — the user row is already gone
}

citadel_log('security', 'info', 'Account destroyed', [
    'user_id'                 => $me,
    'connections_adjusted'    => $connectionsAdjusted,
    'media_destroyed'         => $mediaDestroyed,
]);

citadel_json_ok([
    'message' => 'Account permanently destroyed.',
]);