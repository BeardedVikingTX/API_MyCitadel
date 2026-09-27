<?php
/* ============================================================================
 * ███ USERS/PROFILE_UPDATE.PHP ███
 * Route : POST /v1/users/profile_update
 * Body  : Any subset of editable fields
 *
 * Generic, data-driven updater. Every field is validated by
 * citadel_profile_validate() before being written.
 *
 * IDOR-proof: writes are ALWAYS scoped to citadel_current_user_id().
 * You cannot update another user's profile, no matter what you send.
 * ========================================================================== */

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';
require_once CITADEL_CONFIG . '/db.php';
require_once CITADEL_CONFIG . '/crypto.php';
require_once CITADEL_CONFIG . '/profile.php';

citadel_rate_limit('profile_update', 30, 60);
citadel_require_csrf();
citadel_require_auth('json');

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    header('Allow: POST');
    citadel_json_error('method_not_allowed', 'POST only.', 405);
}

$me   = (int) citadel_current_user_id();
$body = citadel_input_json();

if (empty($body)) {
    citadel_json_error('no_changes', 'No fields provided.', 400);
}

$fields = citadel_profile_fields();

// ── Build the update list ─────────────────────────────────────────────────
$setClauses = [];
$params     = [];
$updatedKeys = [];

// PII fields are encrypted — map field name → [ct_col, nonce_col]
$piiFields = ['first_name', 'middle_name', 'last_name', 'phone',
              'backup_email', 'recovery_phone', 'birthday',
              'address_line1', 'address_line2', 'city', 'zip'];

foreach ($body as $name => $value) {

    // Ignore unknown fields silently (avoid leaking schema info)
    if (!isset($fields[$name])) {
        continue;
    }

    // Visibility handled separately (own endpoint already exists)
    // but we allow it here too
    if ($name === 'visibility') {
        if (!in_array($value, ['public','connections_only','hidden'], true)) {
            citadel_json_error('invalid_visibility', 'Invalid visibility value.', 400);
        }
        $setClauses[] = 'visibility = ?';
        $params[] = $value;
        $updatedKeys[] = $name;
        continue;
    }

    try {
        $normalized = citadel_profile_validate($name, $value, $fields[$name]);
    } catch (InvalidArgumentException $e) {
        citadel_json_error('invalid_field', $e->getMessage(), 400);
    }

    // ── PII: encrypt before storing ──────────────────────────────────────
    if (in_array($name, $piiFields, true)) {
        [$ct, $nonce] = citadel_profile_encrypt_pii($normalized, $me);
        $setClauses[] = "{$name}_ct = ?";
        $setClauses[] = "{$name}_nonce = ?";
        $params[] = $ct;
        $params[] = $nonce;
        $updatedKeys[] = $name;
        continue;
    }

    // ── Plain write ──────────────────────────────────────────────────────
    $setClauses[] = "{$name} = ?";
    $params[] = $normalized;
    $updatedKeys[] = $name;
}

if (empty($setClauses)) {
    citadel_json_error('no_changes', 'No valid fields to update.', 400);
}

// Always bump updated_at
$setClauses[] = 'updated_at = UTC_TIMESTAMP()';
$params[] = $me;

$sql = 'UPDATE user_profiles SET ' . implode(', ', $setClauses) . ' WHERE user_id = ?';

try {
    db_query($sql, $params);
} catch (Throwable $e) {
    citadel_log('api', 'error', 'Profile update failed', [
        'user_id' => $me,
        'fields'  => $updatedKeys,
        'error'   => $e->getMessage(),
    ]);
    citadel_json_error('update_failed', 'Could not update profile.', 500);
}

citadel_log('api', 'info', 'Profile updated', [
    'user_id' => $me,
    'fields'  => $updatedKeys,
]);

citadel_json_ok([
    'updated' => $updatedKeys,
    'message' => count($updatedKeys) . ' field(s) updated.',
]);