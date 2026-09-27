<?php
/* ============================================================================
 * ███ PUSH/SUBSCRIBE.PHP ███
 * Route : POST /v1/push/subscribe
 * Auth  : Required
 * CSRF  : Required
 * Rate  : 10 per minute per IP
 *
 * WHAT IT DOES
 *   Stores a browser's push subscription. Called from the frontend after
 *   the user grants Notification permission and the browser returns a
 *   PushSubscription object.
 *
 * SECURITY
 *   • Endpoint URL is validated against a strict push-service allowlist
 *     (SSRF defense)
 *   • p256dh and auth keys are validated for correct lengths and format
 *   • Subscription is tied to the authenticated user
 *   • Duplicate endpoints are upserted (re-subscribing is idempotent)
 * ========================================================================== */

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';
require_once CITADEL_CONFIG . '/db.php';
require_once CITADEL_CONFIG . '/push.php';

citadel_rate_limit('push_subscribe', 10, 60);
citadel_require_csrf();
citadel_require_auth('json');

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    header('Allow: POST');
    citadel_json_error('method_not_allowed', 'POST only.', 405);
}

$me   = (int) citadel_current_user_id();
$body = citadel_input_json();

// ── Required fields ─────────────────────────────────────────────────────
$endpoint = isset($body['endpoint']) && is_string($body['endpoint']) ? $body['endpoint'] : null;
$p256dh   = isset($body['keys']['p256dh']) && is_string($body['keys']['p256dh']) ? $body['keys']['p256dh'] : null;
$auth     = isset($body['keys']['auth'])   && is_string($body['keys']['auth'])   ? $body['keys']['auth']   : null;

if (!$endpoint || !$p256dh || !$auth) {
    citadel_json_error('missing_fields',
        'endpoint, keys.p256dh, and keys.auth are required.', 400);
}

// ── Validate ─────────────────────────────────────────────────────────────
try {
    citadel_push_validate_endpoint($endpoint);
    citadel_push_validate_keys($p256dh, $auth);
} catch (InvalidArgumentException $e) {
    citadel_log('push', 'warning', 'Invalid push subscription rejected', [
        'user_id' => $me,
        'reason'  => $e->getMessage(),
    ]);
    citadel_json_error('invalid_subscription',
        'Invalid push subscription.', 400);
}

// ── Upsert ───────────────────────────────────────────────────────────────
$endpointHash = hash('sha256', $endpoint);

$uaHash = null;
if (!empty($_SERVER['HTTP_USER_AGENT'])) {
    $uaHash = substr(hash_hmac(
        'sha256',
        $_SERVER['HTTP_USER_AGENT'],
        $GLOBALS['citadel_fingerprint_key'] ?? 'fallback'
    ), 0, 16);
}

try {
    db_query(
        'INSERT INTO push_subscriptions
            (user_id, endpoint_hash, endpoint, p256dh, auth_token, user_agent_hash, is_active)
         VALUES (?, ?, ?, ?, ?, ?, 1)
         ON DUPLICATE KEY UPDATE
            user_id         = VALUES(user_id),
            endpoint        = VALUES(endpoint),
            p256dh          = VALUES(p256dh),
            auth_token      = VALUES(auth_token),
            user_agent_hash = VALUES(user_agent_hash),
            is_active       = 1,
            last_error      = NULL,
            error_count     = 0',
        [$me, $endpointHash, $endpoint, $p256dh, $auth, $uaHash]
    );

    citadel_log('push', 'info', 'Push subscription registered', [
        'user_id'       => $me,
        'endpoint_hash' => substr($endpointHash, 0, 12),
    ]);

} catch (Throwable $e) {
    citadel_log('push', 'error', 'Push subscribe failed', [
        'user_id' => $me,
        'error'   => $e->getMessage(),
    ]);
    citadel_json_error('subscribe_failed',
        'Could not register push subscription.', 500);
}

citadel_json_ok([
    'message' => 'Push subscription registered.',
]);