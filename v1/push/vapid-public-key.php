<?php
/* ============================================================================
 * ███ PUSH/VAPID-PUBLIC-KEY.PHP ███
 * Route : GET /v1/push/vapid-public-key
 * Auth  : None (public — the key is not a secret)
 *
 * Returns the VAPID public key for the frontend to use when subscribing.
 * The public key is safe to expose — the private half stays on the server.
 * ========================================================================== */

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';
require_once CITADEL_CONFIG . '/push.php';

citadel_rate_limit('push_vapid', 120, 60);

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'GET') {
    header('Allow: GET');
    citadel_json_error('method_not_allowed', 'GET only.', 405);
}

try {
    $key = citadel_push_public_key_b64();
} catch (Throwable $e) {
    citadel_log('push', 'error', 'Could not load VAPID public key', [
        'error' => $e->getMessage(),
    ]);
    citadel_json_error('unavailable',
        'Push notifications are not currently available.', 503);
}

// Long cache — the key rotates rarely, and browsers cache it anyway
header('Cache-Control: public, max-age=86400');

citadel_json_ok([
    'public_key' => $key,
]);