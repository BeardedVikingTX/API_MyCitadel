<?php
/* ============================================================================
 * ███ PREMIUM/STATUS.PHP ███
 * Route : GET /v1/premium/status
 * Auth  : Required
 *
 * Returns the current user's premium status. Cheap lookup — the frontend
 * can call this on every page load.
 * ========================================================================== */

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';
require_once CITADEL_CONFIG . '/db.php';
require_once CITADEL_CONFIG . '/stripe.php';

citadel_rate_limit('premium_status', 60, 60);
citadel_require_auth('json');

$me = (int) citadel_current_user_id();

$status = citadel_stripe_get_status($me);

citadel_json_ok([
    'premium' => $status,
]);