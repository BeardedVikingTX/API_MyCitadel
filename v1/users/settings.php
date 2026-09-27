<?php
/* ============================================================================
 * ███ USERS/SETTINGS.PHP ███
 * MyCitadel — Privacy & Visibility Settings
 * ----------------------------------------------------------------------------
 * Route : POST /v1/users/settings
 * Auth  : Required
 * CSRF  : Required
 *
 * ────────────────────────────────────────────────────────────────────────────
 * VISIBILITY OPTIONS
 * ────────────────────────────────────────────────────────────────────────────
 *   public            → appears in directory, anyone can view limited card
 *   connections_only  → hidden from directory, connections see full profile
 *   hidden            → invisible to everyone except self (the "Hide Me" mode)
 *
 * ────────────────────────────────────────────────────────────────────────────
 * BODY
 * ────────────────────────────────────────────────────────────────────────────
 *   {
 *     "visibility": "public" | "connections_only" | "hidden",
 *     "privacy_toggles": {
 *       "show_email": true,
 *       "show_phone": false,
 *       ...
 *     }
 *   }
 *
 * Both fields are optional. Only provided fields are updated.
 * ========================================================================== */

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';
require_once CITADEL_CONFIG . '/db.php';

citadel_rate_limit('users_settings', 30, 60);
citadel_require_csrf();
citadel_require_auth('json');

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    header('Allow: POST');
    citadel_json_error('method_not_allowed', 'POST only.', 405);
}

$me   = (int) citadel_current_user_id();
$body = citadel_input_json();

$updates = [];

// ── Visibility ────────────────────────────────────────────────────────────
if (isset($body['visibility'])) {
    $vis = $body['visibility'];
    if (!is_string($vis) || !in_array($vis, ['public', 'connections_only', 'hidden'], true)) {
        citadel_json_error('invalid_visibility',
            'visibility must be public, connections_only, or hidden.', 400);
    }
    $updates['visibility'] = $vis;
}

// ── Privacy toggles ───────────────────────────────────────────────────────
$allowedToggles = [
    'show_email', 'show_phone', 'show_location', 'show_birthday',
    'show_real_name', 'show_social_links', 'show_premium',
];

if (isset($body['privacy_toggles']) && is_array($body['privacy_toggles'])) {
    foreach ($body['privacy_toggles'] as $key => $value) {
        if (!in_array($key, $allowedToggles, true)) continue;
        $updates[$key] = $value ? 1 : 0;
    }
}

if (empty($updates)) {
    citadel_json_error('no_changes', 'No settings to update.', 400);
}

// ── Build and run the UPDATE ──────────────────────────────────────────────
$setClauses = [];
$params     = [];
foreach ($updates as $col => $val) {
    $setClauses[] = "{$col} = ?";
    $params[]     = $val;
}
$setClauses[] = 'updated_at = UTC_TIMESTAMP()';
$params[]     = $me;

try {
    db_query(
        'UPDATE user_profiles SET ' . implode(', ', $setClauses) . ' WHERE user_id = ?',
        $params
    );

    citadel_log('api', 'info', 'User settings updated', [
        'user_id' => $me,
        'changes' => array_keys($updates),
    ]);

} catch (Throwable $e) {
    citadel_log('api', 'error', 'Settings update failed', [
        'user_id' => $me,
        'error'   => $e->getMessage(),
    ]);
    citadel_json_error('update_failed', 'Could not update settings.', 500);
}

// ── Return fresh state ────────────────────────────────────────────────────
$fresh = db_one(
    'SELECT visibility,
            show_email, show_phone, show_location, show_birthday,
            show_real_name, show_social_links, show_premium
       FROM user_profiles WHERE user_id = ? LIMIT 1',
    [$me]
);

citadel_json_ok([
    'settings' => [
        'visibility' => $fresh['visibility'],
        'privacy_toggles' => [
            'show_email'        => (bool) $fresh['show_email'],
            'show_phone'        => (bool) $fresh['show_phone'],
            'show_location'     => (bool) $fresh['show_location'],
            'show_birthday'     => (bool) $fresh['show_birthday'],
            'show_real_name'    => (bool) $fresh['show_real_name'],
            'show_social_links' => (bool) $fresh['show_social_links'],
            'show_premium'      => (bool) $fresh['show_premium'],
        ],
    ],
]);