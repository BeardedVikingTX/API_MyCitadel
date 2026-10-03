<?php
declare(strict_types=1);
require_once __DIR__ . '/../bootstrap.php';
require_once CITADEL_CONFIG . '/db.php';
require_once CITADEL_CONFIG . '/messages.php';

citadel_rate_limit('msg_open', 30, 60);
citadel_require_csrf();
citadel_require_auth('json');

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    header('Allow: POST');
    citadel_json_error('method_not_allowed', 'POST only.', 405);
}

$me   = (int) citadel_current_user_id();
$body = citadel_input_json();
$to   = isset($body['to']) ? (int) $body['to'] : 0;

/* ══════════════════════════════════════════════════════════════════════
 * TIER LIMITS
 * --------------------------------------------------------------------------
 * Free users may start 1-on-1 conversations only. Group creation is a
 * Premium feature. The $is_group check below is a forward-compatible
 * gate: once group support lands, this branch already enforces the tier.
 * ========================================================================== */
$isPremium = ((int) db_scalar(
    'SELECT is_premium FROM users WHERE id = ? LIMIT 1',
    [$me]
)) === 1;

$isGroupRequest = !empty($body['is_group'])
    || !empty($body['participants'])
    || !empty($body['member_ids']);

if ($isGroupRequest && !$isPremium) {
    citadel_json_error('tier_limit_exceeded',
        'Creating group conversations is a Premium feature. ' .
            'Free users can start 1-on-1 conversations with their connections.',
        403);
}

if ($to <= 0 || $to === $me) {
    citadel_json_error('invalid_target', 'Valid target user required.', 400);
}

if (!citadel_msg_are_connected($me, $to)) {
    citadel_json_error('not_connected',
        'You must be connected to message this user.', 403);
}

try {
    $existing = citadel_msg_find_direct($me, $to);
    $convId   = citadel_msg_open_direct($me, $to);
} catch (Throwable $e) {
    citadel_json_error('open_failed', 'Could not open conversation.', 500);
}

citadel_log('api', 'info', 'Conversation opened', [
    'user_id'         => $me,
    'target_id'       => $to,
    'conversation_id' => $convId,
    'created'         => $existing === null,
    'tier'            => $isPremium ? 'premium' : 'free',
]);

citadel_json_ok([
    'conversation_id' => $convId,
    'created'         => $existing === null,
]);