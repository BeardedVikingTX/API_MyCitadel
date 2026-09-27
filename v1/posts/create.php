<?php
/* ============================================================================
 * ███ POSTS/CREATE.PHP ███
 * Route : POST /v1/posts/create
 * Body  : { "content": "...", "visibility": "public|connections|private" }
 *
 * Awards +10 reputation on creation.
 * Rate-limited per user (20 posts/hour).
 * ========================================================================== */

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';
require_once CITADEL_CONFIG . '/db.php';
require_once CITADEL_CONFIG . '/posts.php';
require_once CITADEL_CONFIG . '/reputation.php';

citadel_rate_limit('post_create', 30, 60);
citadel_require_csrf();
citadel_require_auth('json');

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    header('Allow: POST');
    citadel_json_error('method_not_allowed', 'POST only.', 405);
}

$me = (int) citadel_current_user_id();

// ── Per-user rate limit ──────────────────────────────────────────────────
if (citadel_post_recent_count($me) >= CITADEL_POST_RATE_LIMIT) {
    citadel_json_error('rate_limited',
        'You are posting too frequently. Try again later.', 429);
}

// ── Parse input ──────────────────────────────────────────────────────────
$contentRaw = citadel_input_string('content', null, CITADEL_POST_MAX_LENGTH * 2);
if ($contentRaw === null || trim($contentRaw) === '') {
    citadel_json_error('empty_content', 'Post content cannot be empty.', 400);
}

$content = citadel_post_sanitize($contentRaw);
if ($content === '') {
    citadel_json_error('empty_content', 'Post content cannot be empty.', 400);
}

$visibility = citadel_input_string('visibility', 'connections', 16);
if (!in_array($visibility, ['public', 'connections', 'private'], true)) {
    citadel_json_error('invalid_visibility',
        'Visibility must be public, connections, or private.', 400);
}

// ── Insert ───────────────────────────────────────────────────────────────
try {
    $db = db();
    $db->beginTransaction();

    db_query(
        'INSERT INTO posts (user_id, content, visibility, created_at, updated_at)
         VALUES (?, ?, ?, UTC_TIMESTAMP(), UTC_TIMESTAMP())',
        [$me, $content, $visibility]
    );
    $postId = db_last_id();

    // Award reputation (+10)
    award_points($me, 'post_created', 10, 'post', $postId, 'Created a post');

    $db->commit();

} catch (Throwable $e) {
    if (db()->inTransaction()) db()->rollBack();
    citadel_log('api', 'error', 'Post creation failed', [
        'user_id' => $me, 'error' => $e->getMessage(),
    ]);
    citadel_json_error('create_failed', 'Could not create post.', 500);
}

citadel_log('api', 'info', 'Post created', [
    'post_id' => $postId, 'user_id' => $me, 'visibility' => $visibility,
]);

citadel_json_ok([
    'post_id' => $postId,
    'message' => 'Post created. +10 reputation.',
], 201);