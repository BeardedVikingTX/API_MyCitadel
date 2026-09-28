<?php
/* ============================================================================
 * ███ POSTS/CREATE.PHP ███
 * Route : POST /v1/posts/create
 * Body  : {
 *   "content": "text...",
 *   "visibility": "public|connections|private",
 *   "attachment_tokens": ["<32hex>", "..."]   ← optional, from /upload/media.php
 * }
 *
 * Awards +10 reputation on creation.
 * Bumps post_count and checks post_* badges.
 * Binds pending attachments (uploaded via /upload/media.php) to this post.
 * ========================================================================== */

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';
require_once CITADEL_CONFIG . '/db.php';
require_once CITADEL_CONFIG . '/posts.php';
require_once CITADEL_CONFIG . '/reputation.php';
require_once CITADEL_CONFIG . '/badges.php';
require_once CITADEL_CONFIG . '/attachments.php';

citadel_rate_limit('post_create', 30, 60);
citadel_require_csrf();
citadel_require_auth('json');

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    header('Allow: POST');
    citadel_json_error('method_not_allowed', 'POST only.', 405);
}

$me = (int) citadel_current_user_id();

/* ── Per-user rate limit ─────────────────────────────────────────────── */
if (citadel_post_recent_count($me) >= CITADEL_POST_RATE_LIMIT) {
    citadel_json_error('rate_limited',
        'You are posting too frequently. Try again later.', 429);
}

/* ── Parse input ─────────────────────────────────────────────────────── */
$contentRaw = citadel_input_string('content', null, CITADEL_POST_MAX_LENGTH * 2);
$content    = $contentRaw !== null ? citadel_post_sanitize($contentRaw) : '';

$visibility = citadel_input_string('visibility', 'connections', 16);
if (!in_array($visibility, ['public', 'connections', 'private'], true)) {
    citadel_json_error('invalid_visibility',
        'Visibility must be public, connections, or private.', 400);
}

/* ── Attachment tokens (optional) ────────────────────────────────────── */
$body             = citadel_input_json();
$attachmentTokens = [];
$rawTokens        = $body['attachment_tokens'] ?? null;

if (is_array($rawTokens)) {
    foreach (array_slice($rawTokens, 0, CITADEL_MEDIA_MAX_PER_POST) as $t) {
        if (is_string($t) && preg_match('/^[a-f0-9]{32}$/', $t)) {
            $attachmentTokens[] = $t;
        }
    }
}

/* ── Empty check: allow text OR attachments ──────────────────────────── */
if ($content === '' && empty($attachmentTokens)) {
    citadel_json_error('empty_content',
        'A post must have text or at least one attachment.', 400);
}

/* ── Verify the tokens actually belong to this user and are unbound ──── */
$ownedTokens = [];
if (!empty($attachmentTokens)) {
    $ph = implode(',', array_fill(0, count($attachmentTokens), '?'));
    $rows = db_all(
        "SELECT served_token
           FROM post_attachments
          WHERE served_token IN ($ph)
            AND user_id = ?
            AND post_id IS NULL
            AND comment_id IS NULL",
        array_merge($attachmentTokens, [$me])
    );
    $ownedTokens = array_map(static fn($r) => (string) $r['served_token'], $rows);

    if (count($ownedTokens) !== count($attachmentTokens)) {
        citadel_json_error('invalid_attachments',
            'One or more attachments are invalid or already used.', 400);
    }
}

/* ── Insert ──────────────────────────────────────────────────────────── */
try {
    $db = db();
    $db->beginTransaction();

    db_query(
        'INSERT INTO posts (user_id, content, visibility, created_at, updated_at)
         VALUES (?, ?, ?, UTC_TIMESTAMP(), UTC_TIMESTAMP())',
        [$me, $content, $visibility]
    );
    $postId = (int) db_last_id();

    /* Bind attachments to this post */
    if (!empty($ownedTokens)) {
        $ph = implode(',', array_fill(0, count($ownedTokens), '?'));
        db_query(
            "UPDATE post_attachments
                SET post_id = ?
              WHERE served_token IN ($ph)",
            array_merge([$postId], $ownedTokens)
        );
    }

    /* Bump post counter — this is what post_* badge thresholds read */
    bump_stat($me, 'post_count', 1);

    /* Award reputation */
    award_points($me, 'post_created', 10, 'post', $postId, 'Created a post');

    $db->commit();

} catch (Throwable $e) {
    if ($db->inTransaction()) {
        $db->rollBack();
    }
    citadel_log('api', 'error', 'Post creation failed', [
        'user_id' => $me,
        'error'   => $e->getMessage(),
    ]);
    citadel_json_error('create_failed', 'Could not create post.', 500);
}

citadel_log('api', 'info', 'Post created', [
    'post_id'     => $postId,
    'user_id'     => $me,
    'visibility'  => $visibility,
    'attachments' => count($ownedTokens),
]);

/* ── Badge check (outside the transaction, never blocks the post) ────── */
try {
    $newBadges = check_category_badges($me, 'post');
    if (!empty($newBadges)) {
        citadel_log('api', 'info', 'Post badges awarded', [
            'user_id' => $me,
            'badges'  => $newBadges,
        ]);
    }
} catch (Throwable $e) {
    citadel_log('api', 'warning', 'Post badge check failed (non-fatal)', [
        'user_id' => $me,
        'error'   => $e->getMessage(),
    ]);
}

/* ── Response ───────────────────────────────────────────────────────── */
citadel_json_ok([
    'post_id'     => $postId,
    'attachments' => count($ownedTokens),
    'message'     => 'Post created. +10 reputation.',
], 201);