<?php
/* ============================================================================
 * ███ COMMENTS/CREATE.PHP ███
 * MyCitadel — Create Comment or Reply
 * ----------------------------------------------------------------------------
 * Route : POST /v1/comments/create
 * Body  : { "post_id": 5, "content": "...", "parent_id": 12 }
 *
 * `parent_id` is optional. When present, this is a reply to another comment
 * on the same post. Replies must target non-deleted comments on the same post.
 *
 * Reputation:
 *   Commenter: +5 (comment_given)
 *   Post author: +20 (comment_received)
 *
 * Notifications:
 *   Post author (unless self)
 *   Parent comment author (if reply, unless self or same as post author)
 * ========================================================================== */

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';
require_once CITADEL_CONFIG . '/db.php';
require_once CITADEL_CONFIG . '/posts.php';
require_once CITADEL_CONFIG . '/comments.php';
require_once CITADEL_CONFIG . '/reputation.php';

citadel_rate_limit('comment_create', 60, 60);
citadel_require_csrf();
citadel_require_auth('json');

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    header('Allow: POST');
    citadel_json_error('method_not_allowed', 'POST only.', 405);
}

$me = (int) citadel_current_user_id();

if (citadel_comment_recent_count($me) >= CITADEL_COMMENT_RATE_LIMIT) {
    citadel_json_error('rate_limited',
        'You are commenting too frequently. Try again later.', 429);
}

$postId     = citadel_input_int('post_id');
$parentId   = citadel_input_int('parent_id');   // optional
$contentRaw = citadel_input_string('content', null, CITADEL_COMMENT_MAX_LENGTH * 2);

if ($postId === null || $postId <= 0) {
    citadel_json_error('invalid_post', 'A valid post_id is required.', 400);
}
if ($contentRaw === null || trim($contentRaw) === '') {
    citadel_json_error('empty_content', 'Comment cannot be empty.', 400);
}

$content = citadel_comment_sanitize($contentRaw);
if ($content === '') {
    citadel_json_error('empty_content', 'Comment cannot be empty.', 400);
}

// ── Post must be visible ─────────────────────────────────────────────────
$post = db_one(CITADEL_POST_SELECT . ' WHERE p.id = ? LIMIT 1', [$postId]);
if ($post === null || !citadel_post_can_view($post, $me)) {
    citadel_json_error('post_not_found', 'Post not found.', 404);
}

// ── Parent comment validation (if reply) ─────────────────────────────────
if ($parentId !== null && $parentId > 0) {
    $parent = db_one(
        'SELECT id, post_id, is_deleted FROM comments WHERE id = ? LIMIT 1',
        [$parentId]
    );

    if ($parent === null || (int) $parent['is_deleted'] === 1) {
        citadel_json_error('parent_not_found', 'Parent comment not found.', 404);
    }
    if ((int) $parent['post_id'] !== $postId) {
        citadel_json_error('parent_mismatch',
            'Parent comment is on a different post.', 400);
    }
    // Otherwise valid — proceed
} else {
    $parentId = null;  // normalize: null = top-level comment
}

$postAuthorId = (int) $post['user_id'];

// ── Insert + counters + reputation, atomically ───────────────────────────
$db = db();
$db->beginTransaction();

try {
    db_query(
        'INSERT INTO comments (post_id, user_id, parent_id, content, created_at, updated_at)
         VALUES (?, ?, ?, ?, UTC_TIMESTAMP(), UTC_TIMESTAMP())',
        [$postId, $me, $parentId, $content]
    );
    $commentId = db_last_id();

    db_query(
        'UPDATE posts SET comment_count = comment_count + 1 WHERE id = ?',
        [$postId]
    );

    award_points($me, 'comment_given', 5, 'comment', $commentId, 'Commented on a post');
    if ($postAuthorId !== $me) {
        award_points($postAuthorId, 'comment_received', 20, 'comment', $commentId, 'Received a comment');
    }

    $db->commit();

} catch (Throwable $e) {
    if ($db->inTransaction()) $db->rollBack();
    citadel_log('api', 'error', 'Comment creation failed', [
        'post_id' => $postId, 'user_id' => $me, 'error' => $e->getMessage(),
    ]);
    citadel_json_error('create_failed', 'Could not create comment.', 500);
}

// ── Notifications (outside transaction, fire-and-forget) ─────────────────
citadel_comment_notify_activity(
    $post,
    $commentId,
    $parentId,
    $content,
    $me
);

citadel_log('api', 'info', 'Comment created', [
    'comment_id' => $commentId,
    'post_id'    => $postId,
    'user_id'    => $me,
    'is_reply'   => $parentId !== null,
]);

$isReply = $parentId !== null;

citadel_json_ok([
    'comment_id' => $commentId,
    'parent_id'  => $parentId,
    'is_reply'   => $isReply,
    'message'    => ($isReply ? 'Reply posted. ' : 'Comment posted. ') . '+5 reputation.',
], 201);