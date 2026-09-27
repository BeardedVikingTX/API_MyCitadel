<?php
/* ============================================================================
 * ███ POSTS/DELETE.PHP ███
 * Route : POST /v1/posts/delete
 * Body  : { "id": 5 }
 *
 * Soft delete. Deducts 10 reputation (undoes creation award).
 * This prevents "post → delete → repost" reputation farming.
 * ========================================================================== */

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';
require_once CITADEL_CONFIG . '/db.php';
require_once CITADEL_CONFIG . '/posts.php';
require_once CITADEL_CONFIG . '/reputation.php';

citadel_rate_limit('post_delete', 30, 60);
citadel_require_csrf();
citadel_require_auth('json');

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    header('Allow: POST');
    citadel_json_error('method_not_allowed', 'POST only.', 405);
}

$me     = (int) citadel_current_user_id();
$postId = citadel_input_int('id');

if ($postId === null || $postId <= 0) {
    citadel_json_error('invalid_post', 'A valid post id is required.', 400);
}

$post = db_one(CITADEL_POST_SELECT . ' WHERE p.id = ? LIMIT 1', [$postId]);

if ($post === null) {
    citadel_json_error('post_not_found', 'Post not found.', 404);
}

if (!citadel_post_can_delete($post, $me)) {
    citadel_json_error('post_not_found', 'Post not found.', 404);
}

$db = db();
$db->beginTransaction();

try {
    // Soft delete
    db_query(
        'UPDATE posts
            SET is_deleted = 1, deleted_at = UTC_TIMESTAMP(), updated_at = UTC_TIMESTAMP()
          WHERE id = ?',
        [$postId]
    );

    // Deduct the 10 reputation that was awarded on creation
    award_points($me, 'post_deleted', -10, 'post', $postId, 'Deleted a post');

    $db->commit();

} catch (Throwable $e) {
    if ($db->inTransaction()) $db->rollBack();
    citadel_log('api', 'error', 'Post delete failed', [
        'post_id' => $postId, 'user_id' => $me, 'error' => $e->getMessage(),
    ]);
    citadel_json_error('delete_failed', 'Could not delete post.', 500);
}

citadel_log('api', 'info', 'Post deleted', [
    'post_id' => $postId, 'user_id' => $me,
]);

citadel_json_ok([
    'message'           => 'Post deleted.',
    'reputation_change' => -10,
]);