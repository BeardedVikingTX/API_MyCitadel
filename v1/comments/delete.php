<?php
/* ============================================================================
 * ███ COMMENTS/DELETE.PHP ███
 * Route : POST /v1/comments/delete
 * Body  : { "id": 5 }
 *
 * Soft delete + reputation deduction.
 * ========================================================================== */

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';
require_once CITADEL_CONFIG . '/db.php';
require_once CITADEL_CONFIG . '/comments.php';
require_once CITADEL_CONFIG . '/reputation.php';

citadel_rate_limit('comment_delete', 30, 60);
citadel_require_csrf();
citadel_require_auth('json');

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    header('Allow: POST');
    citadel_json_error('method_not_allowed', 'POST only.', 405);
}

$me        = (int) citadel_current_user_id();
$commentId = citadel_input_int('id');

if ($commentId === null || $commentId <= 0) {
    citadel_json_error('invalid_comment', 'A valid comment id is required.', 400);
}

$comment = db_one(
    'SELECT id, post_id, user_id, is_deleted FROM comments WHERE id = ? LIMIT 1',
    [$commentId]
);

if ($comment === null || !citadel_comment_can_delete($comment, $me)) {
    citadel_json_error('comment_not_found', 'Comment not found.', 404);
}

$postId = (int) $comment['post_id'];

$db = db();
$db->beginTransaction();

try {
    db_query(
        'UPDATE comments
            SET is_deleted = 1, deleted_at = UTC_TIMESTAMP(), updated_at = UTC_TIMESTAMP()
          WHERE id = ?',
        [$commentId]
    );

    db_query(
        'UPDATE posts SET comment_count = GREATEST(0, comment_count - 1) WHERE id = ?',
        [$postId]
    );

    // Deduct the 5 rep the commenter earned
    award_points($me, 'comment_deleted', -5, 'comment', $commentId, 'Deleted a comment');

    $db->commit();

} catch (Throwable $e) {
    if ($db->inTransaction()) $db->rollBack();
    citadel_log('api', 'error', 'Comment delete failed', [
        'comment_id' => $commentId, 'user_id' => $me, 'error' => $e->getMessage(),
    ]);
    citadel_json_error('delete_failed', 'Could not delete comment.', 500);
}

citadel_log('api', 'info', 'Comment deleted', [
    'comment_id' => $commentId, 'user_id' => $me,
]);

citadel_json_ok([
    'message'           => 'Comment deleted.',
    'reputation_change' => -5,
]);