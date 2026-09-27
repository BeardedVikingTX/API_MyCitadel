<?php
/* ============================================================================
 * ███ COMMENTS/LIST.PHP ███
 * Route : GET /v1/comments/list?post_id=5&limit=50&offset=0
 * ========================================================================== */

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';
require_once CITADEL_CONFIG . '/db.php';
require_once CITADEL_CONFIG . '/posts.php';
require_once CITADEL_CONFIG . '/comments.php';

citadel_rate_limit('comment_list', 120, 60);
citadel_require_auth('json');

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'GET') {
    header('Allow: GET');
    citadel_json_error('method_not_allowed', 'GET only.', 405);
}

$me     = (int) citadel_current_user_id();
$postId = isset($_GET['post_id']) ? (int) $_GET['post_id'] : 0;
$limit  = max(1, min(100, (int) ($_GET['limit']  ?? 50)));
$offset = max(0,          (int) ($_GET['offset'] ?? 0));

if ($postId <= 0) {
    citadel_json_error('invalid_post', 'A valid post_id is required.', 400);
}

// Post must be visible to the viewer
$post = db_one(CITADEL_POST_SELECT . ' WHERE p.id = ? LIMIT 1', [$postId]);
if ($post === null || !citadel_post_can_view($post, $me)) {
    citadel_json_error('post_not_found', 'Post not found.', 404);
}

$rows = db_all(
    CITADEL_COMMENT_SELECT . '
     WHERE c.post_id = ? AND c.is_deleted = 0
     ORDER BY c.created_at ASC
     LIMIT ? OFFSET ?',
    [$postId, $limit, $offset]
);

$comments = array_map(
    static fn(array $r): array => citadel_comment_hydrate($r, $me),
    $rows
);

$total = (int) db_scalar(
    'SELECT COUNT(*) FROM comments WHERE post_id = ? AND is_deleted = 0',
    [$postId]
);

citadel_json_ok([
    'comments' => $comments,
    'total'    => $total,
    'limit'    => $limit,
    'offset'   => $offset,
    'has_more' => ($offset + count($comments)) < $total,
]);