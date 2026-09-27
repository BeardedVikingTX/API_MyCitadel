<?php
/* ============================================================================
 * ███ POSTS/USER.PHP ███
 * Route : GET /v1/posts/user?user_id=N&limit=20&offset=0
 *
 * Lists posts by a specific user that the viewer is allowed to see.
 * ========================================================================== */

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';
require_once CITADEL_CONFIG . '/db.php';
require_once CITADEL_CONFIG . '/posts.php';
require_once CITADEL_CONFIG . '/connections.php';

citadel_rate_limit('post_user', 60, 60);
citadel_require_auth('json');

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'GET') {
    header('Allow: GET');
    citadel_json_error('method_not_allowed', 'GET only.', 405);
}

$me       = (int) citadel_current_user_id();
$targetId = isset($_GET['user_id']) ? (int) $_GET['user_id'] : 0;
$limit    = max(1, min(50, (int) ($_GET['limit']  ?? 20)));
$offset   = max(0,        (int) ($_GET['offset'] ?? 0));

if ($targetId <= 0) {
    citadel_json_error('invalid_user', 'A valid user_id is required.', 400);
}

// Verify the viewer can see this user at all
$vis = citadel_rel_visibility($me, $targetId);
$isSelf = ($me === $targetId);

if (!$isSelf && !$vis['can_view']) {
    citadel_json_error('user_not_found', 'User not found.', 404);
}

$isConnected = ($isSelf || $vis['state'] === 'connected');

// Build visibility filter
if ($isSelf) {
    // Self sees everything except soft-deleted
    $visClause  = '(p.visibility IN ("public","connections","private"))';
} elseif ($isConnected) {
    // Connections see public + connections posts
    $visClause  = '(p.visibility IN ("public","connections"))';
} else {
    // Non-connections see only public posts (still gated by user visibility check above)
    $visClause  = '(p.visibility = "public")';
}

$rows = db_all(
    CITADEL_POST_SELECT . "
     WHERE p.user_id = ?
       AND p.is_deleted = 0
       AND {$visClause}
     ORDER BY p.created_at DESC
     LIMIT ? OFFSET ?",
    [$targetId, $limit, $offset]
);

$posts = array_map(
    static fn(array $r): array => citadel_post_hydrate($r, $me),
    $rows
);

// Total for pagination
$total = (int) db_scalar(
    "SELECT COUNT(*) FROM posts p
      WHERE p.user_id = ?
        AND p.is_deleted = 0
        AND {$visClause}",
    [$targetId]
);

citadel_json_ok([
    'posts'    => $posts,
    'total'    => $total,
    'limit'    => $limit,
    'offset'   => $offset,
    'has_more' => ($offset + count($posts)) < $total,
]);