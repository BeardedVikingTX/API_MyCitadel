<?php
/* ============================================================================
 * ███ POSTS/VIEW.PHP ███
 * Route : GET /v1/posts/view?id=N
 * ========================================================================== */

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';
require_once CITADEL_CONFIG . '/db.php';
require_once CITADEL_CONFIG . '/posts.php';

citadel_rate_limit('post_view', 120, 60);
citadel_require_auth('json');

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'GET') {
    header('Allow: GET');
    citadel_json_error('method_not_allowed', 'GET only.', 405);
}

$me     = (int) citadel_current_user_id();
$postId = isset($_GET['id']) ? (int) $_GET['id'] : 0;

if ($postId <= 0) {
    citadel_json_error('invalid_post', 'A valid post id is required.', 400);
}

$post = db_one(CITADEL_POST_SELECT . ' WHERE p.id = ? LIMIT 1', [$postId]);

if ($post === null) {
    citadel_json_error('post_not_found', 'Post not found.', 404);
}

if (!citadel_post_can_view($post, $me)) {
    // Silent 404 — never reveal existence to unauthorized viewers
    citadel_json_error('post_not_found', 'Post not found.', 404);
}

citadel_json_ok([
    'post' => citadel_post_hydrate($post, $me),
]);