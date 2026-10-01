<?php
/* ============================================================================
 * ███ POSTS/UPDATE.PHP ███
 * Route : POST /v1/posts/update
 * Body  : { "id": 5, "content": "edited text", "visibility": "..." }
 *
 * Author only. Sets is_edited=1 on any content/visibility change.
 * ========================================================================== */

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';
require_once CITADEL_CONFIG . '/db.php';
require_once CITADEL_CONFIG . '/posts.php';
require_once CITADEL_CONFIG . '/crypto.php';

citadel_rate_limit('post_update', 30, 60);
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

if (!citadel_post_can_edit($post, $me)) {
    // Silent 404 — don't reveal existence to non-authors
    citadel_json_error('post_not_found', 'Post not found.', 404);
}

$updates = [];

$newContent = citadel_input_string('content', null, CITADEL_POST_MAX_LENGTH * 2);
if ($newContent !== null) {
    $clean = citadel_post_sanitize($newContent);
    if ($clean === '') {
        citadel_json_error('empty_content', 'Post content cannot be empty.', 400);
    }

    // Decrypt current content for comparison. `is_encrypted` rows use the
    // ciphertext path; legacy rows fall back to the plaintext column, with
    // a `?? ''` guard in case that column is NULL for an unmigrated row.
    $currentPlain = (int) $post['is_encrypted'] === 1
        ? (citadel_post_decrypt_content(
              $post['content_ct']    ?? null,
              $post['content_nonce'] ?? null,
              (int) $post['user_id']
          ) ?? '')
        : (string) ($post['content'] ?? '');

    if ($clean !== $currentPlain) {
        $enc = citadel_post_encrypt_content($clean, $me);
        // $updates['content']       = null;      // ← no more plaintext writes
        $updates['content_ct']    = $enc['ct'];
        $updates['content_nonce'] = $enc['nonce'];
        $updates['is_encrypted']  = 1;
    }
}

$newVis = citadel_input_string('visibility', null, 16);
if ($newVis !== null) {
    if (!in_array($newVis, ['public', 'connections', 'private'], true)) {
        citadel_json_error('invalid_visibility',
            'Visibility must be public, connections, or private.', 400);
    }
    if ($newVis !== $post['visibility']) {
        $updates['visibility'] = $newVis;
    }
}

if (empty($updates)) {
    citadel_json_error('no_changes', 'Nothing to update.', 400);
}

$updates['is_edited']  = 1;
$updates['updated_at'] = date('Y-m-d H:i:s');   // Will be overridden by UTC_TIMESTAMP in SQL

// Build UPDATE
$setClauses = [];
$params     = [];
foreach ($updates as $col => $val) {
    if ($col === 'updated_at') {
        $setClauses[] = 'updated_at = UTC_TIMESTAMP()';
        continue;
    }
    $setClauses[] = "{$col} = ?";
    $params[]     = $val;
}
$params[] = $postId;

try {
    db_query(
        'UPDATE posts SET ' . implode(', ', $setClauses) . ' WHERE id = ?',
        $params
    );
} catch (Throwable $e) {
    citadel_log('api', 'error', 'Post update failed', [
        'post_id' => $postId, 'user_id' => $me, 'error' => $e->getMessage(),
    ]);
    citadel_json_error('update_failed', 'Could not update post.', 500);
}

citadel_log('api', 'info', 'Post updated', [
    'post_id' => $postId, 'user_id' => $me, 'fields' => array_keys($updates),
]);

// Reload for response
$fresh = db_one(CITADEL_POST_SELECT . ' WHERE p.id = ? LIMIT 1', [$postId]);

citadel_json_ok([
    'post'    => citadel_post_hydrate($fresh, $me),
    'message' => 'Post updated.',
]);