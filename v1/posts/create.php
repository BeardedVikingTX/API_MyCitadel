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
 *
 * TIER LIMITS (inline, no external config):
 *   Free    — 50 chars, 1 attachment, images only
 *   Premium — 1,500 chars, 10 attachments, any file type
 *
 * ENCRYPTION:
 *   Content is encrypted BEFORE the transaction opens. If crypto fails,
 *   nothing has been written and no lock is held. The ciphertext is
 *   stored in content_ct / content_nonce with is_encrypted = 1.
 * ========================================================================== */

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';
require_once CITADEL_CONFIG . '/db.php';
require_once CITADEL_CONFIG . '/posts.php';
require_once CITADEL_CONFIG . '/reputation.php';
require_once CITADEL_CONFIG . '/badges.php';
require_once CITADEL_CONFIG . '/attachments.php';
require_once CITADEL_CONFIG . '/crypto.php';

citadel_rate_limit('post_create', 30, 60);
citadel_require_auth('json');     // ← auth first (401 before 403)
citadel_require_csrf();           // ← then CSRF

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    header('Allow: POST');
    citadel_json_error('method_not_allowed', 'POST only.', 405);
}

$me = (int) citadel_current_user_id();

/* ══════════════════════════════════════════════════════════════════════
 * PER-USER RATE LIMIT
 * ═════════════════════════════════════════════════════════════════════ */
if (citadel_post_recent_count($me) >= CITADEL_POST_RATE_LIMIT) {
    citadel_json_error('rate_limited',
        'You are posting too frequently. Try again later.', 429);
}

/* ══════════════════════════════════════════════════════════════════════
 * TIER LIMITS — resolved once, used throughout this request
 * ═════════════════════════════════════════════════════════════════════
 *   Free    → 50 chars, 1 attachment, images only
 *   Premium → 1,500 chars, 10 attachments, images/video/audio/documents
 *
 * If the lookup fails for any reason we fall back to the FREE tier.
 * Premium is opt-in; free is the safe default.
 * ═════════════════════════════════════════════════════════════════════ */
$isPremium = ((int) db_scalar(
    'SELECT is_premium FROM users WHERE id = ? LIMIT 1',
    [$me]
)) === 1;

if ($isPremium) {
    $maxChars       = 1500;
    $maxAttachments = 10;
    $allowedKinds   = ['image', 'video', 'audio', 'document'];
} else {
    $maxChars       = 50;
    $maxAttachments = 1;
    $allowedKinds   = ['image'];
}

/* ══════════════════════════════════════════════════════════════════════
 * CONTENT
 * ═════════════════════════════════════════════════════════════════════ */
// Hard input cap is the global max so the tier check below produces the
// friendlier "tier_limit_exceeded" message for anything reasonable.
$contentRaw = citadel_input_string('content', null, CITADEL_POST_MAX_LENGTH);
$content    = $contentRaw !== null ? citadel_post_sanitize($contentRaw) : '';

if (mb_strlen($content) > $maxChars) {
    citadel_json_error('tier_limit_exceeded',
        "Posts are limited to {$maxChars} characters on your tier. " .
            ($isPremium ? '' : 'Upgrade to Premium for up to 1,500.'),
        403);
}

/* ══════════════════════════════════════════════════════════════════════
 * VISIBILITY
 * ═════════════════════════════════════════════════════════════════════ */
$visibility = citadel_input_string('visibility', 'connections', 16);
if (!in_array($visibility, ['public', 'connections', 'private'], true)) {
    citadel_json_error('invalid_visibility',
        'Visibility must be public, connections, or private.', 400);
}

/* ══════════════════════════════════════════════════════════════════════
 * ATTACHMENT TOKENS
 * ═════════════════════════════════════════════════════════════════════ */
$body             = citadel_input_json();
$attachmentTokens = [];
$rawTokens        = $body['attachment_tokens'] ?? null;

if (is_array($rawTokens)) {
    foreach (array_slice($rawTokens, 0, $maxAttachments) as $t) {
        if (is_string($t) && preg_match('/^[a-f0-9]{32}$/', $t)) {
            $attachmentTokens[] = $t;
        }
    }
}

if (is_array($rawTokens) && count($rawTokens) > $maxAttachments) {
    $plural = $maxAttachments === 1 ? 'attachment' : 'attachments';
    citadel_json_error('tier_limit_exceeded',
        "Posts are limited to {$maxAttachments} {$plural} on your tier. " .
            ($isPremium ? '' : 'Upgrade to Premium for up to 10.'),
        403);
}

// A post needs text OR at least one attachment.
if ($content === '' && empty($attachmentTokens)) {
    citadel_json_error('empty_content',
        'A post must have text or at least one attachment.', 400);
}

// Verify tokens belong to this user, are unbound, and are an allowed kind.
$ownedTokens = [];
if (!empty($attachmentTokens)) {
    $ph = implode(',', array_fill(0, count($attachmentTokens), '?'));
    $rows = db_all(
        "SELECT served_token, kind
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

    foreach ($rows as $row) {
        $kind = (string) $row['kind'];
        if (!in_array($kind, $allowedKinds, true)) {
            $allowedList = implode(', ', $allowedKinds);
            citadel_json_error('tier_limit_exceeded',
                "Your tier does not allow '{$kind}' attachments. " .
                    "Allowed: {$allowedList}." .
                    ($isPremium ? '' : ' Upgrade to Premium to unlock all file types.'),
                403);
        }
    }
}

/* ══════════════════════════════════════════════════════════════════════
 * ENCRYPTION — BEFORE the transaction
 * ═════════════════════════════════════════════════════════════════════
 * If encryption fails, we haven't opened a transaction yet, haven't
 * touched the DB, and haven't held any locks. Fail fast, fail clean.
 *
 * If $content is empty (attachment-only post), we skip encryption and
 * write NULL to the ciphertext columns.
 * ═════════════════════════════════════════════════════════════════════ */
$contentCt    = null;
$contentNonce = null;
$isEncrypted  = 0;

if ($content !== '') {
    try {
        $enc          = citadel_post_encrypt_content($content, $me);
        $contentCt    = $enc['ct'];
        $contentNonce = $enc['nonce'];
        $isEncrypted  = 1;
    } catch (Throwable $e) {
        citadel_log('api', 'error', 'Post encryption failed', [
            'user_id' => $me,
            'error'   => $e->getMessage(),
        ]);
        citadel_json_error('encryption_failed',
            'Could not securely store your post. Please try again.', 500);
    }
}

/* ══════════════════════════════════════════════════════════════════════
 * INSERT — single transaction
 * ═════════════════════════════════════════════════════════════════════ */
$db = db();
$db->beginTransaction();

try {
    // ── MIGRATION MODE ──────────────────────────────────────────────
    // We currently write BOTH the plaintext (content) and the ciphertext
    // (content_ct / content_nonce). This lets us compare and roll back
    // if anything goes wrong.
    //
    // WHEN YOU'RE CONFIDENT: change the `?` in the content slot below to
    // SQL literal NULL and drop $content from the params array. Then run:
    //
    //     UPDATE posts SET content = NULL WHERE is_encrypted = 1;
    //
    // After that, the plaintext column holds nothing for any post.
    // ────────────────────────────────────────────────────────────────
    db_query(
        'INSERT INTO posts
            (user_id, content_ct, content_nonce, is_encrypted,
             visibility, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, UTC_TIMESTAMP(), UTC_TIMESTAMP())',
        [
            $me,
            $contentCt,
            $contentNonce,
            $isEncrypted,
            $visibility,
        ]
    );
    $postId = (int) db_last_id();

    // Bind attachments to this post.
    if (!empty($ownedTokens)) {
        $ph = implode(',', array_fill(0, count($ownedTokens), '?'));
        db_query(
            "UPDATE post_attachments
                SET post_id = ?
              WHERE served_token IN ($ph)",
            array_merge([$postId], $ownedTokens)
        );
    }

    // Bump post counter — drives post_* badge thresholds.
    bump_stat($me, 'post_count', 1);

    // Award reputation.
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

/* ══════════════════════════════════════════════════════════════════════
 * POST-COMMIT LOGGING (never blocks the post)
 * ═════════════════════════════════════════════════════════════════════ */
citadel_log('api', 'info', 'Post created', [
    'post_id'     => $postId,
    'user_id'     => $me,
    'tier'        => $isPremium ? 'premium' : 'free',
    'visibility'  => $visibility,
    'encrypted'   => $isEncrypted === 1,
    'attachments' => count($ownedTokens),
]);

/* ── Badge check ─────────────────────────────────────────────────────── */
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

/* ══════════════════════════════════════════════════════════════════════
 * RESPONSE
 * ═════════════════════════════════════════════════════════════════════ */
citadel_json_ok([
    'post_id'     => $postId,
    'attachments' => count($ownedTokens),
    'encrypted'   => $isEncrypted === 1,
    'message'     => 'Post created. +10 reputation.',
], 201);