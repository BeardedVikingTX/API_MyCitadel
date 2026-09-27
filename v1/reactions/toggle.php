<?php
/* ============================================================================
 * ███ REACTIONS/TOGGLE.PHP ███
 * Route : POST /v1/reactions/toggle
 * Body  : { "target_type": "post"|"comment", "target_id": N, "reaction": "like" }
 *
 * THREE-WAY TOGGLE:
 *   No existing reaction       → INSERT (award)
 *   Same reaction, existing    → DELETE (un-react, deduct)
 *   Different reaction, exists → UPDATE (rep delta between two types)
 *
 * Notifications fire only on NEW reaction (not on change or removal).
 * ========================================================================== */

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';
require_once CITADEL_CONFIG . '/db.php';
require_once CITADEL_CONFIG . '/posts.php';
require_once CITADEL_CONFIG . '/comments.php';
require_once CITADEL_CONFIG . '/notifications.php';
require_once CITADEL_CONFIG . '/reputation.php';

citadel_rate_limit('reaction_toggle', 120, 60);
citadel_require_csrf();
citadel_require_auth('json');

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    header('Allow: POST');
    citadel_json_error('method_not_allowed', 'POST only.', 405);
}

$me         = (int) citadel_current_user_id();
$targetType = citadel_input_string('target_type', null, 16);
$targetId   = citadel_input_int('target_id');
$reaction   = citadel_input_string('reaction', null, 16);

if (!in_array($targetType, ['post', 'comment'], true)) {
    citadel_json_error('invalid_target', 'target_type must be post or comment.', 400);
}
if ($targetId === null || $targetId <= 0) {
    citadel_json_error('invalid_target_id', 'A valid target_id is required.', 400);
}
if (!in_array($reaction, CITADEL_REACTION_TYPES, true)) {
    citadel_json_error('invalid_reaction', 'Invalid reaction type.', 400);
}

// ── Resolve the target's author (for rep + notification) ────────────────
if ($targetType === 'post') {
    $post = db_one(CITADEL_POST_SELECT . ' WHERE p.id = ? LIMIT 1', [$targetId]);
    if ($post === null || !citadel_post_can_view($post, $me)) {
        citadel_json_error('target_not_found', 'Target not found.', 404);
    }
    $authorId = (int) $post['user_id'];
} else {
    $comment = db_one(
        'SELECT c.id, c.post_id, c.user_id, c.is_deleted FROM comments c WHERE c.id = ? LIMIT 1',
        [$targetId]
    );
    if ($comment === null || (int) $comment['is_deleted'] === 1) {
        citadel_json_error('target_not_found', 'Target not found.', 404);
    }
    // Comment visibility = post visibility
    $parentPost = db_one(CITADEL_POST_SELECT . ' WHERE p.id = ? LIMIT 1', [(int) $comment['post_id']]);
    if ($parentPost === null || !citadel_post_can_view($parentPost, $me)) {
        citadel_json_error('target_not_found', 'Target not found.', 404);
    }
    $authorId = (int) $comment['user_id'];
}

// ── Reaction point values ───────────────────────────────────────────────
$reactionPoints = [
    'like'    => 2,
    'dislike' => -2,
    'heart'   => 5,
    'angry'   => -5,
];
$deltaForNew = $reactionPoints[$reaction];

// ── Look up existing reaction ────────────────────────────────────────────
$existing = db_one(
    'SELECT id, reaction FROM reactions
      WHERE user_id = ? AND target_type = ? AND target_id = ?
      LIMIT 1',
    [$me, $targetType, $targetId]
);

$db = db();
$db->beginTransaction();

try {
    // ── Case A: no existing reaction → INSERT ───────────────────────────
    if ($existing === null) {
        db_query(
            'INSERT INTO reactions (user_id, target_type, target_id, reaction, created_at)
             VALUES (?, ?, ?, ?, UTC_TIMESTAMP())',
            [$me, $targetType, $targetId, $reaction]
        );

        // Counter + rep for both parties
        if ($targetType === 'post') {
            db_query('UPDATE posts SET reaction_count = reaction_count + 1 WHERE id = ?', [$targetId]);
        }
        // Reaction given (to self) — +deltaForNew
        award_points(
            $me,
            'reaction_given_' . $reaction,
            $deltaForNew,
            $targetType,
            $targetId,
            'Gave a ' . $reaction
        );
        // Reaction received (to author) — +deltaForNew
        if ($authorId !== $me) {
            award_points(
                $authorId,
                'reaction_received_' . $reaction,
                $deltaForNew,
                $targetType,
                $targetId,
                'Received a ' . $reaction
            );
        }

        $newState = $reaction;
        $notify   = ($authorId !== $me);

    // ── Case B: same reaction → DELETE (un-react) ───────────────────────
    } elseif ($existing['reaction'] === $reaction) {
        db_query('DELETE FROM reactions WHERE id = ?', [(int) $existing['id']]);

        if ($targetType === 'post') {
            db_query('UPDATE posts SET reaction_count = GREATEST(0, reaction_count - 1) WHERE id = ?', [$targetId]);
        }
        // Reverse the rep for both parties
        award_points($me, 'reaction_removed', -$deltaForNew, $targetType, $targetId, 'Removed a ' . $reaction);
        if ($authorId !== $me) {
            award_points($authorId, 'reaction_removed_received', -$deltaForNew, $targetType, $targetId, 'Reaction removed');
        }

        $newState = null;
        $notify   = false;

    // ── Case C: different reaction → UPDATE ─────────────────────────────
    } else {
        $oldDelta = $reactionPoints[$existing['reaction']];

        db_query(
            'UPDATE reactions SET reaction = ? WHERE id = ?',
            [$reaction, (int) $existing['id']]
        );

        // Adjust rep by the delta (old → new)
        $deltaChange = $deltaForNew - $oldDelta;
        if ($deltaChange !== 0) {
            award_points($me, 'reaction_changed', $deltaChange, $targetType, $targetId, 'Changed reaction');
            if ($authorId !== $me) {
                award_points($authorId, 'reaction_changed_received', $deltaChange, $targetType, $targetId, 'Reaction changed');
            }
        }

        $newState = $reaction;
        $notify   = false;  // no notification for a change
    }

    $db->commit();

} catch (Throwable $e) {
    if ($db->inTransaction()) $db->rollBack();
    citadel_log('api', 'error', 'Reaction toggle failed', [
        'user_id' => $me, 'target' => "$targetType:$targetId", 'error' => $e->getMessage(),
    ]);
    citadel_json_error('toggle_failed', 'Could not toggle reaction.', 500);
}

// ── Notify on NEW reaction only ─────────────────────────────────────────
if ($notify) {
    try {
        $me_username = db_scalar('SELECT username FROM users WHERE id = ? LIMIT 1', [$me]);
        citadel_notify(
            $authorId,
            'new_reaction',
            'New reaction on your ' . $targetType,
            $me_username . ' reacted with ' . $reaction,
            $me,
            ['target_type' => $targetType, 'target_id' => $targetId, 'reaction' => $reaction],
            $targetType === 'post'
                ? '/posts/' . $targetId
                : '/posts/' . (int) $parentPost['id'] . '#comment-' . $targetId
        );
    } catch (Throwable $e) {
        citadel_log('api', 'warning', 'Reaction notification failed', [
            'target' => "$targetType:$targetId", 'error' => $e->getMessage(),
        ]);
    }
}

citadel_log('api', 'info', 'Reaction toggled', [
    'user_id' => $me, 'target' => "$targetType:$targetId", 'state' => $newState,
]);

// Fresh count for the UI
$count = $targetType === 'post'
    ? (int) db_scalar('SELECT reaction_count FROM posts WHERE id = ?', [$targetId])
    : (int) db_scalar('SELECT COUNT(*) FROM reactions WHERE target_type = "comment" AND target_id = ?', [$targetId]);

citadel_json_ok([
    'reaction' => $newState,
    'count'    => $count,
    'message'  => $newState === null ? 'Reaction removed.' : 'Reaction saved.',
]);