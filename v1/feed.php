<?php
/* ============================================================================
 * ███ FEED.PHP ███
 * MyCitadel — Aggregated Timeline Feed
 * ----------------------------------------------------------------------------
 * Route  : GET /v1/feed
 * Query  : ?scope=all|self|connections&limit=20&cursor=<base64>
 *
 * ────────────────────────────────────────────────────────────────────────────
 * WHAT IT DOES
 * ────────────────────────────────────────────────────────────────────────────
 * Returns a chronological timeline of posts the viewer is allowed to see.
 *
 *   scope=all (default)  → own posts + connections' posts
 *   scope=self           → own posts only
 *   scope=connections    → connections' posts only (excludes self)
 *
 * ────────────────────────────────────────────────────────────────────────────
 * VISIBILITY RULES
 * ────────────────────────────────────────────────────────────────────────────
 *   Own posts:
 *     - visibility != 'private' (private posts stay out of the feed,
 *       accessible only via /v1/posts/view)
 *
 *   Connections' posts:
 *     - visibility IN ('public', 'connections')
 *     - OR: viewer and author are connected with state = 'connected'
 *
 *   Never included:
 *     - Deleted posts
 *     - Posts from blocked users (either direction)
 *     - Posts from banned/inactive users
 *     - Private posts from other users
 *
 * ────────────────────────────────────────────────────────────────────────────
 * CURSOR PAGINATION — WHY NOT OFFSET
 * ────────────────────────────────────────────────────────────────────────────
 * Feeds change between requests (new posts arrive at the top). Offset
 * pagination causes "shifting" — a post you saw on page 1 appears again
 * on page 2 after new posts are inserted. Cursor pagination is stable.
 *
 * The cursor encodes (created_at, id) as base64. The next page uses:
 *   WHERE (created_at < :t) OR (created_at = :t AND id < :id)
 *
 * This is index-friendly and immune to insertion drift.
 * ========================================================================== */

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';
require_once CITADEL_CONFIG . '/db.php';
require_once CITADEL_CONFIG . '/posts.php';
require_once CITADEL_CONFIG . '/connections.php';

citadel_rate_limit('feed', 120, 60);
citadel_require_auth('json');

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'GET') {
    header('Allow: GET');
    citadel_json_error('method_not_allowed', 'GET only.', 405);
}

$me = (int) citadel_current_user_id();

// ── Inputs ────────────────────────────────────────────────────────────────
$scope = isset($_GET['scope']) && is_string($_GET['scope']) ? $_GET['scope'] : 'all';
if (!in_array($scope, ['all', 'self', 'connections'], true)) {
    citadel_json_error('invalid_scope',
        'scope must be all, self, or connections.', 400);
}

$limit = max(1, min(50, (int) ($_GET['limit'] ?? 20)));

// ── Decode cursor ─────────────────────────────────────────────────────────
$cursorTime = null;
$cursorId   = null;

if (!empty($_GET['cursor']) && is_string($_GET['cursor'])) {
    $decoded = base64_decode($_GET['cursor'], true);
    if ($decoded !== false && strpos($decoded, '|') !== false) {
        [$t, $id] = explode('|', $decoded, 2);
        if (preg_match('/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/', $t)
            && ctype_digit($id)
        ) {
            $cursorTime = $t;
            $cursorId   = (int) $id;
        }
    }
    if ($cursorTime === null) {
        citadel_json_error('invalid_cursor', 'Malformed cursor.', 400);
    }
}

// ── Connection IDs (only needed if scope includes connections) ────────────
$connectionIds = [];
if ($scope === 'all' || $scope === 'connections') {
    $rows = db_all(
        'SELECT CASE WHEN user_low_id = ? THEN user_high_id ELSE user_low_id END AS other_id
           FROM user_relationships
          WHERE (user_low_id = ? OR user_high_id = ?)
            AND state = "connected"',
        [$me, $me, $me]
    );
    $connectionIds = array_map(
        static fn(array $r): int => (int) $r['other_id'],
        $rows
    );
}

// ── Build the WHERE clause ────────────────────────────────────────────────
$where   = ['p.is_deleted = 0'];
$params  = [];

// Scope filtering
if ($scope === 'self') {
    $where[]  = 'p.user_id = ?';
    $params[] = $me;
    // Private posts excluded from self feed
    $where[]  = 'p.visibility != "private"';

} elseif ($scope === 'connections') {
    if (empty($connectionIds)) {
        // No connections → empty feed
        citadel_json_ok([
            'posts'      => [],
            'has_more'   => false,
            'next_cursor'=> null,
            'scope'      => $scope,
            'count'      => 0,
        ]);
    }
    $placeholders = implode(',', array_fill(0, count($connectionIds), '?'));
    $where[]  = "p.user_id IN ({$placeholders})";
    $where[]  = 'p.visibility IN ("public","connections")';
    $params   = array_merge($params, $connectionIds);

} else {
    // scope === 'all' — self + connections
    if (empty($connectionIds)) {
        // Just self
        $where[]  = 'p.user_id = ?';
        $where[]  = 'p.visibility != "private"';
        $params[] = $me;
    } else {
        $placeholders = implode(',', array_fill(0, count($connectionIds), '?'));
        $where[]  = '(
            (p.user_id = ? AND p.visibility != "private")
            OR
            (p.user_id IN (' . $placeholders . ') AND p.visibility IN ("public","connections"))
        )';
        $params[] = $me;
        $params   = array_merge($params, $connectionIds);
    }
}

// Cursor clause
if ($cursorTime !== null && $cursorId !== null) {
    $where[]  = '(p.created_at < ? OR (p.created_at = ? AND p.id < ?))';
    $params[] = $cursorTime;
    $params[] = $cursorTime;
    $params[] = $cursorId;
}

$whereSql = implode(' AND ', $where);

// ── Query ─────────────────────────────────────────────────────────────────
// We fetch ONE MORE than the requested limit to determine has_more
$limitPlusOne = (int) ($limit + 1);

$sql = CITADEL_POST_SELECT
     . " WHERE {$whereSql}"
     . ' ORDER BY p.created_at DESC, p.id DESC'
     . ' LIMIT ' . $limitPlusOne;

$stmt = db()->prepare($sql);
$stmt->execute($params);   // only the where-clause params, no limit
$rows = $stmt->fetchAll();

// ── Determine has_more and trim to limit ──────────────────────────────────
$hasMore = count($rows) > $limit;
if ($hasMore) {
    $rows = array_slice($rows, 0, $limit);
}

// ── Hydrate ───────────────────────────────────────────────────────────────
$posts = array_map(
    static fn(array $r): array => citadel_post_hydrate($r, $me),
    $rows
);

// ── Build next cursor ─────────────────────────────────────────────────────
$nextCursor = null;
if ($hasMore && !empty($posts)) {
    $last = end($posts);
    // Rehydrate the raw row so we get the exact DB string, not the ISO format
    $lastRow = end($rows);
    $nextCursor = base64_encode($lastRow['created_at'] . '|' . (int) $lastRow['id']);
}

citadel_log('api', 'info', 'Feed fetched', [
    'user_id'           => $me,
    'scope'             => $scope,
    'count'             => count($posts),
    'has_more'          => $hasMore,
    'connection_count'  => count($connectionIds),
]);

citadel_json_ok([
    'posts'       => $posts,
    'has_more'    => $hasMore,
    'next_cursor' => $nextCursor,
    'scope'       => $scope,
    'count'       => count($posts),
]);