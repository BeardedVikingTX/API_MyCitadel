<?php
/* ============================================================================
 * ███ USERS/LIST.PHP ███
 * MyCitadel — User Directory
 * ----------------------------------------------------------------------------
 * Route : GET /v1/users/list
 * Auth  : Required
 * Rate  : 30 requests per minute per IP
 *
 * ────────────────────────────────────────────────────────────────────────────
 * WHO APPEARS IN THE LIST
 * ────────────────────────────────────────────────────────────────────────────
 *   • visibility = 'public' (not 'connections_only' or 'hidden')
 *   • is_active = 1, is_banned = 0
 *   • NOT in a blocked relationship with the viewer (either direction)
 *   • NOT the viewer themselves
 *
 * ────────────────────────────────────────────────────────────────────────────
 * WHAT EACH ENTRY INCLUDES
 * ────────────────────────────────────────────────────────────────────────────
 *   • Public identity: id, username, display_name, avatar, accent_color
 *   • Reputation + badge count
 *   • Member-since date
 *   • Connection state with the viewer: none | pending_out | pending_in | connected
 *     (so the UI knows whether to show "Connect", "Cancel", "Accept", or "Message")
 *
 * ────────────────────────────────────────────────────────────────────────────
 * PRIVACY
 * ────────────────────────────────────────────────────────────────────────────
 *   • We NEVER return encrypted PII (email, phone, address)
 *   • We NEVER return blocked users, in either direction
 *   • We NEVER return users who set visibility='hidden'
 * ========================================================================== */

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';
require_once CITADEL_CONFIG . '/db.php';
require_once CITADEL_CONFIG . '/connections.php';

citadel_rate_limit('users_list', 30, 60);
citadel_require_auth('json');

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'GET') {
    header('Allow: GET');
    citadel_json_error('method_not_allowed', 'GET only.', 405);
}

$me     = (int) citadel_current_user_id();
$limit  = max(1, min(50, (int) ($_GET['limit']  ?? 24)));
$offset = max(0,        (int) ($_GET['offset'] ?? 0));

// Optional filter: exclude already-connected users
$excludeConnected = isset($_GET['exclude_connected']) && $_GET['exclude_connected'] === '1';

// Viewer's block list — users they should never see
$blockedIds = citadel_rel_exclusion_ids($me);

// Build the SQL. We join relationships once to know the connection state.
$sql = '
    SELECT
        u.id, u.username, u.created_at,
        p.display_name, p.avatar_url, p.avatar_frame_id, p.accent_color,
        p.country_code, p.state_code,
        COALESCE(s.reputation_points, 0) AS reputation,
        COALESCE(s.badge_count, 0)       AS badge_count,
        r.state         AS rel_state,
        r.initiated_by  AS rel_initiated_by
      FROM users u
      LEFT JOIN user_profiles p ON p.user_id = u.id
      LEFT JOIN user_stats    s ON s.user_id = u.id
      LEFT JOIN user_relationships r
             ON (r.user_low_id  = LEAST(u.id, ?) AND r.user_high_id = GREATEST(u.id, ?))
     WHERE u.id != ?
       AND u.is_active = 1
       AND u.is_banned = 0
       AND (p.visibility IS NULL OR p.visibility = "public")
';

$params = [$me, $me, $me];

// Exclude blocked users (either direction) — using NOT IN
if (!empty($blockedIds)) {
    $placeholders = implode(',', array_fill(0, count($blockedIds), '?'));
    $sql .= " AND u.id NOT IN ({$placeholders})";
    $params = array_merge($params, $blockedIds);
}

// Optional: hide already-connected users
if ($excludeConnected) {
    $sql .= ' AND (r.state IS NULL OR r.state != "connected")';
}

$sql .= ' ORDER BY u.created_at DESC LIMIT ? OFFSET ?';
$params[] = $limit;
$params[] = $offset;

$rows = db_all($sql, $params);

// Transform each row into the API shape
$users = array_map(static function (array $row) use ($me): array {
    // Compute connection state from the viewer's perspective
    $state = 'none';
    if ($row['rel_state'] === 'connected') {
        $state = 'connected';
    } elseif ($row['rel_state'] === 'pending') {
        $state = ((int) $row['rel_initiated_by'] === $me) ? 'pending_out' : 'pending_in';
    } elseif ($row['rel_state'] === 'blocked') {
        // Shouldn't happen (we excluded them) — but defensive
        $state = 'blocked';
    }

    return [
        'id'              => (int) $row['id'],
        'username'        => (string) $row['username'],
        'display_name'    => $row['display_name'],
        'avatar_url'      => $row['avatar_url'],
        'avatar_frame_id' => $row['avatar_frame_id'] !== null ? (int) $row['avatar_frame_id'] : null,
        'accent_color'    => (string) $row['accent_color'],
        'country_code'    => $row['country_code'],
        'state_code'      => $row['state_code'],
        'reputation'      => (int) $row['reputation'],
        'badge_count'     => (int) $row['badge_count'],
        'member_since'    => gmdate('c', strtotime((string) $row['created_at'])),
        'connection_state'=> $state,
    ];
}, $rows);

// Total count (for pagination UI)
$countSql = '
    SELECT COUNT(*)
      FROM users u
      LEFT JOIN user_profiles p ON p.user_id = u.id
      LEFT JOIN user_relationships r
             ON (r.user_low_id  = LEAST(u.id, ?) AND r.user_high_id = GREATEST(u.id, ?))
     WHERE u.id != ?
       AND u.is_active = 1
       AND u.is_banned = 0
       AND (p.visibility IS NULL OR p.visibility = "public")
';
$countParams = [$me, $me, $me];

if (!empty($blockedIds)) {
    $placeholders = implode(',', array_fill(0, count($blockedIds), '?'));
    $countSql .= " AND u.id NOT IN ({$placeholders})";
    $countParams = array_merge($countParams, $blockedIds);
}
if ($excludeConnected) {
    $countSql .= ' AND (r.state IS NULL OR r.state != "connected")';
}

$total = (int) db_scalar($countSql, $countParams);

citadel_json_ok([
    'users'  => $users,
    'total'  => $total,
    'limit'  => $limit,
    'offset' => $offset,
]);