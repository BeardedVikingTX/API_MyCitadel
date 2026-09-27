<?php
/* ============================================================================
 * ███ DASHBOARD.PHP ███
 * MyCitadel — User Dashboard Aggregator
 * ----------------------------------------------------------------------------
 * Route : GET /v1/users/dashboard
 * Auth  : Required
 * CSRF  : Not required (safe method)
 * Rate  : 30 requests per minute per IP
 *
 * ────────────────────────────────────────────────────────────────────────────
 * WHAT IT DOES
 * ────────────────────────────────────────────────────────────────────────────
 * Returns everything the user dashboard needs in ONE round-trip:
 *
 *   identity    — who you are (username, display_name, avatar, email, etc.)
 *   account     — account state (verified, premium, member since, age)
 *   stats       — your counters (reputation, badges, post/comment/reaction)
 *   rank        — where you stand among all users
 *   badges      — your earned badges with metadata
 *   activity    — recent reputation events from the ledger
 *   community   — platform-wide aggregates for comparison
 *   features    — which features are available (for graceful UI fallback)
 *
 * ────────────────────────────────────────────────────────────────────────────
 * WHY ONE ENDPOINT, NOT SIX
 * ────────────────────────────────────────────────────────────────────────────
 * A dashboard page loads once and displays everything. Six separate requests
 * means:
 *   • 6× TLS handshakes on cold load
 *   • 6× chances for one to fail, degrading UX
 *   • 6× rate-limit budget consumed
 *   • 6× logs to correlate
 *
 * One aggregated endpoint is faster, cleaner, and easier to reason about.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * QUERY STRATEGY
 * ────────────────────────────────────────────────────────────────────────────
 * Total DB round-trips: 6 (all covered by indexes).
 *   1. User row + joined profile + stats (single query)
 *   2. Count all users (for rank denominator)
 *   3. Count all users with higher rep (for rank numerator)
 *   4. Community reputation sum (for average)
 *   5. Recent reputation_ledger entries for this user (limit 10)
 *   6. User's badges (with badge metadata joined)
 *
 * No N+1. No loops-with-queries. Every query is indexed.
 * ========================================================================== */

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';
require_once CITADEL_CONFIG . '/crypto.php';
require_once CITADEL_CONFIG . '/db.php';


/* ══════════════════════════════════════════════════════════════════════════
 * 01. REQUEST PROTECTIONS
 * ========================================================================== */

citadel_rate_limit('dashboard', 30, 60);
citadel_require_auth('json');

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'GET') {
    header('Allow: GET');
    citadel_json_error('method_not_allowed', 'This endpoint accepts GET only.', 405);
}

$userId = (int) citadel_current_user_id();
$db     = db();


/* ══════════════════════════════════════════════════════════════════════════
 * 02. LOAD THE USER (single joined query)
 * --------------------------------------------------------------------------
 * One query pulls user + profile + stats. This is the foundation for most
 * of the response.
 * ========================================================================== */

$user = db_one(
    'SELECT
        u.id, u.username, u.email_ct, u.email_nonce,
        u.is_premium, u.premium_since, u.premium_expires_at,
        u.email_verified, u.email_verified_at,
        u.is_active, u.is_banned,
        u.created_at, u.updated_at, u.last_login_at,
        u.referral_code, u.referred_by,
        p.visibility, p.display_name, p.tagline, p.bio,
        p.avatar_url, p.avatar_frame_id, p.banner_url, p.banner_frame_id,
        p.accent_color, p.theme_preference,
        p.country_code, p.state_code, p.timezone,
        COALESCE(s.reputation_points, 0)      AS reputation_points,
        COALESCE(s.post_count, 0)             AS post_count,
        COALESCE(s.comment_given_count, 0)    AS comment_given_count,
        COALESCE(s.comment_received_count, 0) AS comment_received_count,
        COALESCE(s.connection_count, 0)       AS connection_count,
        COALESCE(s.badge_count, 0)            AS badge_count,
        COALESCE(s.referral_count, 0)         AS referral_count,
        COALESCE(s.checkin_streak, 0)         AS checkin_streak,
        COALESCE(s.checkin_longest_streak, 0) AS checkin_longest_streak,
        COALESCE(s.reactions_given_like, 0)   AS reactions_given_like,
        COALESCE(s.reactions_given_heart, 0)  AS reactions_given_heart,
        COALESCE(s.reactions_recv_like, 0)    AS reactions_recv_like,
        COALESCE(s.reactions_recv_heart, 0)   AS reactions_recv_heart
      FROM users u
      LEFT JOIN user_profiles p ON p.user_id = u.id
      LEFT JOIN user_stats    s ON s.user_id = u.id
     WHERE u.id = ?
     LIMIT 1',
    [$userId]
);

if ($user === null) {
    citadel_session_destroy();
    citadel_json_error('account_missing', 'Your account no longer exists.', 401);
}

$email = citadel_crypto_decrypt(
    $user['email_ct'],
    $user['email_nonce'],
    $userId
);


/* ══════════════════════════════════════════════════════════════════════════
 * 03. ACCOUNT AGE CALCULATION
 * --------------------------------------------------------------------------
 * Convert "member since" into human-friendly units. We compute them
 * server-side so every client shows the same numbers.
 * ========================================================================== */

$createdTs   = strtotime((string) $user['created_at']);
$now         = time();
$ageSeconds  = max(0, $now - $createdTs);
$ageDays     = (int) floor($ageSeconds / 86400);
$ageWeeks    = (int) floor($ageDays / 7);
$ageMonths   = (int) floor($ageDays / 30.4375);
$ageYears    = (int) floor($ageDays / 365.25);

$memberSince = gmdate('c', $createdTs);
$ageHuman    = match (true) {
    $ageYears  >= 1 => $ageYears . ' year' . ($ageYears  !== 1 ? 's' : ''),
    $ageMonths >= 1 => $ageMonths . ' month' . ($ageMonths !== 1 ? 's' : ''),
    $ageWeeks  >= 1 => $ageWeeks . ' week' . ($ageWeeks  !== 1 ? 's' : ''),
    $ageDays   >= 1 => $ageDays . ' day' . ($ageDays   !== 1 ? 's' : ''),
    default         => 'today',
};


/* ══════════════════════════════════════════════════════════════════════════
 * 04. COMMUNITY STATS (for comparison)
 * --------------------------------------------------------------------------
 * Three aggregates:
 *   totalUsers   — how many accounts exist
 *   higherRep    — how many accounts have MORE reputation than this user
 *   totalRep     — sum of all reputation (for average)
 *
 * Rank = higherRep + 1 (the classic "your position" formula).
 * Percentile = percentage of users below you.
 * ========================================================================== */

$totalUsers = (int) db_scalar('SELECT COUNT(*) FROM users WHERE is_active = 1');

$higherRep = (int) db_scalar(
    'SELECT COUNT(*)
       FROM user_stats
      WHERE reputation_points > ?',
    [(int) $user['reputation_points']]
);

$totalRep = (int) db_scalar('SELECT COALESCE(SUM(reputation_points), 0) FROM user_stats');

$myRank     = $higherRep + 1;
$avgRep     = $totalUsers > 0 ? (int) round($totalRep / $totalUsers) : 0;
$percentile = $totalUsers > 1
    ? (int) round((($totalUsers - $myRank) / ($totalUsers - 1)) * 100)
    : 100;


/* ══════════════════════════════════════════════════════════════════════════
 * 05. EARNED BADGES
 * --------------------------------------------------------------------------
 * Full list of badges with their catalog metadata. Sorted newest first,
 * featured ones pulled to the top (used by the UI to highlight).
 * ========================================================================== */

$badgeRows = db_all(
    'SELECT b.slug, b.name, b.description, b.category, b.threshold,
            b.tier, b.icon_svg, b.color,
            ub.earned_at, ub.is_featured
       FROM user_badges ub
       JOIN badges b ON b.id = ub.badge_id
      WHERE ub.user_id = ?
      ORDER BY ub.is_featured DESC, ub.earned_at DESC',
    [$userId]
);

$badges = array_map(static function (array $row): array {
    return [
        'slug'        => (string) $row['slug'],
        'name'        => (string) $row['name'],
        'description' => (string) $row['description'],
        'category'    => (string) $row['category'],
        'threshold'   => (int)    $row['threshold'],
        'tier'        => (string) $row['tier'],
        'icon_svg'    => $row['icon_svg'] !== null ? (string) $row['icon_svg'] : null,
        'color'       => (string) $row['color'],
        'earned_at'   => gmdate('c', strtotime((string) $row['earned_at'])),
        'is_featured' => (bool)   $row['is_featured'],
    ];
}, $badgeRows);


/* ══════════════════════════════════════════════════════════════════════════
 * 06. RECENT REPUTATION EVENTS
 * --------------------------------------------------------------------------
 * The last 10 reputation changes, straight from the immutable ledger.
 * This is the "activity feed" of the dashboard.
 * ========================================================================== */

$recentEvents = db_all(
    'SELECT delta, reason, reference_type, reference_id, note, created_at
       FROM reputation_ledger
      WHERE user_id = ?
      ORDER BY created_at DESC
      LIMIT 10',
    [$userId]
);

$activity = array_map(static function (array $row): array {
    return [
        'delta'      => (int)    $row['delta'],
        'reason'     => (string) $row['reason'],
        'ref_type'   => $row['reference_type'],
        'ref_id'     => $row['reference_id'] !== null ? (int) $row['reference_id'] : null,
        'note'       => $row['note'],
        'created_at' => gmdate('c', strtotime((string) $row['created_at'])),
    ];
}, $recentEvents);


/* ══════════════════════════════════════════════════════════════════════════
 * 07. REFERRAL STATS
 * --------------------------------------------------------------------------
 * How many users this account has referred. Bonus value for the dashboard.
 * ========================================================================== */

$referralCount = (int) db_scalar(
    'SELECT COUNT(*) FROM referrals WHERE referrer_id = ?',
    [$userId]
);

$referralPoints = (int) db_scalar(
    'SELECT COALESCE(SUM(points_awarded), 0)
       FROM referrals WHERE referrer_id = ?',
    [$userId]
);


/* ══════════════════════════════════════════════════════════════════════════
 * 08. RESPONSE
 * --------------------------------------------------------------------------
 * Structured for the UI. Every top-level key is a distinct "panel" the
 * frontend can render independently.
 *
 * The "features" key tells the client which panels are currently live.
 * As we build posts/comments/etc., we flip these from false to true, and
 * the UI can progressively reveal sections without a code change.
 * ========================================================================== */

citadel_json_ok([
    'identity' => [
        'id'           => $userId,
        'username'     => $user['username'],
        'display_name' => $user['display_name'],
        'email'        => $email,
        'tagline'      => $user['tagline'],
        'avatar_url'   => $user['avatar_url'],
        'banner_url'   => $user['banner_url'],
        'accent_color' => $user['accent_color'],
        'theme'        => $user['theme_preference'],
        'visibility'   => $user['visibility'] ?? 'public',
    ],

    'account' => [
        'is_active'         => (bool) $user['is_active'],
        'is_banned'         => (bool) $user['is_banned'],
        'email_verified'    => (bool) $user['email_verified'],
        'is_premium'        => (bool) $user['is_premium'],
        'premium_since'     => $user['premium_since']
            ? gmdate('c', strtotime((string) $user['premium_since'])) : null,
        'member_since'      => $memberSince,
        'age' => [
            'days'   => $ageDays,
            'weeks'  => $ageWeeks,
            'months' => $ageMonths,
            'years'  => $ageYears,
            'human'  => $ageHuman,
        ],
        'last_login_at'     => $user['last_login_at']
            ? gmdate('c', strtotime((string) $user['last_login_at'])) : null,
    ],

    'stats' => [
        'reputation'             => (int) $user['reputation_points'],
        'badge_count'            => (int) $user['badge_count'],
        'post_count'             => (int) $user['post_count'],
        'comment_given_count'    => (int) $user['comment_given_count'],
        'comment_received_count' => (int) $user['comment_received_count'],
        'connection_count'       => (int) $user['connection_count'],
        'checkin_streak'         => (int) $user['checkin_streak'],
        'checkin_longest_streak' => (int) $user['checkin_longest_streak'],
        'reactions' => [
            'given_like'    => (int) $user['reactions_given_like'],
            'given_heart'   => (int) $user['reactions_given_heart'],
            'recv_like'     => (int) $user['reactions_recv_like'],
            'recv_heart'    => (int) $user['reactions_recv_heart'],
        ],
        'referrals' => [
            'count'  => $referralCount,
            'points' => $referralPoints,
            'code'   => $user['referral_code'],
        ],
    ],

    'rank' => [
        'position'    => $myRank,
        'total_users' => $totalUsers,
        'percentile'  => $percentile,
        'avg_rep'     => $avgRep,
        'your_rep'    => (int) $user['reputation_points'],
        'above_avg'   => (int) $user['reputation_points'] > $avgRep,
    ],

    'badges'   => $badges,
    'activity' => $activity,

    'community' => [
        'total_users'     => $totalUsers,
        'average_rep'     => $avgRep,
        'total_rep'       => $totalRep,
        'total_badges'    => (int) db_scalar('SELECT COUNT(*) FROM badges WHERE is_active = 1'),
    ],

    // Feature availability flags — UI uses these to render or hide panels
    'features' => [
        'posts'          => false,   // enabled when /v1/posts/* ships
        'comments'       => false,
        'reactions'      => false,
        'connections'    => false,
        'notifications'  => false,
        'feed'           => false,
        'search'         => false,
        'premium'        => false,
    ],
]);