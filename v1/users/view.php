<?php
/* ============================================================================
 * ███ USERS/VIEW.PHP ███
 * MyCitadel — Public Profile View
 * ----------------------------------------------------------------------------
 * Route : GET /v1/users/view?id=N
 * Auth  : Required
 * Rate  : 60 requests per minute per IP
 *
 * ────────────────────────────────────────────────────────────────────────────
 * THE AUTHORIZATION MATRIX (this is the whole point of the endpoint)
 * ────────────────────────────────────────────────────────────────────────────
 *
 *   Viewer is the target      → FULL PROFILE (own data)
 *   Target blocked viewer     → 404 (silent)
 *   Viewer blocked target     → 404 (silent)
 *   Target visibility=hidden  → 404 (silent)
 *   Connected                 → FULL PROFILE
 *   Target visibility=public  → LIMITED CARD
 *   Any other case            → 404 (silent)
 *
 * ────────────────────────────────────────────────────────────────────────────
 * WHY 404 AND NOT 403
 * ────────────────────────────────────────────────────────────────────────────
 * A 403 tells an attacker "this user exists, you just can't see them."
 * A 404 says "nothing here." That's the enumeration defense.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * FULL PROFILE vs LIMITED CARD
 * ────────────────────────────────────────────────────────────────────────────
 * LIMITED CARD (public, not connected):
 *   id, username, display_name, avatar, banner, accent_color,
 *   bio, tagline, reputation, badge_count, member_since,
 *   connection_state
 *
 * FULL PROFILE (self or connected):
 *   Everything above PLUS: email (own only), phone (own only),
 *   real name (if user opted in), location, social links, full
 *   profile fields, premium status, last_login (own only)
 * ========================================================================== */

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';
require_once CITADEL_CONFIG . '/db.php';
require_once CITADEL_CONFIG . '/crypto.php';
require_once CITADEL_CONFIG . '/connections.php';

citadel_rate_limit('users_view', 60, 60);
citadel_require_auth('json');

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'GET') {
    header('Allow: GET');
    citadel_json_error('method_not_allowed', 'GET only.', 405);
}

$me       = (int) citadel_current_user_id();
$targetId = isset($_GET['id']) ? (int) $_GET['id'] : 0;

if ($targetId <= 0) {
    citadel_json_error('invalid_user', 'A valid user id is required.', 400);
}

// ── Fetch the target ──────────────────────────────────────────────────────
$target = db_one(
    'SELECT
        u.id, u.username, u.email_ct, u.email_nonce,
        u.is_premium, u.is_active, u.is_banned, u.created_at, u.last_login_at,
        p.visibility, p.display_name, p.tagline, p.bio, p.personal_motto,
        p.avatar_url, p.avatar_frame_id, p.banner_url, p.banner_frame_id,
        p.accent_color, p.theme_preference, p.pronouns,
        p.country_code, p.state_code, p.timezone,
        p.job_title, p.company_name, p.industry, p.education,
        p.hobbies_and_interests, p.looking_for, p.availability,
        p.website_url, p.github_url, p.twitter_url, p.linkedin_url,
        p.mastodon_url, p.bluesky_url, p.public_pgp_key,
        p.show_email, p.show_phone, p.show_location, p.show_birthday,
        p.show_real_name, p.show_social_links, p.show_premium,
        COALESCE(s.reputation_points, 0) AS reputation,
        COALESCE(s.badge_count, 0)       AS badge_count,
        COALESCE(s.post_count, 0)        AS post_count,
        COALESCE(s.connection_count, 0)  AS connection_count
      FROM users u
      LEFT JOIN user_profiles p ON p.user_id = u.id
      LEFT JOIN user_stats    s ON s.user_id = u.id
     WHERE u.id = ?
     LIMIT 1',
    [$targetId]
);

if ($target === null) {
    citadel_json_error('user_not_found', 'User not found.', 404);
}

// ── Authorization check ───────────────────────────────────────────────────
$visibility = citadel_rel_visibility($me, $targetId);
$state      = $visibility['state'];

// Silent 404 for anything the viewer shouldn't see
$isSelf     = ($me === $targetId);
$isConnected= ($state === 'connected');

// Rule: inactive/banned users are invisible to everyone but self
if ((int) $target['is_active'] !== 1 || (int) $target['is_banned'] === 1) {
    if (!$isSelf) {
        citadel_json_error('user_not_found', 'User not found.', 404);
    }
}

// Rule: hidden users are invisible to everyone but self and connections
if ($target['visibility'] === 'hidden' && !$isSelf && !$isConnected) {
    citadel_json_error('user_not_found', 'User not found.', 404);
}

// Rule: blocked → 404 in both directions
if ($state === 'blocked' && !$isSelf) {
    citadel_json_error('user_not_found', 'User not found.', 404);
}

// Rule: not connected and not public → 404
$isPublic = $target['visibility'] === 'public' || $target['visibility'] === null;
if (!$isSelf && !$isConnected && !$isPublic) {
    citadel_json_error('user_not_found', 'User not found.', 404);
}

// ── Decide response shape ─────────────────────────────────────────────────
$showFull = $isSelf || $isConnected;

$profile = [
    'id'              => (int) $target['id'],
    'username'        => (string) $target['username'],
    'display_name'    => $target['display_name'],
    'tagline'         => $target['tagline'],
    'bio'             => $target['bio'],
    'avatar_url'      => $target['avatar_url'],
    'avatar_frame_id' => $target['avatar_frame_id'] !== null ? (int) $target['avatar_frame_id'] : null,
    'banner_url'      => $target['banner_url'],
    'banner_frame_id' => $target['banner_frame_id'] !== null ? (int) $target['banner_frame_id'] : null,
    'accent_color'    => (string) $target['accent_color'],
    'pronouns'        => $target['pronouns'],
    'reputation'      => (int) $target['reputation'],
    'badge_count'     => (int) $target['badge_count'],
    'post_count'      => (int) $target['post_count'],
    'connection_count'=> (int) $target['connection_count'],
    'member_since'    => gmdate('c', strtotime((string) $target['created_at'])),
    'connection_state'=> (function () use ($state, $visibility, $me, $isSelf): string {
        if ($isSelf) return 'self';
        if ($state !== 'pending') return $state;
        // Distinguish pending_in vs pending_out
        $initiatedBy = $visibility['initiated_by'] ?? null;
        return ((int) $initiatedBy === $me) ? 'pending_out' : 'pending_in';
    })(),    
    'is_self'         => $isSelf,
];

// Add fields visible only to connections or self
if ($showFull) {
    // Location — respect show_location toggle unless it's you
    if ($isSelf || (int) $target['show_location'] === 1) {
        $profile['location'] = [
            'country_code' => $target['country_code'],
            'state_code'   => $target['state_code'],
            'timezone'     => $target['timezone'],
        ];
    }

    // Professional info — always public
    $profile['work'] = [
        'job_title'   => $target['job_title'],
        'company'     => $target['company_name'],
        'industry'    => $target['industry'],
        'education'   => $target['education'],
    ];

    // Interests
    $profile['interests'] = [
        'hobbies'      => $target['hobbies_and_interests'],
        'looking_for'  => $target['looking_for'],
        'availability' => $target['availability'],
    ];

    // Social links — respect show_social_links toggle unless it's you
    if ($isSelf || (int) $target['show_social_links'] === 1) {
        $profile['links'] = [
            'website'    => $target['website_url'],
            'github'     => $target['github_url'],
            'twitter'    => $target['twitter_url'],
            'linkedin'   => $target['linkedin_url'],
            'mastodon'   => $target['mastodon_url'],
            'bluesky'    => $target['bluesky_url'],
            'pgp_key'    => $target['public_pgp_key'],
        ];
    }

    // Premium status — respect show_premium toggle unless self
    if ($isSelf || (int) $target['show_premium'] === 1) {
        $profile['is_premium'] = (bool) $target['is_premium'];
    }
}

// Add fields visible only to self
if ($isSelf) {
    $profile['email'] = citadel_crypto_decrypt(
        $target['email_ct'],
        $target['email_nonce'],
        $targetId
    );
    $profile['last_login_at'] = $target['last_login_at']
        ? gmdate('c', strtotime((string) $target['last_login_at']))
        : null;
    $profile['visibility'] = $target['visibility'];
    $profile['privacy_toggles'] = [
        'show_email'        => (bool) $target['show_email'],
        'show_phone'        => (bool) $target['show_phone'],
        'show_location'     => (bool) $target['show_location'],
        'show_birthday'     => (bool) $target['show_birthday'],
        'show_real_name'    => (bool) $target['show_real_name'],
        'show_social_links' => (bool) $target['show_social_links'],
        'show_premium'      => (bool) $target['show_premium'],
    ];
}

// ── Badges ────────────────────────────────────────────────────────────────
$badgeRows = db_all(
    'SELECT b.slug, b.name, b.description, b.tier, b.color, b.icon_svg,
            ub.earned_at, ub.is_featured
       FROM user_badges ub
       JOIN badges b ON b.id = ub.badge_id
      WHERE ub.user_id = ?
      ORDER BY ub.is_featured DESC, ub.earned_at DESC
      LIMIT 24',
    [$targetId]
);

$profile['badges'] = array_map(static function (array $r): array {
    return [
        'slug'        => (string) $r['slug'],
        'name'        => (string) $r['name'],
        'description' => (string) $r['description'],
        'tier'        => (string) $r['tier'],
        'color'       => (string) $r['color'],
        'icon_svg'    => $r['icon_svg'],
        'earned_at'   => gmdate('c', strtotime((string) $r['earned_at'])),
        'is_featured' => (bool) $r['is_featured'],
    ];
}, $badgeRows);

citadel_json_ok([
    'profile' => $profile,
    'view'    => $showFull ? 'full' : 'limited',
]);