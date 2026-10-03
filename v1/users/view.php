<?php
/* ============================================================================
 * ███ USERS/VIEW.PHP ███
 * MyCitadel — Profile Viewer (Public + Connected + Self)
 * ----------------------------------------------------------------------------
 * Route : GET /v1/users/view?id=N
 * Auth  : Required
 * Rate  : 60 requests per minute per IP (per-viewer)
 *
 * ══════════════════════════════════════════════════════════════════════════
 * THE AUTHORIZATION MATRIX — THIS IS THE WHOLE POINT OF THE ENDPOINT
 * ══════════════════════════════════════════════════════════════════════════
 *
 *   Viewer is the target          → FULL PROFILE (own data)
 *   Target blocked viewer         → 404 (silent)
 *   Viewer blocked target         → 404 (silent)
 *   Target inactive or banned     → 404 (silent, unless self)
 *   Target visibility=hidden      → 404 (silent, unless self or connected)
 *   Target visibility=connections → 404 (unless self or connected)
 *   Target visibility=public      → MINIMAL CARD
 *   Connected                     → FULL PROFILE
 *
 * ══════════════════════════════════════════════════════════════════════════
 * WHY 404 AND NOT 403
 * ══════════════════════════════════════════════════════════════════════════
 *   A 403 tells an attacker "this user exists, you just can't see them."
 *   A 404 says "nothing here." Every authorization failure returns the
 *   same shape so enumeration via error codes is impossible.
 *
 * ══════════════════════════════════════════════════════════════════════════
 * MINIMAL CARD vs FULL PROFILE
 * ══════════════════════════════════════════════════════════════════════════
 *   MINIMAL CARD (public, not connected):
 *     id, username, connection_state, is_self
 *     — NOTHING ELSE. No avatar, no bio, no badges, no stats, no age.
 *     — The card exists only so a viewer knows who they're requesting to
 *       connect with. Every other field is considered private until the
 *       connection is mutual.
 *
 *   FULL PROFILE (self or accepted connection):
 *     Everything, gated by the target's own privacy toggles.
 *
 * ══════════════════════════════════════════════════════════════════════════
 * SQL INJECTION DEFENSES
 * ══════════════════════════════════════════════════════════════════════════
 *   • Every query uses PDO prepared statements with positional binds.
 *   • The only user-supplied value is $targetId, which is cast to int at
 *     the boundary. Even if it were a string, it goes through a bind.
 *   • No string concatenation in any SQL. No dynamic column names.
 *   • PDO::ATTR_EMULATE_PREPARES = false (see config/db.php), so the DB
 *     does true server-side parameter binding.
 *
 * ══════════════════════════════════════════════════════════════════════════
 * ENUMERATION HARDENING
 * ══════════════════════════════════════════════════════════════════════════
 *   • Every failure path returns the same JSON shape and same 404 status.
 *   • Failed lookups are logged (hashed) for anomaly detection.
 *   • Viewing a profile is audit-logged so scraping patterns are visible.
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

$me = (int) citadel_current_user_id();

/* ══════════════════════════════════════════════════════════════════════════
 * 01. INPUT VALIDATION
 * ========================================================================== */

$targetId = isset($_GET['id']) ? (int) $_GET['id'] : 0;

if ($targetId <= 0) {
    // Same shape as a real 404 — never distinguish "malformed id" from
    // "user not found" so probes can't be fingerprinted.
    citadel_json_error('user_not_found', 'User not found.', 404);
}

/* ══════════════════════════════════════════════════════════════════════════
 * 02. FETCH THE TARGET
 * --------------------------------------------------------------------------
 * Single query. All fields fetched in one round trip. If the row doesn't
 * exist, we return 404 with the same shape as every other failure.
 * ========================================================================== */

$target = db_one(
    'SELECT
        u.id, u.username, u.email_ct, u.email_nonce,
        u.is_premium, u.is_active, u.is_banned,
        u.created_at, u.last_login_at, u.last_active_at,
        p.visibility, p.display_name, p.tagline, p.bio,
        p.personal_motto, p.pronouns,
        p.avatar_url, p.avatar_frame_id,
        p.banner_url, p.banner_frame_id,
        p.wallpaper_url, p.wallpaper_opacity, p.wallpaper_blur,
        p.accent_color, p.theme_preference,
        p.border_thickness, p.border_color, p.border_style,
        p.font_heading, p.font_body, p.font_mono,
        p.music_video_id, p.music_autoplay,
        p.country_code, p.state_code, p.timezone,
        p.job_title, p.company_name, p.years_at_company,
        p.work_description, p.industry, p.education,
        p.relationship_status, p.has_kids, p.kids_count,
        p.languages_spoken, p.personality_type, p.zodiac_sign,
        p.looking_for, p.availability, p.contact_preference,
        p.favorite_movies, p.favorite_books, p.favorite_songs,
        p.favorite_shows, p.favorite_games,
        p.favorite_quotes, p.favorite_food,
        p.hobbies_and_interests,
        p.website_url, p.facebook_url, p.twitter_url, p.instagram_url,
        p.tiktok_url, p.linkedin_url, p.youtube_url, p.threads_url,
        p.mastodon_url, p.bluesky_url, p.discord_handle,
        p.steam_id, p.psn_handle, p.xbox_gamertag,
        p.kick_url, p.twitch_url, p.podcast_url,
        p.github_url, p.stackoverflow_url,
        p.hackerone_url, p.bugcrowd_url, p.intigriti_url, p.yeswehack_url,
        p.public_pgp_key, p.signal_username,
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
    citadel_log('security', 'info', 'Profile view: target not found', [
        'viewer_id' => $me,
        'target_id' => $targetId,
    ]);
    citadel_json_error('user_not_found', 'User not found.', 404);
}

/* ══════════════════════════════════════════════════════════════════════════
 * 03. AUTHORIZATION
 * --------------------------------------------------------------------------
 * Every rule below can only DEMOTE access. None of them can grant it.
 * The order matters: we check the strictest rules first, and every branch
 * funnels to the same 404 response so no timing or shape difference leaks.
 * ========================================================================== */

$visibility = citadel_rel_visibility($me, $targetId);
$state      = is_array($visibility) ? ($visibility['state'] ?? 'none') : 'none';

$isSelf      = ($me === (int) $target['id']);
$isConnected = ($state === 'connected');

// ── Rule 1: inactive or banned — invisible to everyone but self ──────────
if (!$isSelf && ((int) $target['is_active'] !== 1 || (int) $target['is_banned'] === 1)) {
    citadel_log('security', 'info', 'Profile view: target inactive/banned', [
        'viewer_id' => $me,
        'target_id' => $targetId,
        'active'    => (int) $target['is_active'],
        'banned'    => (int) $target['is_banned'],
    ]);
    citadel_json_error('user_not_found', 'User not found.', 404);
}

// ── Rule 2: blocked (either direction) — invisible ───────────────────────
if (!$isSelf && $state === 'blocked') {
    citadel_log('security', 'info', 'Profile view: blocked relationship', [
        'viewer_id' => $me,
        'target_id' => $targetId,
    ]);
    citadel_json_error('user_not_found', 'User not found.', 404);
}

// ── Rule 3: hidden visibility — invisible to everyone but self/connections ─
$targetVisibility = $target['visibility'] ?? 'public';

if (!$isSelf && !$isConnected && $targetVisibility === 'hidden') {
    citadel_log('security', 'info', 'Profile view: hidden visibility', [
        'viewer_id' => $me,
        'target_id' => $targetId,
    ]);
    citadel_json_error('user_not_found', 'User not found.', 404);
}

// ── Rule 4: connections_only — invisible to non-connections ──────────────
if (!$isSelf && !$isConnected && $targetVisibility === 'connections_only') {
    citadel_log('security', 'info', 'Profile view: connections_only visibility', [
        'viewer_id' => $me,
        'target_id' => $targetId,
    ]);
    citadel_json_error('user_not_found', 'User not found.', 404);
}

// ── Rule 5: unknown visibility → default deny ────────────────────────────
$allowedVisibilities = ['public', 'connections_only', 'hidden'];
if (!in_array($targetVisibility, $allowedVisibilities, true) && $targetVisibility !== null) {
    citadel_log('security', 'warning', 'Profile view: unknown visibility value', [
        'viewer_id'  => $me,
        'target_id'  => $targetId,
        'visibility' => $targetVisibility,
    ]);
    citadel_json_error('user_not_found', 'User not found.', 404);
}

/* ══════════════════════════════════════════════════════════════════════════
 * 04. RESPONSE SHAPE DECISION
 * --------------------------------------------------------------------------
 * At this point we know the viewer is authorized to see SOMETHING. The only
 * question is how much.
 *
 *   $showFull = self OR accepted connection
 *   Otherwise = minimal card
 * ========================================================================== */

$showFull = $isSelf || $isConnected;

/* ══════════════════════════════════════════════════════════════════════════
 * 05. BUILD THE PROFILE
 * --------------------------------------------------------------------------
 * Start with the MINIMAL card, which is the same for every viewer. Then,
 * only if $showFull is true, add the fields the viewer is allowed to see.
 *
 * This is a whitelist-by-default pattern: the base array contains only
 * fields that are safe for everyone, and every additional field is gated
 * behind an explicit condition. There is no "start with everything and
 * remove some" logic, which is the pattern that caused the leak.
 * ========================================================================== */

$profile = [
    'id'               => (int) $target['id'],
    'username'         => (string) $target['username'],
    'connection_state' => (function () use ($state, $visibility, $me, $isSelf): string {
        if ($isSelf) return 'self';
        if ($state !== 'pending') return $state;
        $initiatedBy = is_array($visibility) ? ($visibility['initiated_by'] ?? null) : null;
        return ((int) $initiatedBy === $me) ? 'pending_out' : 'pending_in';
    })(),
    'is_self'          => $isSelf,
];

/* ── Everything else gated behind $showFull ─────────────────────────────── */

if ($showFull) {

    // ── Identity ─────────────────────────────────────────────────────────
    $profile['display_name']    = $target['display_name'];
    $profile['tagline']         = $target['tagline'];
    $profile['bio']             = $target['bio'];
    $profile['personal_motto']  = $target['personal_motto'];
    $profile['pronouns']        = $target['pronouns'];

    // ── Images ───────────────────────────────────────────────────────────
    $profile['avatar_url']      = $target['avatar_url'];
    $profile['avatar_frame_id'] = $target['avatar_frame_id'] !== null
        ? (int) $target['avatar_frame_id'] : null;
    $profile['banner_url']      = $target['banner_url'];
    $profile['banner_frame_id'] = $target['banner_frame_id'] !== null
        ? (int) $target['banner_frame_id'] : null;
    $profile['accent_color']    = (string) $target['accent_color'];

    // ── Stats ────────────────────────────────────────────────────────────
    $profile['reputation']       = (int) $target['reputation'];
    $profile['badge_count']      = (int) $target['badge_count'];
    $profile['post_count']       = (int) $target['post_count'];
    $profile['connection_count'] = (int) $target['connection_count'];
    $profile['member_since']     = gmdate('c', strtotime((string) $target['created_at']));

    // ── Location (toggle-gated) ──────────────────────────────────────────
    if ($isSelf || (int) $target['show_location'] === 1) {
        $profile['location'] = [
            'country_code' => $target['country_code'],
            'state_code'   => $target['state_code'],
            'timezone'     => $target['timezone'],
        ];
    }

    // ── Work ─────────────────────────────────────────────────────────────
    $profile['work'] = [
        'job_title'        => $target['job_title'],
        'company'          => $target['company_name'],
        'years_at_company' => $target['years_at_company'] !== null
            ? (int) $target['years_at_company'] : null,
        'description'      => $target['work_description'],
        'industry'         => $target['industry'],
        'education'        => $target['education'],
    ];

    // ── Personal ─────────────────────────────────────────────────────────
    $profile['personal'] = [
        'relationship_status' => $target['relationship_status'],
        'has_kids'            => $target['has_kids'] !== null
            ? (bool) $target['has_kids'] : null,
        'kids_count'          => $target['kids_count'] !== null
            ? (int) $target['kids_count'] : null,
        'languages_spoken'    => $target['languages_spoken'],
        'personality_type'    => $target['personality_type'],
        'zodiac_sign'         => $target['zodiac_sign'],
        'availability'        => $target['availability'],
        'contact_preference'  => $target['contact_preference'],
    ];

    // ── Interests ────────────────────────────────────────────────────────
    $lookingForRaw = $target['looking_for'] ?? '';
    $lookingFor    = ($lookingForRaw !== '' && $lookingForRaw !== null)
        ? array_values(array_filter(array_map('trim', explode(',', (string) $lookingForRaw))))
        : [];

    $profile['interests'] = [
        'hobbies'     => $target['hobbies_and_interests'],
        'looking_for' => $lookingFor,
    ];

    // ── Favorites ────────────────────────────────────────────────────────
    $decodeJsonList = static function ($raw): array {
        if ($raw === null || $raw === '') return [];
        $decoded = json_decode((string) $raw, true);
        return is_array($decoded)
            ? array_values(array_filter($decoded, static fn($v) => is_string($v) && $v !== ''))
            : [];
    };

    $profile['favorites'] = [
        'movies' => $decodeJsonList($target['favorite_movies']),
        'books'  => $decodeJsonList($target['favorite_books']),
        'songs'  => $decodeJsonList($target['favorite_songs']),
        'shows'  => $decodeJsonList($target['favorite_shows']),
        'games'  => $decodeJsonList($target['favorite_games']),
        'quotes' => $target['favorite_quotes'],
        'food'   => $target['favorite_food'],
    ];

    // ── Social links (toggle-gated) ──────────────────────────────────────
    if ($isSelf || (int) $target['show_social_links'] === 1) {
        $profile['links'] = [
            'website'       => $target['website_url'],
            'facebook'      => $target['facebook_url'],
            'twitter'       => $target['twitter_url'],
            'instagram'     => $target['instagram_url'],
            'tiktok'        => $target['tiktok_url'],
            'linkedin'      => $target['linkedin_url'],
            'youtube'       => $target['youtube_url'],
            'threads'       => $target['threads_url'],
            'mastodon'      => $target['mastodon_url'],
            'bluesky'       => $target['bluesky_url'],
            'discord'       => $target['discord_handle'],
            'steam'         => $target['steam_id'],
            'psn'           => $target['psn_handle'],
            'xbox'          => $target['xbox_gamertag'],
            'kick'          => $target['kick_url'],
            'twitch'        => $target['twitch_url'],
            'podcast'       => $target['podcast_url'],
            'github'        => $target['github_url'],
            'stackoverflow' => $target['stackoverflow_url'],
            'hackerone'     => $target['hackerone_url'],
            'bugcrowd'      => $target['bugcrowd_url'],
            'intigriti'     => $target['intigriti_url'],
            'yeswehack'     => $target['yeswehack_url'],
            'signal'        => $target['signal_username'],
            'pgp_key'       => $target['public_pgp_key'],
        ];
    }

    // ── Premium (toggle-gated) ───────────────────────────────────────────
    if ($isSelf || (int) $target['show_premium'] === 1) {
        $profile['is_premium'] = (bool) $target['is_premium'];
    }

    // ── Theme (self only — connections don't need your private styling) ──
    if ($isSelf) {
        $profile['theme'] = [
            'wallpaper_opacity' => (int) $target['wallpaper_opacity'],
            'wallpaper_blur'    => (int) $target['wallpaper_blur'],
            'accent_color'      => $target['accent_color'],
            'theme_preference'  => $target['theme_preference'],
            'border_style'      => $target['border_style'],
            'border_thickness'  => (int) $target['border_thickness'],
            'border_color'      => $target['border_color'],
            'font_heading'      => $target['font_heading'],
            'font_body'         => $target['font_body'],
            'font_mono'         => $target['font_mono'],
            'music_video_id'    => $target['music_video_id'],
            'music_autoplay'    => (bool) $target['music_autoplay'],
        ];
    }

    // ── Badges (self or connections only) ────────────────────────────────
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
}

/* ══════════════════════════════════════════════════════════════════════════
 * 06. SELF-ONLY FIELDS
 * --------------------------------------------------------------------------
 * Extra fields only the account owner ever sees. None of these are ever
 * returned for any viewer other than self, regardless of connection state.
 * ========================================================================== */

if ($isSelf) {
    $profile['email'] = citadel_crypto_decrypt(
        $target['email_ct'],
        $target['email_nonce'],
        $targetId
    );
    $profile['last_login_at'] = $target['last_login_at']
        ? gmdate('c', strtotime((string) $target['last_login_at']))
        : null;
    $profile['last_active_at'] = $target['last_active_at']
        ? gmdate('c', strtotime((string) $target['last_active_at']))
        : null;
    $profile['visibility']     = $targetVisibility;
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

/* ══════════════════════════════════════════════════════════════════════════
 * 07. AUDIT LOG
 * --------------------------------------------------------------------------
 * Every successful profile view is logged with the viewer, the target,
 * and whether it was full or minimal. This is what lets you spot scraping
 * patterns after the fact — someone pulling 500 profiles in an hour.
 * ========================================================================== */

citadel_log('security', 'info', 'Profile viewed', [
    'viewer_id'      => $me,
    'target_id'      => $targetId,
    'view_mode'      => $showFull ? 'full' : 'minimal',
    'relationship'   => $state,
    'self_view'      => $isSelf,
]);

/* ══════════════════════════════════════════════════════════════════════════
 * 08. RESPONSE
 * ========================================================================== */

citadel_json_ok([
    'profile' => $profile,
    'view'    => $showFull ? 'full' : 'limited',
]);