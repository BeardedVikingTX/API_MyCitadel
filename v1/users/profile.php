<?php
/* ============================================================================
 * ███ USERS/PROFILE.PHP ███
 * Route : GET /v1/users/profile
 * Auth  : Required
 *
 * Returns the CURRENT USER'S full editable profile, with all PII decrypted.
 * This is the endpoint the profile editor page loads.
 * ========================================================================== */

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';
require_once CITADEL_CONFIG . '/db.php';
require_once CITADEL_CONFIG . '/crypto.php';
require_once CITADEL_CONFIG . '/profile.php';

citadel_rate_limit('profile_get', 60, 60);
citadel_require_auth('json');

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'GET') {
    header('Allow: GET');
    citadel_json_error('method_not_allowed', 'GET only.', 405);
}

$me = (int) citadel_current_user_id();

$row = db_one('SELECT * FROM user_profiles WHERE user_id = ? LIMIT 1', [$me]);

if ($row === null) {
    citadel_json_error('profile_missing', 'Profile row not found.', 500);
}

// Decrypt PII fields
$piiFields = ['first_name', 'middle_name', 'last_name', 'phone',
              'backup_email', 'recovery_phone', 'birthday',
              'address_line1', 'address_line2', 'city', 'zip'];

$decrypted = [];
foreach ($piiFields as $f) {
    $decrypted[$f] = citadel_profile_decrypt_pii(
        $row[$f . '_ct'] ?? null,
        $row[$f . '_nonce'] ?? null,
        $me
    );
}

// Decode JSON fields
$jsonFields = ['favorite_movies', 'favorite_books', 'favorite_songs',
               'favorite_shows', 'favorite_games'];
$decoded = [];
foreach ($jsonFields as $f) {
    $decoded[$f] = ($row[$f] ?? null) !== null
        ? json_decode((string) $row[$f], true)
        : [];
}

// Split looking_for set
$lookingFor = ($row['looking_for'] ?? null) !== null
    ? explode(',', (string) $row['looking_for'])
    : [];

// Build response — only return fields the user can edit
citadel_json_ok([
    'profile' => [
        // Public
        'display_name'      => $row['display_name'],
        'tagline'           => $row['tagline'],
        'bio'               => $row['bio'],
        'personal_motto'    => $row['personal_motto'],
        'pronouns'          => $row['pronouns'],

        // Location
        'country_code'      => $row['country_code'],
        'state_code'        => $row['state_code'],
        'timezone'          => $row['timezone'],

        // PII (decrypted)
        'first_name'        => $decrypted['first_name'],
        'middle_name'       => $decrypted['middle_name'],
        'last_name'         => $decrypted['last_name'],
        'phone'             => $decrypted['phone'],
        'backup_email'      => $decrypted['backup_email'],
        'recovery_phone'    => $decrypted['recovery_phone'],
        'birthday'          => $decrypted['birthday'],
        'birth_year'        => $row['birth_year'] !== null ? (int) $row['birth_year'] : null,
        'address_line1'     => $decrypted['address_line1'],
        'address_line2'     => $decrypted['address_line2'],
        'city'              => $decrypted['city'],
        'zip'               => $decrypted['zip'],

        // Work
        'job_title'         => $row['job_title'],
        'company_name'      => $row['company_name'],
        'years_at_company'  => $row['years_at_company'] !== null ? (int) $row['years_at_company'] : null,
        'work_description'  => $row['work_description'],
        'industry'          => $row['industry'],
        'education'         => $row['education'],

        // Personal
        'relationship_status' => $row['relationship_status'],
        'has_kids'          => $row['has_kids'] !== null ? (bool) $row['has_kids'] : null,
        'kids_count'        => $row['kids_count'] !== null ? (int) $row['kids_count'] : null,
        'languages_spoken'  => $row['languages_spoken'],
        'personality_type'  => $row['personality_type'],
        'zodiac_sign'       => $row['zodiac_sign'],
        'looking_for'       => $lookingFor,
        'availability'      => $row['availability'],
        'contact_preference'=> $row['contact_preference'],

        // Favorites
        'favorite_movies'   => $decoded['favorite_movies'],
        'favorite_books'    => $decoded['favorite_books'],
        'favorite_songs'    => $decoded['favorite_songs'],
        'favorite_shows'    => $decoded['favorite_shows'],
        'favorite_games'    => $decoded['favorite_games'],
        'favorite_quotes'   => $row['favorite_quotes'],
        'favorite_food'     => $row['favorite_food'],
        'hobbies_and_interests' => $row['hobbies_and_interests'],

        // Links
        'website_url'       => $row['website_url'],
        'facebook_url'      => $row['facebook_url'],
        'twitter_url'       => $row['twitter_url'],
        'instagram_url'     => $row['instagram_url'],
        'tiktok_url'        => $row['tiktok_url'],
        'linkedin_url'      => $row['linkedin_url'],
        'youtube_url'       => $row['youtube_url'],
        'threads_url'       => $row['threads_url'],
        'mastodon_url'      => $row['mastodon_url'],
        'bluesky_url'       => $row['bluesky_url'],
        'discord_handle'    => $row['discord_handle'],
        'steam_id'          => $row['steam_id'],
        'psn_handle'        => $row['psn_handle'],
        'xbox_gamertag'     => $row['xbox_gamertag'],
        'kick_url'          => $row['kick_url'],
        'twitch_url'        => $row['twitch_url'],
        'podcast_url'       => $row['podcast_url'],
        'github_url'        => $row['github_url'],
        'stackoverflow_url' => $row['stackoverflow_url'],
        'hackerone_url'     => $row['hackerone_url'],
        'bugcrowd_url'      => $row['bugcrowd_url'],
        'intigriti_url'     => $row['intigriti_url'],
        'yeswehack_url'     => $row['yeswehack_url'],
        'public_pgp_key'    => $row['public_pgp_key'],
        'signal_username'   => $row['signal_username'],

        // Theme
        'avatar_url'        => $row['avatar_url'],
        'avatar_frame_id'   => $row['avatar_frame_id'] !== null ? (int) $row['avatar_frame_id'] : null,
        'banner_url'        => $row['banner_url'],
        'banner_frame_id'   => $row['banner_frame_id'] !== null ? (int) $row['banner_frame_id'] : null,
        'wallpaper_url'     => $row['wallpaper_url'],
        'wallpaper_opacity' => (int) $row['wallpaper_opacity'],
        'wallpaper_blur'    => (int) $row['wallpaper_blur'],
        'accent_color'      => $row['accent_color'],
        'theme_preference'  => $row['theme_preference'],
        'border_thickness'  => (int) $row['border_thickness'],
        'border_color'      => $row['border_color'],
        'border_style'      => $row['border_style'],
        'font_heading'      => $row['font_heading'],
        'font_body'         => $row['font_body'],
        'font_mono'         => $row['font_mono'],
        'music_video_id'    => $row['music_video_id'],
        'music_autoplay'    => (bool) $row['music_autoplay'],

        // Visibility
        'visibility'        => $row['visibility'],

        // Privacy toggles
        'show_email'        => (bool) $row['show_email'],
        'show_phone'        => (bool) $row['show_phone'],
        'show_location'     => (bool) $row['show_location'],
        'show_birthday'     => (bool) $row['show_birthday'],
        'show_real_name'    => (bool) $row['show_real_name'],
        'show_social_links' => (bool) $row['show_social_links'],
        'show_premium'      => (bool) $row['show_premium'],
    ],
    // Constraints the editor UI should use for dropdowns, sliders, etc.
    'options' => [
        'fonts_heading' => CITADEL_FONTS_HEADING,
        'fonts_body'    => CITADEL_FONTS_BODY,
        'fonts_mono'    => CITADEL_FONTS_MONO,
        'border_styles' => ['solid','dashed','dotted','double','glow','none'],
        'relationship_statuses' => ['single','married','divorced','widowed','complicated','prefer_not_to_say'],
        'availabilities' => ['open_to_work','busy','on_vacation','dm_me','offline'],
        'contact_preferences' => ['email','dm','none'],
        'looking_for_options' => ['friends','networking','collaborators','mentors','dating','all'],
    ],
]);