<?php
/* ============================================================================
 * ███ USERS/PROFILE_UPDATE.PHP ███
 * Route : POST /v1/users/profile_update
 * Body  : Any subset of editable profile fields
 *
 * Generic, data-driven updater. Every field is validated by
 * citadel_profile_validate() before being written.
 *
 * IDOR-proof: writes are ALWAYS scoped to citadel_current_user_id().
 * You cannot update another user's profile, no matter what you send.
 *
 * REPUTATION REWARDS
 *   Fields earn points the FIRST time they transition empty → non-empty.
 *   Re-editing is free. This is enforced by comparing a snapshot of the
 *   row BEFORE the UPDATE with the row AFTER.
 *
 *   The whole reward block is wrapped in try/catch and can NEVER fail the
 *   request — reputation is cosmetic and must not block a profile save.
 * ========================================================================== */

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';
require_once CITADEL_CONFIG . '/db.php';
require_once CITADEL_CONFIG . '/crypto.php';
require_once CITADEL_CONFIG . '/profile.php';
require_once CITADEL_CONFIG . '/reputation.php';
require_once CITADEL_CONFIG . '/badges.php';

citadel_rate_limit('profile_update', 30, 60);
citadel_require_csrf();
citadel_require_auth('json');

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    header('Allow: POST');
    citadel_json_error('method_not_allowed', 'POST only.', 405);
}

$me   = (int) citadel_current_user_id();
$body = citadel_input_json();

if (empty($body)) {
    citadel_json_error('no_changes', 'No fields provided.', 400);
}

$fields = citadel_profile_fields();

/* ══════════════════════════════════════════════════════════════════════════
 * 01. REWARD TRACKING — snapshot BEFORE the UPDATE
 * --------------------------------------------------------------------------
 * Only these fields earn reputation on first fill. They represent the
 * "core identity" a new Citizen needs to have a complete profile.
 *
 * Points are deliberately modest. This is not a farming vector.
 * ========================================================================== */

$rewardFields = [
    'display_name'          => 25,
    'tagline'               => 15,
    'bio'                   => 25,
    'pronouns'              => 10,
    'personal_motto'        => 10,
    'avatar_url'            => 50,
    'banner_url'            => 30,
    'wallpaper_url'         => 30,
    'country_code'          => 10,
    'timezone'              => 10,
    'job_title'             => 15,
    'company_name'          => 15,
    'education'             => 15,
    'hobbies_and_interests' => 20,
    'languages_spoken'      => 10,
    'website_url'           => 15,
    'github_url'            => 15,
    'twitter_url'           => 10,
    'linkedin_url'          => 10,
];

$rewardFieldNames = array_keys($rewardFields);
$selectCols       = implode(',', $rewardFieldNames);

// Snapshot the row BEFORE any writes happen
$beforeRow = db_one(
    "SELECT {$selectCols} FROM user_profiles WHERE user_id = ? LIMIT 1",
    [$me]
);

/* ══════════════════════════════════════════════════════════════════════════
 * 02. BUILD THE UPDATE LIST
 * ========================================================================== */

$setClauses  = [];
$params      = [];
$updatedKeys = [];

// PII fields are encrypted — map field name → [ct_col, nonce_col]
$piiFields = ['first_name', 'middle_name', 'last_name', 'phone',
              'backup_email', 'recovery_phone', 'birthday',
              'address_line1', 'address_line2', 'city', 'zip'];

foreach ($body as $name => $value) {

    // Ignore unknown fields silently (avoid leaking schema info)
    if (!isset($fields[$name])) {
        continue;
    }

    // Visibility handled separately (own endpoint already exists)
    if ($name === 'visibility') {
        if (!in_array($value, ['public','connections_only','hidden'], true)) {
            citadel_json_error('invalid_visibility', 'Invalid visibility value.', 400);
        }
        $setClauses[] = 'visibility = ?';
        $params[]     = $value;
        $updatedKeys[] = $name;
        continue;
    }

    try {
        $normalized = citadel_profile_validate($name, $value, $fields[$name]);
    } catch (InvalidArgumentException $e) {
        citadel_json_error('invalid_field', $e->getMessage(), 400);
    }

    // PII: encrypt before storing
    if (in_array($name, $piiFields, true)) {
        [$ct, $nonce] = citadel_profile_encrypt_pii($normalized, $me);
        $setClauses[] = "{$name}_ct = ?";
        $setClauses[] = "{$name}_nonce = ?";
        $params[]     = $ct;
        $params[]     = $nonce;
        $updatedKeys[] = $name;
        continue;
    }

    // Plain write
    $setClauses[] = "{$name} = ?";
    $params[]     = $normalized;
    $updatedKeys[] = $name;
}

if (empty($setClauses)) {
    citadel_json_error('no_changes', 'No valid fields to update.', 400);
}

$setClauses[] = 'updated_at = UTC_TIMESTAMP()';
$params[]     = $me;

$sql = 'UPDATE user_profiles SET ' . implode(', ', $setClauses) . ' WHERE user_id = ?';

try {
    db_query($sql, $params);
} catch (Throwable $e) {
    citadel_log('api', 'error', 'Profile update failed', [
        'user_id' => $me,
        'fields'  => $updatedKeys,
        'error'   => $e->getMessage(),
    ]);
    citadel_json_error('update_failed', 'Could not update profile.', 500);
}

citadel_log('api', 'info', 'Profile updated', [
    'user_id' => $me,
    'fields'  => $updatedKeys,
]);

/* ══════════════════════════════════════════════════════════════════════════
 * 03. REWARDS — completely isolated, cannot fail the request
 * ========================================================================== */

try {
    // Read the row AFTER the update to compare against $beforeRow
    $afterRow = db_one(
        "SELECT {$selectCols} FROM user_profiles WHERE user_id = ? LIMIT 1",
        [$me]
    );

    if ($beforeRow !== null && $afterRow !== null) {

        $totalBonus   = 0;
        $earnedFields = [];

        foreach ($rewardFields as $field => $points) {
            $wasEmpty = trim((string) ($beforeRow[$field] ?? '')) === '';
            $nowSet   = trim((string) ($afterRow[$field]  ?? '')) !== '';

            if ($nowSet && $wasEmpty) {
                $totalBonus    += $points;
                $earnedFields[] = $field;
            }
        }

        if ($totalBonus > 0) {
            award_points(
                $me,
                'profile_completion',
                $totalBonus,
                'profile',
                0,   // reference_id: int, never null
                'First-time profile completion: ' . implode(', ', $earnedFields)
            );

            citadel_log('api', 'info', 'Profile completion reward', [
                'user_id' => $me,
                'points'  => $totalBonus,
                'fields'  => $earnedFields,
            ]);
        }

        /* ── profile_full badge ───────────────────────────────────────
         * Awarded when ALL 15 core identity fields are non-empty.
         * Idempotent — award_badge() returns false if already owned.
         * ---------------------------------------------------------- */

        $coreFields = [
            'display_name',
            'tagline',
            'bio',
            'pronouns',
            'avatar_url',
            'banner_url',
            'country_code',
            'timezone',
            'job_title',
            'company_name',
            'education',
            'hobbies_and_interests',
            'languages_spoken',
            'personal_motto',
            'website_url',
        ];

        $allCoreSet = true;
        foreach ($coreFields as $f) {
            if (trim((string) ($afterRow[$f] ?? '')) === '') {
                $allCoreSet = false;
                break;
            }
        }

        if ($allCoreSet) {
            $newlyAwarded = award_badge(
                $me,
                'profile_full',
                'completed all core profile fields'
            );
            if ($newlyAwarded) {
                citadel_log('api', 'info', 'profile_full badge awarded', [
                    'user_id' => $me,
                ]);
            }
        }
    }
} catch (Throwable $e) {
    // Rewards are cosmetic. Never fail the request because of them.
    citadel_log('api', 'warning', 'Reward block failed (non-fatal)', [
        'user_id' => $me,
        'error'   => $e->getMessage(),
        'file'    => $e->getFile(),
        'line'    => $e->getLine(),
    ]);
}

/* ══════════════════════════════════════════════════════════════════════════
 * 04. RESPONSE
 * ========================================================================== */

citadel_json_ok([
    'updated' => $updatedKeys,
    'message' => count($updatedKeys) . ' field(s) updated.',
]);