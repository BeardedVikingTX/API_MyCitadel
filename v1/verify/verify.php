<?php
/* ============================================================================
 * ███ VERIFY.PHP ███
 * MyCitadel — Email Verification: Consume Token
 * ----------------------------------------------------------------------------
 * Route   : POST /v1/verify/verify
 * Auth    : Required (must be logged in — the link takes them to login first)
 * CSRF    : Required
 * Rate    : 20 per hour per IP (brute-force defense)
 *
 * ────────────────────────────────────────────────────────────────────────────
 * WHAT IT DOES
 * ────────────────────────────────────────────────────────────────────────────
 *  1. Reads the raw token from the JSON body.
 *  2. Hashes it with SHA-256.
 *  3. Looks up the token row: matching hash, unconsumed, unexpired.
 *  4. Verifies the token belongs to the currently-authenticated user.
 *  5. Marks the user's email_verified = 1 and email_verified_at = now.
 *  6. Marks the token consumed (single-use).
 *  7. Awards the 'email_verified' badge (+1000 reputation points).
 *  8. Returns success.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * SECURITY
 * ────────────────────────────────────────────────────────────────────────────
 *   • Token is compared via HASH LOOKUP, not string comparison. The stored
 *     hash is unique, so timing differences reveal nothing.
 *   • A user can only consume their OWN tokens — cross-user attempts are
 *     treated as invalid (same generic error as a wrong token).
 *   • Consumed tokens are immutable — even if you re-hash and match, the
 *     `consumed_at IS NULL` filter rejects them.
 *   • Rate-limited on IP to prevent brute-force over 2^256 space.
 *   • Errors are generic: "Invalid or expired verification link."
 * ========================================================================== */

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';
require_once CITADEL_CONFIG . '/crypto.php';
require_once CITADEL_CONFIG . '/db.php';
require_once CITADEL_CONFIG . '/badges.php';
require_once CITADEL_CONFIG . '/reputation.php';


/* ══════════════════════════════════════════════════════════════════════════
 * 01. REQUEST PROTECTIONS
 * ========================================================================== */

citadel_rate_limit('verify_consume', 20, 3600);
citadel_require_csrf();
citadel_require_auth('json');

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
if ($method !== 'POST') {
    header('Allow: POST');
    citadel_json_error('method_not_allowed', 'This endpoint accepts POST only.', 405);
}

$userId = (int) citadel_current_user_id();


/* ══════════════════════════════════════════════════════════════════════════
 * 02. READ + VALIDATE THE TOKEN
 * ========================================================================== */

$rawToken = citadel_input_string('token', null, 128);

if ($rawToken === null || $rawToken === '') {
    citadel_json_error('missing_token', 'Verification token is required.', 400);
}

// Raw tokens are 64 hex chars. Reject anything that doesn't match that shape.
if (!preg_match('/^[a-f0-9]{64}$/i', $rawToken)) {
    citadel_log('auth', 'warning', 'Verification token malformed', [
        'user_id' => $userId,
    ]);
    citadel_json_error('invalid_token',
        'Invalid or expired verification link.', 400);
}

$tokenHash = hash('sha256', $rawToken);


/* ══════════════════════════════════════════════════════════════════════════
 * 03. ATOMIC LOOKUP + CONSUME
 * --------------------------------------------------------------------------
 * We use a single UPDATE to consume the token — if zero rows are affected,
 * the token was invalid, expired, already consumed, or not for this user.
 *
 * Why not SELECT then UPDATE? Because between them, a race is possible.
 * The UPDATE's WHERE clause is the guard: it only succeeds if ALL conditions
 * hold at the exact moment of the write.
 * ========================================================================== */

$db = db();
$db->beginTransaction();

try {
    // ── 3a. Atomic consume ───────────────────────────────────────────
    $stmt = $db->prepare(
        "UPDATE email_verification_tokens
            SET consumed_at = UTC_TIMESTAMP()
          WHERE token_hash = ?
            AND user_id = ?
            AND purpose = 'verify_initial'
            AND consumed_at IS NULL
            AND expires_at > UTC_TIMESTAMP()"
    );
    $stmt->execute([$tokenHash, $userId]);

    if ($stmt->rowCount() !== 1) {
        // Token was invalid, expired, already used, or belongs to someone else.
        $db->rollBack();

        citadel_log('auth', 'warning', 'Verification token rejected', [
            'user_id' => $userId,
        ]);

        citadel_json_error('invalid_token',
            'Invalid or expired verification link.', 400);
    }

    // ── 3b. Mark the user verified ───────────────────────────────────
    $stmt = $db->prepare(
        "UPDATE users
            SET email_verified = 1,
                email_verified_at = UTC_TIMESTAMP(),
                updated_at = UTC_TIMESTAMP()
          WHERE id = ? AND email_verified = 0"
    );
    $stmt->execute([$userId]);

    $newlyVerified = $stmt->rowCount() === 1;

    // If the user was already verified (edge case — two tabs, two clicks),
    // we still consider this a success; the token was legitimately consumed.
    // But we don't re-award the badge.

    // ── 3c. Award the badge (only if newly verified) ─────────────────
    if ($newlyVerified) {
        // award_badge participates in our open transaction.
        try {
            award_badge($userId, 'email_verified', 'verified email address');
        } catch (Throwable $e) {
            // Badge award failure should not block verification itself.
            // Log it, but proceed with the commit.
            citadel_log('auth', 'warning', 'email_verified badge award failed', [
                'user_id' => $userId,
                'error'   => $e->getMessage(),
            ]);
        }
    }

    $db->commit();

} catch (Throwable $e) {
    if ($db->inTransaction()) $db->rollBack();

    citadel_log('auth', 'error', 'Verification consume failed', [
        'user_id' => $userId,
        'error'   => $e->getMessage(),
    ]);

    citadel_json_error('internal_error',
        'Could not verify your email. Please try again later.', 500);
}


/* ══════════════════════════════════════════════════════════════════════════
 * 04. AUDIT + RESPONSE
 * ========================================================================== */

citadel_log('auth', 'info', 'Email verified', [
    'user_id' => $userId,
    'already' => !$newlyVerified,
]);

citadel_json_ok([
    'message'        => 'Email verified successfully.',
    'email_verified' => true,
    'already_verified' => !$newlyVerified,
]);