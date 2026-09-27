<?php
/* ============================================================================
 * ███ PASSWORD_RESET_EXCHANGE.PHP ███
 * MyCitadel — Password Reset: Step 2 of 3 (Exchange URL Token → Session)
 * ----------------------------------------------------------------------------
 * Route   : POST /v1/verify/password_reset_exchange
 * Auth    : None
 * CSRF    : Required
 * Rate    : 10 per hour per IP
 *
 * ────────────────────────────────────────────────────────────────────────────
 * WHAT IT DOES
 * ────────────────────────────────────────────────────────────────────────────
 *  1. Takes the raw token from the email link's URL fragment.
 *  2. Hashes it, looks up an unconsumed, unexpired row.
 *  3. Consumes the token IMMEDIATELY (does not wait for form submission).
 *  4. Establishes a short-lived session authorization:
 *        $_SESSION['_citadel']['pwreset'] = [
 *            'user_id' => 42,
 *            'expires' => time() + 900,   // 15 min to complete the form
 *        ]
 *  5. Returns success.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * WHY THIS EXISTS — THE ATTACK IT DEFEATS
 * ────────────────────────────────────────────────────────────────────────────
 * The naive design: user clicks link → sees form → submits → token consumed.
 *
 * Attack: token leaks from any of these places:
 *   • Server access logs (query strings are logged)
 *   • Browser history
 *   • Referer header to any third-party resource
 *   • Corporate email scanners that pre-visit links
 *   • Screenshots / shared URLs
 *
 * An attacker who finds that URL any time before form submission owns the
 * account. With a 1-hour window, that's a huge attack surface.
 *
 * Our design: token is CONSUMED ON PAGE LOAD. The form the user fills out
 * uses a session flag, not the token. By the time the attacker finds the
 * URL, it's already dead.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * WHY THE FRAGMENT
 * ────────────────────────────────────────────────────────────────────────────
 * The link uses '#token=' instead of '?token='. The fragment is NEVER sent
 * to the server. That kills:
 *   • Access-log exposure
 *   • Referer-header exposure
 *   • Email-scanner exposure (scanners strip fragments, or don't execute JS)
 *   • Proxy exposure
 * It's the cleanest way to move a token through a URL safely.
 * ========================================================================== */

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';
require_once CITADEL_CONFIG . '/crypto.php';
require_once CITADEL_CONFIG . '/db.php';


/* ══════════════════════════════════════════════════════════════════════════
 * 01. REQUEST-LEVEL PROTECTIONS
 * ========================================================================== */

citadel_rate_limit('pwreset_exchange', 10, 3600);
citadel_require_csrf();

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    header('Allow: POST');
    citadel_json_error('method_not_allowed', 'POST only.', 405);
}


/* ══════════════════════════════════════════════════════════════════════════
 * 02. PARSE + VALIDATE TOKEN
 * ========================================================================== */

$rawToken = citadel_input_string('token', null, 128);

if ($rawToken === null || !preg_match('/^[a-f0-9]{64}$/i', $rawToken)) {
    citadel_json_error('invalid_token', 'Invalid or expired reset link.', 400);
}

$tokenHash = hash('sha256', $rawToken);
$db        = db();

$db->beginTransaction();

try {
    /* ── 2a. Atomically consume the token ────────────────────────────────
     * The UPDATE's WHERE clause is the guard: it only succeeds if ALL
     * conditions hold at the moment of the write. This prevents:
     *   • Replay (consumed_at IS NULL)
     *   • Expired tokens (expires_at > NOW)
     *   • Wrong-purpose tokens (purpose = 'password_reset')
     * There is NO race window between check and consume — it's one atomic
     * statement.
     * ──────────────────────────────────────────────────────────────────── */
    $stmt = $db->prepare(
        "UPDATE email_verification_tokens
            SET consumed_at = UTC_TIMESTAMP()
          WHERE token_hash = ?
            AND purpose = 'password_reset'
            AND consumed_at IS NULL
            AND expires_at > UTC_TIMESTAMP()"
    );
    $stmt->execute([$tokenHash]);

    if ($stmt->rowCount() !== 1) {
        $db->rollBack();
        citadel_log('security', 'warning', 'Password reset exchange: invalid token', []);
        citadel_json_error('invalid_token', 'Invalid or expired reset link.', 400);
    }

    /* ── 2b. Fetch the user this token belonged to ─────────────────────── */
    $row = db_one(
        "SELECT user_id FROM email_verification_tokens
          WHERE token_hash = ?
          LIMIT 1",
        [$tokenHash]
    );

    if ($row === null) {
        $db->rollBack();
        citadel_json_error('invalid_token', 'Invalid or expired reset link.', 400);
    }

    $userId = (int) $row['user_id'];

    /* ── 2c. Set the session authorization flag ──────────────────────────
     * This is the "you may now change the password" ticket. It lives in
     * $_SESSION, keyed by nothing the client can forge. It expires in
     * 15 minutes — enough time to type a new password, not enough time
     * for an attacker to exploit.
     * ──────────────────────────────────────────────────────────────────── */
    $_SESSION['_citadel']['pwreset'] = [
        'user_id'   => $userId,
        'expires'   => time() + 900,   // 15 minutes
        'issued_at' => time(),
    ];

    $db->commit();

} catch (Throwable $e) {
    if ($db->inTransaction()) $db->rollBack();
    citadel_log('auth', 'error', 'Password reset exchange failed', [
        'error' => $e->getMessage(),
    ]);
    citadel_json_error('internal_error',
        'Could not process the reset link. Please try again.', 500);
}


/* ══════════════════════════════════════════════════════════════════════════
 * 03. RESPONSE
 * ========================================================================== */

citadel_log('auth', 'info', 'Password reset URL token exchanged for session', [
    'user_id' => $userId,
]);

citadel_json_ok([
    'message'    => 'Reset link verified. You may now set a new password.',
    'expires_in' => 900,
]);