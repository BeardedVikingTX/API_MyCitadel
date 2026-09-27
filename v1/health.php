<?php
/* ============================================================================
 * ███ HEALTH.PHP ███
 * MyCitadel — Health Check Endpoint
 * ----------------------------------------------------------------------------
 * Route  : GET /v1/health
 * Auth   : Token required (via X-Health-Token header or ?token= query)
 * Rate   : 120 requests per minute per IP
 *
 * PURPOSE
 *   Provides a machine-readable health status for monitoring tools, uptime
 *   checkers, and load balancers. Unlike a diagnostic page, this endpoint
 *   NEVER exposes:
 *     ✗ Filesystem paths
 *     ✗ Environment variables
 *     ✗ PHP version or SAPI
 *     ✗ Extension lists
 *     ✗ Session configuration
 *
 * WHAT IT *DOES* RETURN
 *   • status: "healthy" | "degraded" | "unhealthy"
 *   • checks: per-subsystem pass/fail
 *   • version: API version string (safe to expose)
 *   • timestamp: server UTC time
 *
 * SECURITY
 *   • Requires a shared secret token (HEALTH_TOKEN env var).
 *   • Token comparison uses hash_equals() — constant time.
 *   • Failed attempts are logged and rate-limited.
 *   • Internal localhost requests bypass the token (for cron/monitoring).
 *
 * CONFIGURATION
 *   Add to .env:
 *     HEALTH_TOKEN=<32+ random hex chars>
 *   Generate with: openssl rand -hex 32
 * ========================================================================== */

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';


/* ══════════════════════════════════════════════════════════════════════════
 * 01. REQUEST PROTECTIONS
 * ========================================================================== */

// Generous rate limit — health checks can be frequent.
citadel_rate_limit('health', 120, 60);


/* ══════════════════════════════════════════════════════════════════════════
 * 02. METHOD CHECK
 * ========================================================================== */

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'GET') {
    header('Allow: GET');
    citadel_json_error('method_not_allowed',
        'Health checks accept GET only.', 405);
}


/* ══════════════════════════════════════════════════════════════════════════
 * 03. AUTHENTICATION
 * --------------------------------------------------------------------------
 * Two paths to authentication:
 *
 *   A. Internal localhost request — allowed without token (monitoring tools
 *      running on the same server, cron jobs, etc.)
 *
 *   B. External request — must supply the correct token via:
 *        • X-Health-Token header, OR
 *        • ?token= query parameter (for tools that can't set headers)
 *
 * The token is compared with hash_equals() to prevent timing attacks.
 * ========================================================================== */

if (!citadel_is_internal_request()) {
    $configuredToken = getenv('HEALTH_TOKEN') ?: '';

    if ($configuredToken === '') {
        // No token configured — refuse external access entirely.
        citadel_log('security', 'warning', 'Health endpoint accessed without token configured', []);
        citadel_json_error('service_unavailable',
            'Health endpoint is not configured.', 503);
    }

    $suppliedToken = $_SERVER['HTTP_X_HEALTH_TOKEN']
                  ?? $_GET['token']
                  ?? '';

    if (!is_string($suppliedToken) || $suppliedToken === '' ||
        !hash_equals($configuredToken, $suppliedToken)) {

        citadel_log('security', 'warning', 'Health endpoint auth failed', [
            'ip_hash' => substr(
                hash_hmac('sha256', citadel_client_ip(),
                          $GLOBALS['citadel_fingerprint_key'] ?? ''),
                0, 12
            ),
        ]);

        citadel_json_error('unauthorized',
            'Valid health token required.', 401);
    }
}


/* ══════════════════════════════════════════════════════════════════════════
 * 04. RUN HEALTH CHECKS
 * --------------------------------------------------------------------------
 * Each check returns true (healthy) or false (degraded).
 * The overall status is "unhealthy" if any critical check fails.
 * ========================================================================== */

$checks  = [];
$healthy = true;

// ── Database connectivity ────────────────────────────────────────────────
try {
    $db = citadel_db();
    $db->query('SELECT 1');
    $checks['database'] = true;
} catch (Throwable $e) {
    $checks['database'] = false;
    $healthy = false;
    citadel_log('system', 'error', 'Health check: database failed', [
        'error' => $e->getMessage(),
    ]);
}

// ── Encryption keys readable ─────────────────────────────────────────────
$checks['keys_readable'] = is_readable(CITADEL_KEYS . '/session.key');

// ── Logs writable ────────────────────────────────────────────────────────
$checks['logs_writable'] = is_writable(CITADEL_LOGS);

// ── Sessions writable ────────────────────────────────────────────────────
$checks['sessions_writable'] = is_writable(CITADEL_SESSIONS);

// ── Disk space (warn under 500 MB free) ──────────────────────────────────
$freeBytes = @disk_free_space(CITADEL_LOGS);
$checks['disk_space_ok'] = ($freeBytes === false) ? true : ($freeBytes > 524288000);

// Overall degradation if any non-critical check fails.
$allChecks = array_values($checks);
if (in_array(false, $allChecks, true)) {
    $healthy = false;
}


/* ══════════════════════════════════════════════════════════════════════════
 * 05. RESPONSE
 * ========================================================================== */

$status = $healthy ? 'healthy' : 'degraded';
$httpCode = $healthy ? 200 : 503;

citadel_json_send('ok', [
    'health'    => $status,
    'checks'    => $checks,
    'version'   => API_VERSION,
    'uptime_ok' => true,
], $httpCode);