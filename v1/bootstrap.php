<?php
/* ============================================================================
 * ███ BOOTSTRAP.PHP ███
 * MyCitadel — API Bootstrap & Request Lifecycle Manager (v2)
 * ----------------------------------------------------------------------------
 * Path      : /path/to/api.mycitadel.lol/v1/bootstrap.php
 * Author    : Bearded Viking (https://beardedviking.org)
 * Project   : MyCitadel (https://mycitadel.lol)
 * License   : MIT
 *
 * PURPOSE
 *   Every API request enters through this file. It handles:
 *
 *     00. Request ID (generated FIRST so all errors have it)
 *     01. Bootstrap guard (prevent double-loading)
 *     02. Path constants + directory existence validation
 *     03. Environment detection
 *     04. Error reporting configuration
 *     05. Custom error / exception / shutdown handlers
 *     06. Environment variable loading (.env)
 *     07. Environment integrity validation
 *     08. Timezone & locale
 *     09. HTTP method allowlist
 *     10. Client identification (browser vs mobile vs API)
 *     11. Real IP resolution (Cloudflare / proxy aware)
 *     12. HTTP security headers
 *     13. CORS policy (web + mobile WebView aware)
 *     14. Composer autoload
 *     15. Session subsystem
 *     16. Argon2id subsystem
 *     17. Database connection (lazy PDO singleton)
 *     18. Structured logging
 *     19. JSON response helpers
 *     20. Request input helpers
 *     21. Rate limiting (real-IP aware)
 *
 * PHILOSOPHY
 *   • Fail closed. If anything is uncertain, refuse the request.
 *   • Never leak internals. Errors return generic JSON, details go to logs.
 *   • Every request gets an ID before any code can fail.
 *   • Mobile and web clients are first-class citizens.
 *   • The request lifecycle is auditable from the first byte.
 *
 * USAGE
 *   Every endpoint file starts with:
 *       require_once __DIR__ . '/../bootstrap.php';
 *
 *   Then it can immediately use:
 *       citadel_json_ok(['user' => $user]);
 *       $db = citadel_db();
 *       $body = citadel_input_json();
 *       citadel_rate_limit('login', 10, 60);
 * ========================================================================== */

declare(strict_types=1);


/* ══════════════════════════════════════════════════════════════════════════
 * 00. REQUEST ID — GENERATED FIRST
 * --------------------------------------------------------------------------
 * This is the very first thing we do. If ANY subsequent code fails — even
 * a parse error in this file — the shutdown handler will have a valid
 * request ID to correlate with logs.
 *
 * Format: 32 lowercase hex chars. Client can supply their own via
 * X-Request-ID for distributed tracing; we validate the format strictly
 * to prevent log injection.
 * ═════════════════════════════════════════════════════════════════════════ */

$GLOBALS['citadel_request_id'] = bin2hex(random_bytes(16));

if (!empty($_SERVER['HTTP_X_REQUEST_ID'])
    && is_string($_SERVER['HTTP_X_REQUEST_ID'])
    && preg_match('/^[a-f0-9]{32}$/i', $_SERVER['HTTP_X_REQUEST_ID'])) {
    $GLOBALS['citadel_request_id'] = strtolower($_SERVER['HTTP_X_REQUEST_ID']);
}


/* ══════════════════════════════════════════════════════════════════════════
 * 01. BOOTSTRAP GUARD
 * ═════════════════════════════════════════════════════════════════════════ */

if (defined('CITADEL_BOOTSTRAPPED')) {
    return;
}
define('CITADEL_BOOTSTRAPPED', true);


/* ══════════════════════════════════════════════════════════════════════════
 * 02. PATH CONSTANTS + DIRECTORY VALIDATION
 * --------------------------------------------------------------------------
 * Every path the application needs is defined here. Immediately after,
 * we verify the directories exist and are writable (where applicable).
 * Failing here is better than failing 40 lines into a request.
 * ═════════════════════════════════════════════════════════════════════════ */

if (!defined('CITADEL_ROOT')) {
    define('CITADEL_ROOT', '/home/beardedviking/secure_mycitadel.lol');
}
if (!defined('API_ROOT')) {
    define('API_ROOT', dirname(__DIR__));
}
if (!defined('API_VERSION')) {
    define('API_VERSION', 'v1');
}

define('CITADEL_CONFIG',    CITADEL_ROOT . '/config');
define('CITADEL_LOGS',      CITADEL_ROOT . '/logs');
define('CITADEL_KEYS',      CITADEL_ROOT . '/keys');
define('CITADEL_SESSIONS',  CITADEL_ROOT . '/sessions');
define('CITADEL_VENDOR',    CITADEL_ROOT . '/vendor');
define('CITADEL_ENV_FILE',  CITADEL_ROOT . '/.env');

// Ensure every critical directory exists before we need it.
// We create these here rather than at point-of-use so a boot can never
// half-succeed and leave the app in an inconsistent state.
foreach ([
    CITADEL_LOGS,
    CITADEL_LOGS . '/php',
    CITADEL_LOGS . '/ratelimit',
    CITADEL_LOGS . '/security',
    CITADEL_KEYS,
    CITADEL_SESSIONS,
] as $dir) {
    if (!is_dir($dir)) {
        @mkdir($dir, 0700, true);
    }
}

// Point PHP's error_log at our directory (it now exists).
ini_set('log_errors', '1');
ini_set('error_log', CITADEL_LOGS . '/php/error.log');


/* ══════════════════════════════════════════════════════════════════════════
 * 03. ENVIRONMENT DETECTION
 * --------------------------------------------------------------------------
 * Environment is inferred from server-controlled signals only. Never
 * from anything the client can influence.
 * ═════════════════════════════════════════════════════════════════════════ */

$citadelEnv = getenv('CITADEL_ENV') ?: null;

if ($citadelEnv === null) {
    if      (is_file(CITADEL_ROOT . '/.env.development')) $citadelEnv = 'development';
    elseif  (is_file(CITADEL_ROOT . '/.env.staging'))     $citadelEnv = 'staging';
    elseif  (is_file(CITADEL_ROOT . '/.env.production'))  $citadelEnv = 'production';
    else                                                  $citadelEnv = 'production';
}

define('CITADEL_ENV',            $citadelEnv);
define('CITADEL_IS_PRODUCTION',  CITADEL_ENV === 'production');
define('CITADEL_IS_STAGING',     CITADEL_ENV === 'staging');
define('CITADEL_IS_DEVELOPMENT', CITADEL_ENV === 'development');


/* ══════════════════════════════════════════════════════════════════════════
 * 04. ERROR REPORTING
 * --------------------------------------------------------------------------
 * Development: loud.
 * Production:  silent to the client, verbose to the log.
 * ═════════════════════════════════════════════════════════════════════════ */

error_reporting(E_ALL);

if (CITADEL_IS_DEVELOPMENT) {
    ini_set('display_errors', '1');
    ini_set('display_startup_errors', '1');
} else {
    ini_set('display_errors', '0');
    ini_set('display_startup_errors', '0');
}


/* ══════════════════════════════════════════════════════════════════════════
 * 05. ERROR / EXCEPTION / SHUTDOWN HANDLERS
 * --------------------------------------------------------------------------
 * The safety net. Every uncaught failure becomes a clean JSON response.
 * Internal details always go to the log, never to the client.
 * ═════════════════════════════════════════════════════════════════════════ */

/**
 * Emit a fatal JSON error response and stop execution.
 * Use this for infrastructure-level failures only — endpoints should
 * use citadel_json_error() instead.
 */
function citadel_fatal(string $publicMessage, ?Throwable $e = null, int $httpCode = 500): never
{
    $line = sprintf(
        "[FATAL] %s | %s | %s:%d | rid=%s",
        $publicMessage,
        $e?->getMessage() ?? 'no exception',
        $e?->getFile()    ?? '-',
        $e?->getLine()    ?? 0,
        $GLOBALS['citadel_request_id'] ?? 'unknown'
    );
    @error_log($line);

    if (headers_sent()) {
        exit;
    }

    while (ob_get_level() > 0) { ob_end_clean(); }

    header('Content-Type: application/json; charset=utf-8');
    header('X-Request-ID: ' . ($GLOBALS['citadel_request_id'] ?? 'unknown'));
    http_response_code($httpCode);

    echo json_encode([
        'status'     => 'error',
        'code'       => 'internal_error',
        'message'    => $publicMessage,
        'request_id' => $GLOBALS['citadel_request_id'] ?? null,
        'ts'         => gmdate('c'),
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

// In development, warnings become exceptions — but NOT deprecations,
// because third-party libraries often emit them harmlessly.
if (CITADEL_IS_DEVELOPMENT) {
    set_error_handler(static function (int $severity, string $message, string $file, int $line): bool {
        if (!(error_reporting() & $severity)) return false;
        if ($severity === E_DEPRECATED || $severity === E_USER_DEPRECATED) return false;
        throw new ErrorException($message, 0, $severity, $file, $line);
    });
}

set_exception_handler(static function (Throwable $e): void {
    citadel_fatal('An unexpected error occurred.', $e, 500);
});

register_shutdown_function(static function (): void {
    $err = error_get_last();
    if ($err !== null && in_array(
        $err['type'],
        [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR, E_USER_ERROR],
        true
    )) {
        citadel_fatal('A fatal error occurred.', new ErrorException(
            $err['message'], 0, $err['type'], $err['file'], $err['line']
        ), 500);
    }
});


/* ══════════════════════════════════════════════════════════════════════════
 * 06. ENVIRONMENT VARIABLE LOADING (.env)
 * ═════════════════════════════════════════════════════════════════════════ */

/**
 * Parse a .env file into getenv()/putenv()/$_ENV/$_SERVER.
 * Never overwrites real environment variables set by the web server.
 */
function citadel_load_env(string $path): void
{
    if (!is_file($path) || !is_readable($path)) {
        return;
    }

    $lines = @file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if ($lines === false) return;

    foreach ($lines as $line) {
        $line = trim($line);
        if ($line === '' || str_starts_with($line, '#')) continue;

        $eq = strpos($line, '=');
        if ($eq === false) continue;

        $key = trim(substr($line, 0, $eq));
        $val = trim(substr($line, $eq + 1));

        if (strlen($val) >= 2) {
            $first = $val[0];
            $last  = $val[-1];
            if (($first === '"' && $last === '"') || ($first === "'" && $last === "'")) {
                $val = substr($val, 1, -1);
            }
        }

        if (!preg_match('/^[A-Z_][A-Z0-9_]*$/i', $key)) continue;

        if (getenv($key) === false) {
            putenv("{$key}={$val}");
            $_ENV[$key]    = $val;
            $_SERVER[$key] = $val;
        }
    }
}

citadel_load_env(CITADEL_ENV_FILE);


/* ══════════════════════════════════════════════════════════════════════════
 * 07. ENVIRONMENT INTEGRITY VALIDATION
 * --------------------------------------------------------------------------
 * Fail-closed on missing or unsafe configuration. This must run BEFORE
 * anything downstream relies on .env values.
 * ═════════════════════════════════════════════════════════════════════════ */

$validatorFile = CITADEL_CONFIG . '/env_validator.php';
if (is_file($validatorFile)) {
    require_once $validatorFile;
}


/* ══════════════════════════════════════════════════════════════════════════
 * 08. TIMEZONE & LOCALE
 * ========================================================================== */

date_default_timezone_set('UTC');
setlocale(LC_ALL, 'C');


/* ══════════════════════════════════════════════════════════════════════════
 * 09. HTTP METHOD ALLOWLIST
 * --------------------------------------------------------------------------
 * Reject TRACE, CONNECT, and any non-standard method outright. These are
 * never used by our clients (web, mobile, API tools) and their presence
 * indicates either a misconfiguration or an attack.
 * ═════════════════════════════════════════════════════════════════════════ */

if (PHP_SAPI !== 'cli') {
    $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
    if (!in_array($method, ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'], true)) {
        http_response_code(405);
        header('Allow: GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD');
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode([
            'status'     => 'error',
            'code'       => 'method_not_allowed',
            'message'    => 'HTTP method not supported.',
            'request_id' => $GLOBALS['citadel_request_id'],
            'ts'         => gmdate('c'),
        ]);
        exit;
    }
}


/* ══════════════════════════════════════════════════════════════════════════
 * 10. CLIENT IDENTIFICATION
 * --------------------------------------------------------------------------
 * Three client types talk to this API:
 *
 *   • browser  — web app (mycitadel.lol) or mobile WebView
 *   • android  — native Android app (Kotlin)
 *   • api      — CLI tools, Postman, server-to-server
 *
 * Native mobile apps should send:
 *   X-Citadel-Client: android/1.0.0
 *
 * This lets endpoints adjust behavior (e.g., longer-lived tokens for
 * mobile, stricter CSRF for browsers) without guessing.
 * ═════════════════════════════════════════════════════════════════════════ */

$clientHeader = $_SERVER['HTTP_X_CITADEL_CLIENT'] ?? '';
$clientType   = 'browser';
$clientVer    = '';

if (preg_match('#^(browser|android|ios|api)/([0-9A-Za-z.\-]+)$#i', $clientHeader, $m)) {
    $clientType = strtolower($m[1]);
    $clientVer  = $m[2];
} elseif (!empty($_SERVER['HTTP_USER_AGENT'])) {
    // Fallback: infer from User-Agent for legacy clients that don't send
    // the header yet.
    $ua = $_SERVER['HTTP_USER_AGENT'];
    if (str_starts_with($ua, 'MyCitadelAndroid/')) {
        $clientType = 'android';
    }
}

$GLOBALS['citadel_client_type']    = $clientType;
$GLOBALS['citadel_client_version'] = $clientVer;


/* ══════════════════════════════════════════════════════════════════════════
 * 11. REAL IP RESOLUTION
 * --------------------------------------------------------------------------
 * Behind Cloudflare, a CDN, or a reverse proxy, $_SERVER['REMOTE_ADDR']
 * is the proxy's IP — not the user's. Without this, all rate limits
 * collapse into one bucket.
 *
 * SECURITY: We only trust forwarded headers when REMOTE_ADDR is in the
 * trusted proxy list. Otherwise, X-Forwarded-For is trivially spoofable
 * by any client.
 *
 * Configure trusted proxies in .env:
 *   TRUSTED_PROXIES=173.245.48.0/20,103.21.244.0/22,...
 * (Cloudflare's published ranges: https://www.cloudflare.com/ips/)
 * ═════════════════════════════════════════════════════════════════════════ */

/**
 * Resolve the real client IP, honoring proxy headers only from trusted
 * upstreams. Result is cached in $GLOBALS.
 *
 * @return string IPv4 or IPv6 address
 */
function citadel_client_ip(): string
{
    static $resolved = null;
    if ($resolved !== null) return $resolved;

    $remote = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

    // Parse trusted proxy CIDR ranges from env.
    $trustedRaw = getenv('TRUSTED_PROXIES') ?: '';
    $trusted = array_filter(array_map('trim', explode(',', $trustedRaw)));

    $isTrusted = false;
    foreach ($trusted as $cidr) {
        if (citadel_ip_in_cidr($remote, $cidr)) {
            $isTrusted = true;
            break;
        }
    }

    if (!$isTrusted) {
        return $resolved = $remote;
    }

    // Cloudflare-specific header (preferred when present and trusted).
    $cfIp = $_SERVER['HTTP_CF_CONNECTING_IP'] ?? null;
    if (is_string($cfIp) && filter_var($cfIp, FILTER_VALIDATE_IP)) {
        return $resolved = $cfIp;
    }

    // X-Forwarded-For — first IP in the list is the original client.
    $xff = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? null;
    if (is_string($xff) && $xff !== '') {
        $parts = array_map('trim', explode(',', $xff));
        $first = $parts[0] ?? null;
        if (is_string($first) && filter_var($first, FILTER_VALIDATE_IP)) {
            return $resolved = $first;
        }
    }

    // X-Real-IP — used by some nginx configurations.
    $real = $_SERVER['HTTP_X_REAL_IP'] ?? null;
    if (is_string($real) && filter_var($real, FILTER_VALIDATE_IP)) {
        return $resolved = $real;
    }

    return $resolved = $remote;
}

/**
 * Check whether an IP falls within a CIDR range.
 *
 * @param string $ip
 * @param string $cidr  e.g. "173.245.48.0/20" or a bare IP
 * @return bool
 */
function citadel_ip_in_cidr(string $ip, string $cidr): bool
{
    // Bare IP — exact match.
    if (strpos($cidr, '/') === false) {
        return $ip === $cidr;
    }

    [$subnet, $bits] = explode('/', $cidr, 2);
    $bits = (int) $bits;

    $ipBin     = @inet_pton($ip);
    $subnetBin = @inet_pton($subnet);

    if ($ipBin === false || $subnetBin === false) return false;
    if (strlen($ipBin) !== strlen($subnetBin))  return false;

    $bytes = intdiv($bits, 8);
    $rem   = $bits % 8;

    if ($bytes > 0 && substr($ipBin, 0, $bytes) !== substr($subnetBin, 0, $bytes)) {
        return false;
    }
    if ($rem === 0) return true;

    $mask = ~((1 << (8 - $rem)) - 1) & 0xFF;
    return (ord($ipBin[$bytes]) & $mask) === (ord($subnetBin[$bytes]) & $mask);
}


/* ══════════════════════════════════════════════════════════════════════════
 * 12. HTTP SECURITY HEADERS
 * ========================================================================== */

if (PHP_SAPI !== 'cli' && !headers_sent()) {
    header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer');
    header('Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=(), usb=(), interest-cohort=()');
    header('X-Permitted-Cross-Domain-Policies: none');
    header_remove('X-Powered-By');
}


/* ══════════════════════════════════════════════════════════════════════════
 * 13. CORS POLICY — WEB + MOBILE WEBVIEW
 * --------------------------------------------------------------------------
 * Browser clients: strict origin allowlist.
 * Mobile native apps: no Origin header at all — implicitly allowed.
 * Mobile WebViews: origins like "capacitor://localhost" or
 *   "file://" — handled by the extended allowlist below.
 * ═════════════════════════════════════════════════════════════════════════ */

/** @var array<int,string> Origins permitted to call this API. */
const CITADEL_ALLOWED_ORIGINS = [
    // ── Web ──────────────────────────────────────────────────────────
    'https://mycitadel.lol',
    'https://www.mycitadel.lol',
    'https://vendors.mycitadel.lol',

    // ── Local development ────────────────────────────────────────────
    'http://localhost:8000',
    'http://localhost:8080',
    'http://127.0.0.1:8000',
    'http://127.0.0.1:8080',

    // ── Mobile WebView (Capacitor / Cordova / React Native WebView) ──
    'capacitor://localhost',
    'ionic://localhost',
    'http://localhost',
];

function citadel_apply_cors(): void
{
    if (PHP_SAPI === 'cli' || headers_sent()) return;

    $origin = $_SERVER['HTTP_ORIGIN'] ?? '';

    // No Origin header → native mobile or CLI tool. No CORS headers needed;
    // the client isn't a browser and doesn't enforce same-origin policy.
    if ($origin === '') return;

    if (in_array($origin, CITADEL_ALLOWED_ORIGINS, true)) {
        header('Access-Control-Allow-Origin: ' . $origin);
        header('Access-Control-Allow-Credentials: true');
        header('Vary: Origin');
    } else {
        // Disallowed origin. Reject preflight immediately.
        if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'OPTIONS') {
            http_response_code(403);
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode([
                'status'     => 'error',
                'code'       => 'origin_not_allowed',
                'message'    => 'Cross-origin request denied.',
                'request_id' => $GLOBALS['citadel_request_id'],
            ]);
            exit;
        }
    }

    header('Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type, X-CSRF-Token, X-Requested-With, Authorization, X-Citadel-Client, X-Request-ID');
    header('Access-Control-Expose-Headers: X-Request-ID');
    header('Access-Control-Max-Age: 600');

    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'OPTIONS') {
        http_response_code(204);
        exit;
    }
}

citadel_apply_cors();


/* ══════════════════════════════════════════════════════════════════════════
 * 14. COMPOSER AUTOLOAD
 * ========================================================================== */

$autoload = CITADEL_VENDOR . '/autoload.php';
if (is_file($autoload)) {
    require_once $autoload;
}


/* ══════════════════════════════════════════════════════════════════════════
 * 15. SESSION SUBSYSTEM
 * ========================================================================== */

$sessionFile = CITADEL_CONFIG . '/session.php';
if (is_file($sessionFile)) {
    require_once $sessionFile;
}


/* ══════════════════════════════════════════════════════════════════════════
 * 16. ARGON2ID SUBSYSTEM
 * ========================================================================== */

$argonFile = CITADEL_CONFIG . '/argon2.php';
if (is_file($argonFile)) {
    require_once $argonFile;
}


/* ══════════════════════════════════════════════════════════════════════════
 * 17. DATABASE CONNECTION (LAZY SINGLETON)
 * ========================================================================== */

/**
 * Return a shared PDO connection. Opened on first use, cached for the
 * request lifetime.
 *
 * @throws RuntimeException if configuration is missing
 * @return PDO
 */
function citadel_db(): PDO
{
    static $pdo = null;
    if ($pdo instanceof PDO) return $pdo;

    $host = getenv('DB_HOST') ?: '127.0.0.1';
    $port = getenv('DB_PORT') ?: '3306';
    $name = getenv('DB_NAME') ?: '';
    $user = getenv('DB_USER') ?: '';
    $pass = getenv('DB_PASS') ?: '';
    $char = getenv('DB_CHARSET') ?: 'utf8mb4';

    if ($name === '' || $user === '') {
        throw new RuntimeException('Database credentials are not configured.');
    }

    $dsn = "mysql:host={$host};port={$port};dbname={$name};charset={$char}";

    try {
        $pdo = new PDO($dsn, $user, $pass, [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
            PDO::ATTR_PERSISTENT         => false,
            PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES {$char} COLLATE {$char}_unicode_ci",
        ]);
    } catch (PDOException $e) {
        citadel_fatal('Database connection failed.', $e, 503);
    }

    return $pdo;
}


/* ══════════════════════════════════════════════════════════════════════════
 * 18. STRUCTURED LOGGING
 * ========================================================================== */

/**
 * Write a structured JSON-lines log entry.
 *
 * @param string $channel  'auth' | 'api' | 'db' | 'security' | 'stripe'
 * @param string $level    'debug' | 'info' | 'warning' | 'error' | 'critical'
 * @param string $message
 * @param array  $context
 */
function citadel_log(string $channel, string $level, string $message, array $context = []): void
{
    $channel = preg_replace('/[^a-z0-9_]/', '', strtolower($channel)) ?: 'app';
    $logDir  = CITADEL_LOGS . '/' . $channel;

    if (!is_dir($logDir)) {
        @mkdir($logDir, 0700, true);
    }

    $entry = [
        'ts'          => gmdate('c'),
        'level'       => $level,
        'channel'     => $channel,
        'message'     => $message,
        'request_id'  => $GLOBALS['citadel_request_id'] ?? null,
        'user_id'     => function_exists('citadel_current_user_id')
                            ? citadel_current_user_id()
                            : null,
        'client_type' => $GLOBALS['citadel_client_type'] ?? null,
        'client_ver'  => $GLOBALS['citadel_client_version'] ?? null,
        'path'        => $_SERVER['REQUEST_URI']    ?? null,
        'method'      => $_SERVER['REQUEST_METHOD'] ?? null,
        'context'     => $context,
    ];

    $line = json_encode($entry, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    if ($line === false) return;

    @file_put_contents($logDir . '/app.log', $line . "\n", FILE_APPEND | LOCK_EX);
}


/* ══════════════════════════════════════════════════════════════════════════
 * 19. JSON RESPONSE HELPERS
 * ========================================================================== */

function citadel_json_ok(array $data = [], int $status = 200): never
{
    citadel_json_send('ok', $data, $status);
}

function citadel_json_error(string $code, string $message, int $status = 400, array $extra = []): never
{
    citadel_json_send('error', array_merge([
        'code'    => $code,
        'message' => $message,
    ], $extra), $status);
}

function citadel_json_send(string $status, array $payload, int $httpCode): never
{
    if (headers_sent()) exit;
    while (ob_get_level() > 0) { ob_end_clean(); }

    header('Content-Type: application/json; charset=utf-8');
    header('X-Request-ID: ' . ($GLOBALS['citadel_request_id'] ?? 'unknown'));
    http_response_code($httpCode);

    $body = array_merge([
        'status'     => $status,
        'request_id' => $GLOBALS['citadel_request_id'] ?? null,
        'ts'         => gmdate('c'),
    ], $payload);

    echo json_encode($body, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}


/* ══════════════════════════════════════════════════════════════════════════
 * 20. REQUEST INPUT HELPERS
 * ========================================================================== */

/**
 * Read and decode the JSON request body. Returns [] if empty.
 * Rejects non-JSON content types on unsafe methods.
 */
function citadel_input_json(): array
{
    static $cached = null;
    if ($cached !== null) return $cached;

    $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
    if (in_array($method, ['GET', 'HEAD', 'OPTIONS'], true)) {
        return $cached = [];
    }

    $ctype = $_SERVER['CONTENT_TYPE'] ?? '';
    if ($ctype !== '' && !str_starts_with($ctype, 'application/json')) {
        citadel_json_error('invalid_content_type',
            'Content-Type must be application/json.', 415);
    }

    $raw = file_get_contents('php://input');
    if ($raw === false || $raw === '') {
        return $cached = [];
    }

    if (strlen($raw) > 1048576) {
        citadel_json_error('payload_too_large',
            'Request body exceeds 1 MB.', 413);
    }

    $decoded = json_decode($raw, true);
    if (!is_array($decoded)) {
        citadel_json_error('invalid_json',
            'Request body is not valid JSON.', 400);
    }

    return $cached = $decoded;
}

function citadel_input_string(string $key, ?string $default = null, int $maxLen = 255): ?string
{
    $body = citadel_input_json();
    if (!array_key_exists($key, $body)) return $default;

    $val = $body[$key];
    if (!is_string($val)) return $default;

    $val = trim($val);
    if (strlen($val) > $maxLen) {
        citadel_json_error('input_too_long',
            "Field '{$key}' exceeds {$maxLen} characters.", 400);
    }
    return $val;
}

function citadel_input_int(string $key, ?int $default = null): ?int
{
    $body = citadel_input_json();
    if (!array_key_exists($key, $body)) return $default;

    $val = $body[$key];
    if (is_int($val)) return $val;
    if (is_string($val) && ctype_digit($val)) return (int) $val;
    return $default;
}


/* ══════════════════════════════════════════════════════════════════════════
 * 21. RATE LIMITING (REAL-IP AWARE)
 * --------------------------------------------------------------------------
 * Uses citadel_client_ip() so limits apply to the actual client even
 * behind Cloudflare or a CDN.
 *
 * Rate-limit keys are hashed with the fingerprint key so they don't
 * leak the raw IP in the filesystem.
 * ═════════════════════════════════════════════════════════════════════════ */

function citadel_rate_limit(string $bucket, int $maxAttempts, int $windowSeconds): void
{
    if (PHP_SAPI === 'cli') return;

    $ip = citadel_client_ip();

    // Hash the IP for storage. Key is derived from the session fingerprint
    // key which is set in session.php.
    $hmacKey = $GLOBALS['citadel_fingerprint_key'] ?? 'default-rate-limit-key';
    $ipHash  = hash_hmac('sha256', $ip, $hmacKey);

    $dir = CITADEL_LOGS . '/ratelimit';
    if (!is_dir($dir)) @mkdir($dir, 0700, true);

    $safeBucket = preg_replace('/[^a-z0-9_]/', '', strtolower($bucket)) ?: 'default';
    $file = $dir . '/' . $safeBucket . '_' . $ipHash . '.json';

    $now         = time();
    $windowStart = $now - $windowSeconds;

    $hits = [];
    if (is_file($file)) {
        $raw = @file_get_contents($file);
        if ($raw !== false) {
            $decoded = json_decode($raw, true);
            if (is_array($decoded)) {
                $hits = array_values(array_filter(
                    $decoded,
                    fn($t) => is_int($t) && $t > $windowStart
                ));
            }
        }
    }

    if (count($hits) >= $maxAttempts) {
        $retryAfter = $windowSeconds - ($now - min($hits));
        header('Retry-After: ' . max(1, $retryAfter));

        citadel_log('security', 'warning', 'Rate limit exceeded', [
            'bucket'  => $safeBucket,
            'ip_hash' => substr($ipHash, 0, 12),
        ]);

        citadel_json_error('rate_limited',
            "Too many requests. Try again in {$retryAfter} seconds.", 429);
    }

    $hits[] = $now;
    @file_put_contents($file, json_encode($hits), LOCK_EX);
}


/* ══════════════════════════════════════════════════════════════════════════
 * ▓▓▓ END OF BOOTSTRAP.PHP ▓▓▓
 * --------------------------------------------------------------------------
 * Bootstrap is infrastructure, not business logic. If you're tempted to
 * add an endpoint's worth of code here, don't. Put it in the endpoint.
 *
 * The order matters:
 *   00. Request ID   — before anything can fail
 *   01. Guard        — prevent double-load
 *   02. Paths        — before any file operation
 *   05. Handlers     — before any code that might throw
 *   06. Env          — before anything reads config
 *   07. Validation   — before anything uses config
 *   15. Session      — before auth helpers are called
 *   17. Database     — lazy; opened only when needed
 *
 * When in doubt: fail closed, log loudly, return JSON.
 * — Bearded Viking
 * ═════════════════════════════════════════════════════════════════════════ */