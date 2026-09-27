<?php
/* ============================================================================
 * ███ BOOTSTRAP.PHP ███
 * MyCitadel — API Bootstrap & Request Lifecycle Manager (v3)
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
 *     02. Path constants + directory validation
 *     03. Environment detection
 *     04. Error reporting configuration
 *     05. Custom error / exception / shutdown handlers
 *     06. Environment variable loading (.env)
 *     07. Environment integrity validation
 *     08. Timezone & locale
 *     09. HTTP method allowlist
 *     09b. Request origin gate (NEW — declare yourself or be refused)
 *     10. Client identification + User-Agent filter
 *     11. Real IP resolution (Cloudflare / proxy aware)
 *     12. HTTP security headers
 *     13. CORS policy (environment-aware)
 *     14. Composer autoload
 *     15. Session subsystem
 *     16. Argon2id subsystem
 *     17. Database connection (lazy PDO singleton)
 *     18. Structured logging
 *     19. JSON response helpers
 *     20. Request input helpers
 *     21. Rate limiting (with file locking)
 *     22. Internal request whitelist
 *     23. Request replay protection (optional header)
 *
 * PHILOSOPHY
 *   • Fail closed. If anything is uncertain, refuse the request.
 *   • Every client must identify itself.
 *   • Production is strict. Development is flexible.
 *   • Nothing is unhackable. Everything is expensive to attack.
 *   • Log every rejection. Suspicious patterns become visible.
 * ========================================================================== */

declare(strict_types=1);


/* ══════════════════════════════════════════════════════════════════════════
 * 00. REQUEST ID — GENERATED FIRST
 * ========================================================================== */

$GLOBALS['citadel_request_id'] = bin2hex(random_bytes(16));

if (!empty($_SERVER['HTTP_X_REQUEST_ID'])
    && is_string($_SERVER['HTTP_X_REQUEST_ID'])
    && preg_match('/^[a-f0-9]{32}$/i', $_SERVER['HTTP_X_REQUEST_ID'])) {
    $GLOBALS['citadel_request_id'] = strtolower($_SERVER['HTTP_X_REQUEST_ID']);
}


/* ══════════════════════════════════════════════════════════════════════════
 * 01. BOOTSTRAP GUARD
 * ========================================================================== */

if (defined('CITADEL_BOOTSTRAPPED')) {
    return;
}
define('CITADEL_BOOTSTRAPPED', true);


/* ══════════════════════════════════════════════════════════════════════════
 * 02. PATH CONSTANTS + DIRECTORY VALIDATION
 * ========================================================================== */

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

ini_set('log_errors', '1');
ini_set('error_log', CITADEL_LOGS . '/php/error.log');


/* ══════════════════════════════════════════════════════════════════════════
 * 03. ENVIRONMENT DETECTION
 * ========================================================================== */

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
 * ========================================================================== */

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
 * ========================================================================== */

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

    if (headers_sent()) exit;
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
 * ========================================================================== */

function citadel_load_env(string $path): void
{
    if (!is_file($path) || !is_readable($path)) return;

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
 * ========================================================================== */

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
 * ========================================================================== */

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
 * 09b. REQUEST ORIGIN GATE — NEW
 * --------------------------------------------------------------------------
 * State-changing requests (POST/PUT/PATCH/DELETE) MUST declare themselves
 * by one of two mechanisms:
 *
 *   1. Origin header — set by browsers on cross-origin requests.
 *   2. X-Citadel-Client header — set by our own native/mobile clients.
 *
 * Requests with NEITHER are treated as anonymous CLI/script calls. In
 * production, we refuse them outright. In development/staging, we allow
 * them (so curl-based testing works).
 *
 * GET requests are exempt — they're read-only, and browsers don't always
 * send Origin on same-origin navigations.
 *
 * Rationale: this blocks naive "curl the API" attacks and forces every
 * attacker to spoof a header, raising the cost of reconnaissance.
 * ═════════════════════════════════════════════════════════════════════════ */

if (PHP_SAPI !== 'cli' && CITADEL_IS_PRODUCTION) {
    $method       = $_SERVER['REQUEST_METHOD'] ?? 'GET';
    $isStateful   = in_array($method, ['POST', 'PUT', 'PATCH', 'DELETE'], true);
    $hasOrigin    = !empty($_SERVER['HTTP_ORIGIN']);
    $hasClientHdr = !empty($_SERVER['HTTP_X_CITADEL_CLIENT']);
    $isInternal   = citadel_is_internal_request();  // defined in §22

    if ($isStateful && !$hasOrigin && !$hasClientHdr && !$isInternal) {
        // Log the rejection before responding (defense in depth — see §18).
        // We can't call citadel_log() yet because it may not be defined if
        // this file somehow loads in a broken order. Fall back to error_log.
        @error_log(sprintf(
            '[CITADEL GATE] Rejected unauthenticated %s from %s rid=%s',
            $method,
            $_SERVER['REMOTE_ADDR'] ?? '?',
            $GLOBALS['citadel_request_id'] ?? '?'
        ));

        http_response_code(403);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode([
            'status'     => 'error',
            'code'       => 'origin_required',
            'message'    => 'Requests must declare an Origin or X-Citadel-Client header.',
            'request_id' => $GLOBALS['citadel_request_id'],
            'ts'         => gmdate('c'),
        ]);
        exit;
    }
}


/* ══════════════════════════════════════════════════════════════════════════
 * 10. CLIENT IDENTIFICATION + USER-AGENT FILTER
 * --------------------------------------------------------------------------
 * Two responsibilities:
 *
 *   (a) Identify the client type: browser | android | ios | api
 *   (b) Filter out obvious scanner traffic in production only
 *
 * The User-Agent filter is DEFENSE IN DEPTH, not defense in principle.
 * An attacker can trivially spoof a UA. But scanners using default UAs
 * (sqlmap, nmap, nikto) get bounced at the door, and that's worth the
 * five lines of code.
 * ═════════════════════════════════════════════════════════════════════════ */

/**
 * Known-bad User-Agent substrings. Match is case-insensitive.
 * Only enforced in production.
 *
 * NOTE: 'python-requests' and 'go-http-client' appear here because NO
 * legitimate MyCitadel client uses them. If you ever add a server-to-
 * server integration that does, remove that entry.
 */
const CITADEL_BLOCKED_UA_SUBSTRINGS = [
    // Command-line tools
    'curl/', 'wget/', 'httpie/',
    // Scripting HTTP libraries
    'python-requests', 'python-urllib', 'aiohttp', 'httpx',
    'go-http-client', 'libwww-perl', 'ruby/', 'java/',
    // Security scanners
    'sqlmap', 'nikto', 'nmap', 'masscan', 'nessus', 'openvas',
    'burpsuite', 'zaproxy', 'zap/', 'w3af', 'skipfish', 'arachni',
    // Directory busters
    'dirbuster', 'gobuster', 'ffuf', 'wfuzz', 'dirb/',
    // Credential attackers
    'hydra', 'medusa', 'patator',
    // Site rippers
    'httrack', 'webcopier',
    // Generic bots / scanners
    'netsystemsresearch', 'shodan', 'censys',
];

/**
 * Apply the User-Agent blocklist (production only).
 *
 * Includes a dev bypass mechanism: if DEV_BYPASS_UAS in .env contains a
 * comma-separated list of UA substrings, matching requests skip the block.
 * Used for controlled debugging. MUST be emptied before public launch.
 */
function citadel_apply_ua_filter(): void
{
    if (!CITADEL_IS_PRODUCTION) return;
    if (PHP_SAPI === 'cli') return;
    if (citadel_is_internal_request()) return;

    $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';

    // ── Dev bypass — exempt specific UAs even in production ─────────────
    $bypass = getenv('DEV_BYPASS_UAS') ?: '';
    if ($bypass !== '' && $ua !== '') {
        foreach (array_filter(array_map('trim', explode(',', $bypass))) as $pattern) {
            if ($pattern !== '' && str_contains($ua, $pattern)) {
                return;  // trusted client — skip blocklist
            }
        }
    }

    if ($ua === '') return;

    $uaLower = strtolower($ua);
    foreach (CITADEL_BLOCKED_UA_SUBSTRINGS as $needle) {
        if (str_contains($uaLower, $needle)) {
            @error_log(sprintf(
                '[CITADEL UA-FILTER] Blocked UA="%s" from %s rid=%s',
                substr($ua, 0, 120),
                $_SERVER['REMOTE_ADDR'] ?? '?',
                $GLOBALS['citadel_request_id'] ?? '?'
            ));

            http_response_code(403);
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode([
                'status'     => 'error',
                'code'       => 'client_not_permitted',
                'message'    => 'This client is not permitted to access the API.',
                'request_id' => $GLOBALS['citadel_request_id'],
                'ts'         => gmdate('c'),
            ]);
            exit;
        }
    }
}
// Apply the User-Agent filter (production only).
citadel_apply_ua_filter();

// Classify the client type.
$clientHeader = $_SERVER['HTTP_X_CITADEL_CLIENT'] ?? '';
$clientType   = 'browser';
$clientVer    = '';

if (preg_match('#^(browser|android|ios|api)/([0-9A-Za-z.\-]+)$#i', $clientHeader, $m)) {
    $clientType = strtolower($m[1]);
    $clientVer  = $m[2];
} elseif (!empty($_SERVER['HTTP_USER_AGENT'])) {
    $ua = $_SERVER['HTTP_USER_AGENT'];
    if (str_starts_with($ua, 'MyCitadelAndroid/')) {
        $clientType = 'android';
    } elseif (str_starts_with($ua, 'MyCitadeliOS/')) {
        $clientType = 'ios';
    }
}

$GLOBALS['citadel_client_type']    = $clientType;
$GLOBALS['citadel_client_version'] = $clientVer;


/* ══════════════════════════════════════════════════════════════════════════
 * 11. REAL IP RESOLUTION
 * ========================================================================== */

function citadel_client_ip(): string
{
    static $resolved = null;
    if ($resolved !== null) return $resolved;

    $remote = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

    $trustedRaw = getenv('TRUSTED_PROXIES') ?: '';
    $trusted = array_filter(array_map('trim', explode(',', $trustedRaw)));

    $isTrusted = false;
    foreach ($trusted as $cidr) {
        if (citadel_ip_in_cidr($remote, $cidr)) {
            $isTrusted = true;
            break;
        }
    }

    if (!$isTrusted) return $resolved = $remote;

    $cfIp = $_SERVER['HTTP_CF_CONNECTING_IP'] ?? null;
    if (is_string($cfIp) && filter_var($cfIp, FILTER_VALIDATE_IP)) {
        return $resolved = $cfIp;
    }

    $xff = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? null;
    if (is_string($xff) && $xff !== '') {
        $parts = array_map('trim', explode(',', $xff));
        $first = $parts[0] ?? null;
        if (is_string($first) && filter_var($first, FILTER_VALIDATE_IP)) {
            return $resolved = $first;
        }
    }

    $real = $_SERVER['HTTP_X_REAL_IP'] ?? null;
    if (is_string($real) && filter_var($real, FILTER_VALIDATE_IP)) {
        return $resolved = $real;
    }

    return $resolved = $remote;
}

function citadel_ip_in_cidr(string $ip, string $cidr): bool
{
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
 * 13. CORS POLICY — ENVIRONMENT-AWARE
 * --------------------------------------------------------------------------
 * Production: only .lol domains. No localhost, no capacitor://.
 * Dev/staging: adds localhost + mobile WebView origins for testing.
 * ═════════════════════════════════════════════════════════════════════════ */

/**
 * Build the allowed-origins list based on environment.
 * @return array<int,string>
 */
function citadel_allowed_origins(): array
{
    // Always allowed — production domains.
    $origins = [
        'https://mycitadel.lol',
        'https://www.mycitadel.lol',
        'https://vendors.mycitadel.lol',
    ];

    // Development/staging additions.
    if (!CITADEL_IS_PRODUCTION) {
        $origins = array_merge($origins, [
            'http://localhost:8000',
            'http://localhost:8080',
            'http://127.0.0.1:8000',
            'http://127.0.0.1:8080',
            'capacitor://localhost',
            'ionic://localhost',
            'http://localhost',
        ]);
    }

    return $origins;
}

function citadel_apply_cors(): void
{
    if (PHP_SAPI === 'cli' || headers_sent()) return;

    $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
    if ($origin === '') return;

    $allowed = citadel_allowed_origins();

    if (in_array($origin, $allowed, true)) {
        header('Access-Control-Allow-Origin: ' . $origin);
        header('Access-Control-Allow-Credentials: true');
        header('Vary: Origin');
    } else {
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
    header('Access-Control-Allow-Headers: Content-Type, X-CSRF-Token, X-Requested-With, Authorization, X-Citadel-Client, X-Request-ID, X-Request-Time');
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
 * 16b. MAILER SUBSYSTEM
 * ========================================================================== */

$mailerFile = CITADEL_CONFIG . '/mailer.php';
if (is_file($mailerFile)) {
    require_once $mailerFile;
}

/* ══════════════════════════════════════════════════════════════════════════
 * 17. DATABASE CONNECTION (LAZY SINGLETON)
 * ========================================================================== */

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
        ]);
        
        // Set connection collation explicitly (avoids deprecated PDO::MYSQL_ATTR_INIT_COMMAND).
        // PHP 8.5+ deprecates the constant, so we run it as a post-connect statement.
        $pdo->exec("SET NAMES {$char} COLLATE {$char}_unicode_ci");
    } catch (PDOException $e) {
        citadel_fatal('Database connection failed.', $e, 503);
    }

    return $pdo;
}


/* ══════════════════════════════════════════════════════════════════════════
 * 18. STRUCTURED LOGGING
 * ========================================================================== */

function citadel_log(string $channel, string $level, string $message, array $context = []): void
{
    $channel = preg_replace('/[^a-z0-9_]/', '', strtolower($channel)) ?: 'app';
    $logDir  = CITADEL_LOGS . '/' . $channel;

    if (!is_dir($logDir)) {
        @mkdir($logDir, 0700, true);
    }

    // Cap context payload to prevent log-flooding DoS.
    $encodedCtx = json_encode($context, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    if ($encodedCtx !== false && strlen($encodedCtx) > 8192) {
        $context = ['_truncated' => true, '_original_size' => strlen($encodedCtx)];
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

    // ⚠️ Do NOT trim passwords or secrets — whitespace is significant.
    // Endpoints that need trimming must do it themselves.
    if ($maxLen > 256) {
        // Long fields (passwords, tokens) — return raw
        if (strlen($val) > $maxLen) {
            citadel_json_error('input_too_long',
                "Field '{$key}' exceeds {$maxLen} characters.", 400);
        }
        return $val;
    }

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
 * 21. RATE LIMITING (WITH FILE LOCKING)
 * --------------------------------------------------------------------------
 * The v2 version had a race condition: two concurrent requests could both
 * read "under limit" and both write. This version uses flock() to ensure
 * the read-modify-write cycle is atomic.
 * ═════════════════════════════════════════════════════════════════════════ */

function citadel_rate_limit(string $bucket, int $maxAttempts, int $windowSeconds): void
{
    if (PHP_SAPI === 'cli') return;

    $ip = citadel_client_ip();

    $hmacKey = $GLOBALS['citadel_fingerprint_key'] ?? 'default-rate-limit-key';
    $ipHash  = hash_hmac('sha256', $ip, $hmacKey);

    $dir = CITADEL_LOGS . '/ratelimit';
    if (!is_dir($dir)) @mkdir($dir, 0700, true);

    $safeBucket = preg_replace('/[^a-z0-9_]/', '', strtolower($bucket)) ?: 'default';
    $file = $dir . '/' . $safeBucket . '_' . $ipHash . '.json';

    $now         = time();
    $windowStart = $now - $windowSeconds;

    // Open with exclusive lock for the whole read-modify-write cycle.
    $fh = @fopen($file, 'c+');
    if ($fh === false) {
        // Can't open the file — fail open for availability.
        // (Rate limiter failing = better than the whole API going down.)
        return;
    }

    if (!flock($fh, LOCK_EX)) {
        fclose($fh);
        return;  // Couldn't lock — fail open
    }

    try {
        // Read existing hits.
        $contents = stream_get_contents($fh);
        $hits = [];
        if ($contents !== false && $contents !== '') {
            $decoded = json_decode($contents, true);
            if (is_array($decoded)) {
                $hits = array_values(array_filter(
                    $decoded,
                    fn($t) => is_int($t) && $t > $windowStart
                ));
            }
        }

        // Enforce limit.
        if (count($hits) >= $maxAttempts) {
            $retryAfter = $windowSeconds - ($now - min($hits));
            flock($fh, LOCK_UN);
            fclose($fh);

            header('Retry-After: ' . max(1, $retryAfter));

            if (function_exists('citadel_log')) {
                citadel_log('security', 'warning', 'Rate limit exceeded', [
                    'bucket'  => $safeBucket,
                    'ip_hash' => substr($ipHash, 0, 12),
                ]);
            }

            citadel_json_error('rate_limited',
                "Too many requests. Try again in {$retryAfter} seconds.", 429);
        }

        // Record this hit and write back atomically.
        $hits[] = $now;
        ftruncate($fh, 0);
        rewind($fh);
        fwrite($fh, json_encode($hits));
        fflush($fh);

    } finally {
        flock($fh, LOCK_UN);
        fclose($fh);
    }
}


/* ══════════════════════════════════════════════════════════════════════════
 * 22. INTERNAL REQUEST WHITELIST — NEW
 * --------------------------------------------------------------------------
 * Requests from localhost are treated as "internal" and bypass the
 * origin gate and UA filter. This lets:
 *   • Health-check scripts run without spoofing headers
 *   • Cron jobs call internal endpoints
 *   • Local monitoring tools hit the API cleanly
 *
 * In production, only 127.0.0.1 and ::1 are internal. In dev/staging,
 * that's still the case — we don't want a compromised network position
 * to grant internal status.
 * ═════════════════════════════════════════════════════════════════════════ */

function citadel_is_internal_request(): bool
{
    static $cached = null;
    if ($cached !== null) return $cached;

    if (PHP_SAPI === 'cli') return $cached = true;

    $remote = $_SERVER['REMOTE_ADDR'] ?? '';
    $cached = in_array($remote, ['127.0.0.1', '::1', 'localhost'], true);
    return $cached;
}


/* ══════════════════════════════════════════════════════════════════════════
 * 23. REQUEST REPLAY PROTECTION — OPTIONAL HEADER
 * --------------------------------------------------------------------------
 * If a client sends X-Request-Time (Unix timestamp), we validate it's
 * within ±300 seconds of server time. This blocks replay attacks where
 * an attacker captures a request and re-sends it later.
 *
 * Clients that don't send the header aren't affected — this is opt-in
 * hardening for mobile apps and future signed-request schemes.
 *
 * The header alone isn't sufficient for replay protection (attacker can
 * also spoof the timestamp), but when combined with HMAC signing later,
 * it becomes the timestamp component of a signed request.
 * ═════════════════════════════════════════════════════════════════════════ */

function citadel_check_request_time(): void
{
    if (PHP_SAPI === 'cli') return;
    if (citadel_is_internal_request()) return;

    $header = $_SERVER['HTTP_X_REQUEST_TIME'] ?? '';
    if ($header === '') return;  // opt-in

    if (!ctype_digit($header)) {
        citadel_json_error('invalid_request_time',
            'X-Request-Time must be a Unix timestamp.', 400);
    }

    $clientTime = (int) $header;
    $serverTime = time();
    $drift      = abs($serverTime - $clientTime);

    if ($drift > 300) {
        @error_log(sprintf(
            '[CITADEL REPLAY] Clock drift %ds from %s rid=%s',
            $drift,
            $_SERVER['REMOTE_ADDR'] ?? '?',
            $GLOBALS['citadel_request_id'] ?? '?'
        ));

        citadel_json_error('request_expired',
            'Request timestamp is outside the allowed window.', 400);
    }
}

citadel_check_request_time();


/* ══════════════════════════════════════════════════════════════════════════
 * ▓▓▓ END OF BOOTSTRAP.PHP ▓▓▓
 * --------------------------------------------------------------------------
 * Order matters:
 *   00. Request ID   — before anything can fail
 *   01. Guard        — prevent double-load
 *   02. Paths        — before any file operation
 *   05. Handlers     — before any code that might throw
 *   06. Env          — before anything reads config
 *   07. Validation   — before anything uses config
 *   09b. Origin Gate — before any endpoint runs
 *   10. UA Filter    — before any endpoint runs
 *   21. Rate Limit   — with flock, atomic
 *   22. Internal     — used by gate + UA filter
 *
 * When in doubt: fail closed, log loudly, return JSON.
 * — Bearded Viking
 * ═════════════════════════════════════════════════════════════════════════ */