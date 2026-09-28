<?php
/* ============================================================================
 * ███ API.MYCITADEL.LOL/INDEX.PHP ███
 * MyCitadel — Public API Documentation
 * ----------------------------------------------------------------------------
 * Path    : /home/beardedviking/api.mycitadel.lol/index.php
 * Author  : Bearded Viking (https://beardedviking.org)
 * Project : MyCitadel (https://mycitadel.lol)
 * License : MIT
 *
 * ══════════════════════════════════════════════════════════════════════════
 * PURPOSE
 * ══════════════════════════════════════════════════════════════════════════
 *
 * This is the front door of the API. Every developer, bug-bounty hunter,
 * and future contributor lands here first. It is BOTH:
 *
 *   1. A human-readable reference for every endpoint, organized by feature
 *      area (auth, users, posts, etc.), with request/response shapes and
 *      copy-paste curl examples.
 *
 *   2. A living data structure — the $ENDPOINTS array below is the single
 *      source of truth. If a new endpoint is added and the array is not
 *      updated, the docs are wrong. The fix is one array entry, not HTML
 *      surgery.
 *
 * ══════════════════════════════════════════════════════════════════════════
 * PUBLIC-SAFETY RULES — WHAT MUST NEVER APPEAR ON THIS PAGE
 * ══════════════════════════════════════════════════════════════════════════
 *
 *   ✗ Absolute filesystem paths (/home/beardedviking/...)
 *   ✗ Environment variable names or values
 *   ✗ Internal table names or schema details
 *   ✗ Internal function names, file names, or code structure
 *   ✗ The health endpoint URL (it requires a token and should not be
 *     advertised)
 *   ✗ Any secret, key, salt, or token — even truncated
 *   ✗ Database connection details
 *
 * Everything visible on this page is intended for public consumption.
 * PHP comments (/* * /) do not render to HTML — but they are also
 * preserved in the source file. Do not put secrets in comments either.
 * ========================================================================== */

declare(strict_types=1);

// Security headers — consistent with the rest of the API surface.
// This is a public static page, but consistency matters.
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
header_remove('X-Powered-By');

/* ══════════════════════════════════════════════════════════════════════════
 * ENDPOINT CATALOG
 * --------------------------------------------------------------------------
 * Every endpoint the API exposes. Grouped by feature area.
 *
 * Each endpoint entry:
 *   method   — HTTP verb
 *   path     — full path (leading /v1 included)
 *   auth     — true if a session cookie is required
 *   csrf     — true if X-CSRF-Token is required (unsafe methods only)
 *   summary  — one-line description
 *   body     — optional request body example (JSON string for display)
 *   response — optional success response example (JSON string for display)
 *   notes    — optional additional context
 * ========================================================================== */

$ENDPOINTS = [

    'Authentication' => [
        'description' => 'Obtain a session, prove you are who you say you are, and end the session when done.',
        'endpoints' => [
            [
                'method'  => 'GET',
                'path'    => '/v1/auth/csrf.php',
                'auth'    => false,
                'csrf'    => false,
                'summary' => 'Mint a fresh CSRF token. Call this first on any page load.',
                'response' => '{"status":"ok","token":"<hex>","expires_in":3600}',
                'notes'   => 'The token is also set in the citadel_csrf cookie for browser clients. Rotate it by calling this endpoint again. The API rotates it automatically on login, logout, and password change.',
            ],
            [
                'method'  => 'POST',
                'path'    => '/v1/auth/register.php',
                'auth'    => false,
                'csrf'    => true,
                'summary' => 'Create a new MyCitadel account.',
                'body'    => "{\n  \"username\": \"viking_42\",\n  \"email\": \"viking@example.com\",\n  \"password\": \"correct-horse-battery-staple\"\n}",
                'response'=> '{"status":"ok","user":{"id":42,"username":"viking_42","reputation":500,"premium":false},"csrf_token":"<hex>"}',
                'notes'   => 'On success, an authenticated session is created immediately. The registration badge (+500 rep) is awarded. Username must be 3–32 characters, letters/numbers/underscores only. Password minimum: 12 characters.',
            ],
            [
                'method'  => 'POST',
                'path'    => '/v1/auth/login.php',
                'auth'    => false,
                'csrf'    => true,
                'summary' => 'Authenticate with username/email and password.',
                'body'    => "{\n  \"identifier\": \"viking_42\",\n  \"password\": \"correct-horse-battery-staple\"\n}",
                'response'=> '{"status":"ok","user":{"id":42,"username":"viking_42","reputation":1520,"premium":false},"csrf_token":"<hex>"}',
                'notes'   => 'If the account has 2FA enabled, the response is instead: {"status":"ok","two_fa_required":true,"expires_in":300}. Complete the flow via /v1/auth/login_2fa.php.',
            ],
            [
                'method'  => 'POST',
                'path'    => '/v1/auth/login_2fa.php',
                'auth'    => false,
                'csrf'    => true,
                'summary' => 'Complete login when 2FA is enabled.',
                'body'    => "{\n  \"code\": \"123456\"\n}",
                'response'=> '{"status":"ok","user":{"id":42,"username":"viking_42"},"csrf_token":"<hex>","via_recovery_code":false}',
                'notes'   => 'Accepts either a 6-digit TOTP code or a recovery code. Only valid if the immediately-preceding login.php returned two_fa_required. Expires in 5 minutes.',
            ],
            [
                'method'  => 'POST',
                'path'    => '/v1/auth/logout.php',
                'auth'    => true,
                'csrf'    => true,
                'summary' => 'End the current session.',
                'response'=> '{"status":"ok","message":"You have been logged out."}',
                'notes'   => 'Session cookie, CSRF cookie, and hint cookie are all cleared. Idempotent — calling twice is fine.',
            ],
        ],
    ],

    'Two-Factor Authentication' => [
        'description' => 'TOTP-based second factor compatible with Google Authenticator, Microsoft Authenticator, Authy, 1Password, Bitwarden, and any RFC 6238 app.',
        'endpoints' => [
            [
                'method'  => 'GET',
                'path'    => '/v1/auth/2fa/status.php',
                'auth'    => true,
                'csrf'    => false,
                'summary' => 'Check whether 2FA is enabled and how many recovery codes remain.',
                'response'=> '{"status":"ok","two_fa_enabled":true,"two_fa_enabled_at":"2026-09-27T22:00:00+00:00","recovery_codes_remaining":9}',
            ],
            [
                'method'  => 'POST',
                'path'    => '/v1/auth/2fa/setup.php',
                'auth'    => true,
                'csrf'    => true,
                'summary' => 'Begin 2FA setup. Returns a QR code and secret.',
                'body'    => "{\n  \"password\": \"correct-horse-battery-staple\"\n}",
                'response'=> '{"status":"ok","otpauth_url":"otpauth://totp/...","secret":"<base32>","qr_code":"data:image/png;base64,...","account":"viking_42","issuer":"MyCitadel"}',
                'notes'   => 'Requires current password. The QR code is a PNG data URI ready to embed in an <img> tag. The base32 secret is for manual entry. 2FA is NOT yet active — confirm with /v1/auth/2fa/verify.php.',
            ],
            [
                'method'  => 'POST',
                'path'    => '/v1/auth/2fa/verify.php',
                'auth'    => true,
                'csrf'    => true,
                'summary' => 'Confirm 2FA setup by entering the first valid code.',
                'body'    => "{\n  \"code\": \"123456\"\n}",
                'response'=> '{"status":"ok","two_fa_enabled":true,"recovery_codes":["ABCD-EFGH-IJKL", "..."],"reputation_earned":1500}',
                'notes'   => 'On success, 2FA is enabled, the Guardian badge is awarded (+1500 reputation), and 10 recovery codes are returned. These codes are shown ONLY ONCE — save them immediately.',
            ],
            [
                'method'  => 'POST',
                'path'    => '/v1/auth/2fa/disable.php',
                'auth'    => true,
                'csrf'    => true,
                'summary' => 'Disable 2FA. Requires password AND a valid code.',
                'body'    => "{\n  \"password\": \"correct-horse-battery-staple\",\n  \"code\": \"123456\"\n}",
                'response'=> '{"status":"ok","two_fa_enabled":false,"message":"Two-factor disabled."}',
                'notes'   => 'Accepts either a 6-digit TOTP code or a recovery code. The Guardian badge and its reputation are NOT removed.',
            ],
        ],
    ],

    'Verification & Recovery' => [
        'description' => 'Email verification, password reset, and account unlock flows.',
        'endpoints' => [
            [
                'method'  => 'POST',
                'path'    => '/v1/verify/send.php',
                'auth'    => true,
                'csrf'    => true,
                'summary' => 'Request a verification email for the current account.',
                'response'=> '{"status":"ok","message":"If your email requires verification, a link has been sent.","expires_in":86400}',
                'notes'   => 'Rate-limited per user. Prior unconsumed tokens are invalidated.',
            ],
            [
                'method'  => 'POST',
                'path'    => '/v1/verify/verify.php',
                'auth'    => true,
                'csrf'    => true,
                'summary' => 'Consume an email verification token.',
                'body'    => "{\n  \"token\": \"<64-hex>\"\n}",
                'response'=> '{"status":"ok","message":"Email verified successfully.","email_verified":true}',
                'notes'   => 'Single-use. Awards the Verified Citizen badge (+1000 reputation).',
            ],
            [
                'method'  => 'POST',
                'path'    => '/v1/verify/password_reset_request.php',
                'auth'    => false,
                'csrf'    => true,
                'summary' => 'Request a password reset email.',
                'body'    => "{\n  \"email\": \"viking@example.com\"\n}",
                'response'=> '{"status":"ok","message":"If an account exists for that email, a reset link has been sent.","expires_in":900}',
                'notes'   => 'Returns the same response for existent and non-existent accounts. Link expires in 15 minutes. Rate-limited per email.',
            ],
            [
                'method'  => 'POST',
                'path'    => '/v1/verify/password_reset_exchange.php',
                'auth'    => false,
                'csrf'    => true,
                'summary' => 'Exchange a reset token for a session authorization.',
                'body'    => "{\n  \"token\": \"<64-hex>\"\n}",
                'response'=> '{"status":"ok","message":"Reset link verified. You may now set a new password.","expires_in":900}',
                'notes'   => 'Consumes the URL token IMMEDIATELY. Sets a session flag authorizing the actual reset.',
            ],
            [
                'method'  => 'POST',
                'path'    => '/v1/verify/password_reset_consume.php',
                'auth'    => false,
                'csrf'    => true,
                'summary' => 'Set the new password.',
                'body'    => "{\n  \"password\": \"new-strong-password-42\"\n}",
                'response'=> '{"status":"ok","message":"Password reset successful. You are now logged in.","csrf_token":"<hex>"}',
                'notes'   => 'Requires a valid session authorization from the exchange step. Invalidates ALL other sessions. Sends a confirmation email to the account owner.',
            ],
            [
                'method'  => 'POST',
                'path'    => '/v1/verify/unlock.php',
                'auth'    => false,
                'csrf'    => true,
                'summary' => 'Unlock a locked account via email link.',
                'body'    => "{\n  \"token\": \"<64-hex>\"\n}",
                'response'=> '{"status":"ok","message":"Your account has been unlocked."}',
            ],
        ],
    ],

    'Users' => [
        'description' => 'Read and update your own account, browse the directory, and view other users.',
        'endpoints' => [
            [
                'method'  => 'GET',
                'path'    => '/v1/users/me.php',
                'auth'    => true,
                'csrf'    => false,
                'summary' => 'Return the current user profile with decrypted email.',
                'response'=> '{"status":"ok","user":{"id":42,"username":"viking_42","email":"viking@example.com","reputation":3170,"premium":false,"email_verified":true,"is_active":true,"created_at":"...","last_login_at":"..."}}',
            ],
            [
                'method'  => 'POST',
                'path'    => '/v1/users/update.php',
                'auth'    => true,
                'csrf'    => true,
                'summary' => 'Update username, email, or password.',
                'body'    => "{\n  \"username\": \"new_name\",\n  \"current_password\": \"...\"\n}",
                'notes'   => 'Changing email or password requires current_password. Username changes re-index the blind index atomically.',
            ],
            [
                'method'  => 'GET',
                'path'    => '/v1/users/dashboard.php',
                'auth'    => true,
                'csrf'    => false,
                'summary' => 'Aggregated dashboard: identity, account, stats, rank, badges, activity, community.',
                'response'=> '{"status":"ok","identity":{...},"account":{...},"stats":{...},"rank":{...},"badges":[...],"activity":[...],"community":{...},"features":{...}}',
                'notes'   => 'Single round-trip for the dashboard UI. Six indexed queries total.',
            ],
            [
                'method'  => 'GET',
                'path'    => '/v1/users/list.php',
                'auth'    => true,
                'csrf'    => false,
                'summary' => 'Browse the user directory with optional search.',
                'notes'   => 'Query params: ?q=<search>&limit=24&offset=0&exclude_connected=1. Search matches username or display_name. Blocked users are always excluded.',
            ],
            [
                'method'  => 'GET',
                'path'    => '/v1/users/view.php',
                'auth'    => true,
                'csrf'    => false,
                'summary' => 'View another user\'s profile.',
                'notes'   => 'Query param: ?id=N. Returns 404 for blocked, hidden, or non-visible users — never reveals existence. Non-connected users see a limited card; connections see the full profile.',
            ],
            [
                'method'  => 'POST',
                'path'    => '/v1/users/settings.php',
                'auth'    => true,
                'csrf'    => true,
                'summary' => 'Update visibility and privacy toggles.',
                'body'    => "{\n  \"visibility\": \"public\",\n  \"privacy_toggles\": {\n    \"show_email\": false,\n    \"show_location\": true\n  }\n}",
                'notes'   => 'visibility values: public | connections_only | hidden.',
            ],
            [
                'method'  => 'GET',
                'path'    => '/v1/users/profile.php',
                'auth'    => true,
                'csrf'    => false,
                'summary' => 'Return the current user\'s full editable profile (PII decrypted).',
            ],
            [
                'method'  => 'POST',
                'path'    => '/v1/users/profile_update.php',
                'auth'    => true,
                'csrf'    => true,
                'summary' => 'Update any subset of profile fields.',
                'notes'   => '60+ fields accepted. PII is encrypted at rest with per-user envelope keys. URLs are HTTPS-only. Media URLs must be on mycitadel-owned hosts.',
            ],
            [
                'method'  => 'POST',
                'path'    => '/v1/users/delete_account.php',
                'auth'    => true,
                'csrf'    => true,
                'summary' => 'Request account deletion (step 1 of 2).',
                'body'    => "{\n  \"password\": \"...\",\n  \"confirmation_phrase\": \"DELETE MY ACCOUNT\"\n}",
            ],
            [
                'method'  => 'POST',
                'path'    => '/v1/users/delete_account_confirm.php',
                'auth'    => true,
                'csrf'    => true,
                'summary' => 'Confirm account destruction (step 2 of 2).',
                'body'    => "{\n  \"token\": \"<64-hex>\"\n}",
                'notes'   => 'Destroys posts, comments, reactions, connections, media. Adjusts reputation for affected connections. Irreversible.',
            ],
        ],
    ],

    'Connections' => [
        'description' => 'The social graph. Request, accept, or block connections. Blocking is mutual and permanent.',
        'endpoints' => [
            [
                'method'  => 'POST',
                'path'    => '/v1/connections/request.php',
                'auth'    => true,
                'csrf'    => true,
                'summary' => 'Send a connection request.',
                'body'    => "{\n  \"user_id\": 42,\n  \"message\": \"Hi from the North\"\n}",
            ],
            [
                'method'  => 'POST',
                'path'    => '/v1/connections/accept.php',
                'auth'    => true,
                'csrf'    => true,
                'summary' => 'Accept a pending connection request.',
                'body'    => "{\n  \"user_id\": 42\n}",
                'notes'   => 'Awards +25 reputation to both parties.',
            ],
            [
                'method'  => 'POST',
                'path'    => '/v1/connections/block.php',
                'auth'    => true,
                'csrf'    => true,
                'summary' => 'Block, deny, or sever a connection.',
                'body'    => "{\n  \"user_id\": 42,\n  \"reason\": \"optional\"\n}",
                'notes'   => 'Severing a connection deducts 25 reputation from both parties. Silent — no notification is sent.',
            ],
            [
                'method'  => 'GET',
                'path'    => '/v1/connections/list.php',
                'auth'    => true,
                'csrf'    => false,
                'summary' => 'List accepted connections.',
                'notes'   => 'Query params: ?limit=50&offset=0&sort=recent|rep|name.',
            ],
            [
                'method'  => 'GET',
                'path'    => '/v1/connections/pending.php',
                'auth'    => true,
                'csrf'    => false,
                'summary' => 'List incoming connection requests awaiting your response.',
            ],
        ],
    ],

    'Posts' => [
        'description' => 'The content layer. Visibility is gated by connection state.',
        'endpoints' => [
            [
                'method'  => 'POST',
                'path'    => '/v1/posts/create.php',
                'auth'    => true,
                'csrf'    => true,
                'summary' => 'Create a post.',
                'body'    => "{\n  \"content\": \"Hello, Citadel.\",\n  \"visibility\": \"connections\"\n}",
                'notes'   => 'Awards +10 reputation. visibility: public | connections | private.',
            ],
            [
                'method'  => 'GET',
                'path'    => '/v1/posts/view.php',
                'auth'    => true,
                'csrf'    => false,
                'summary' => 'View a single post.',
                'notes'   => 'Query param: ?id=N. Returns 404 if the viewer is not authorized.',
            ],
            [
                'method'  => 'GET',
                'path'    => '/v1/posts/user.php',
                'auth'    => true,
                'csrf'    => false,
                'summary' => 'List posts by a user.',
                'notes'   => 'Query params: ?user_id=N&limit=20&offset=0.',
            ],
            [
                'method'  => 'POST',
                'path'    => '/v1/posts/update.php',
                'auth'    => true,
                'csrf'    => true,
                'summary' => 'Edit your own post.',
                'body'    => "{\n  \"id\": 5,\n  \"content\": \"Edited.\"\n}",
            ],
            [
                'method'  => 'POST',
                'path'    => '/v1/posts/delete.php',
                'auth'    => true,
                'csrf'    => true,
                'summary' => 'Soft-delete your own post.',
                'body'    => "{\n  \"id\": 5\n}",
                'notes'   => 'Deducts 10 reputation (undoes creation award).',
            ],
        ],
    ],

    'Comments' => [
        'description' => 'Comment on posts or reply to existing comments.',
        'endpoints' => [
            [
                'method'  => 'POST',
                'path'    => '/v1/comments/create.php',
                'auth'    => true,
                'csrf'    => true,
                'summary' => 'Post a comment or reply.',
                'body'    => "{\n  \"post_id\": 5,\n  \"content\": \"Nice post!\",\n  \"parent_id\": null\n}",
                'notes'   => 'Awards +5 to the commenter, +20 to the post author. Notifies both the post author and (if a reply) the parent comment author.',
            ],
            [
                'method'  => 'GET',
                'path'    => '/v1/comments/list.php',
                'auth'    => true,
                'csrf'    => false,
                'summary' => 'List comments on a post.',
                'notes'   => 'Query params: ?post_id=N&limit=50&offset=0.',
            ],
            [
                'method'  => 'POST',
                'path'    => '/v1/comments/delete.php',
                'auth'    => true,
                'csrf'    => true,
                'summary' => 'Delete your own comment.',
                'body'    => "{\n  \"id\": 12\n}",
            ],
        ],
    ],

    'Reactions' => [
        'description' => 'Three-way toggle: no reaction → insert, same reaction → remove, different reaction → change.',
        'endpoints' => [
            [
                'method'  => 'POST',
                'path'    => '/v1/reactions/toggle.php',
                'auth'    => true,
                'csrf'    => true,
                'summary' => 'Toggle a reaction on a post or comment.',
                'body'    => "{\n  \"target_type\": \"post\",\n  \"target_id\": 5,\n  \"reaction\": \"heart\"\n}",
                'notes'   => 'target_type: post | comment. reaction: like | dislike | heart | angry. Reputation delta depends on the reaction type.',
            ],
        ],
    ],

    'Feed' => [
        'description' => 'Aggregated timeline of posts from connections and yourself.',
        'endpoints' => [
            [
                'method'  => 'GET',
                'path'    => '/v1/feed.php',
                'auth'    => true,
                'csrf'    => false,
                'summary' => 'Fetch the feed.',
                'notes'   => 'Query params: ?scope=all|self|connections&limit=20&cursor=<opaque>. Cursor pagination is stable across insertions.',
            ],
        ],
    ],

    'Notifications' => [
        'description' => 'In-app notifications plus Web Push delivery to subscribed browsers.',
        'endpoints' => [
            [
                'method'  => 'GET',
                'path'    => '/v1/notifications/list.php',
                'auth'    => true,
                'csrf'    => false,
                'summary' => 'List notifications.',
                'notes'   => 'Query params: ?unread_only=1&limit=50.',
            ],
            [
                'method'  => 'POST',
                'path'    => '/v1/notifications/read.php',
                'auth'    => true,
                'csrf'    => true,
                'summary' => 'Mark a notification (or all) as read.',
                'body'    => "{\n  \"id\": 5\n}\n// or: {\"all\": true}",
            ],
        ],
    ],

    'Web Push' => [
        'description' => 'Real-time OS notifications delivered to subscribed browsers via VAPID.',
        'endpoints' => [
            [
                'method'  => 'GET',
                'path'    => '/v1/push/vapid-public-key.php',
                'auth'    => false,
                'csrf'    => false,
                'summary' => 'Fetch the VAPID public key for the frontend to subscribe.',
                'response'=> '{"status":"ok","public_key":"B..."}',
            ],
            [
                'method'  => 'POST',
                'path'    => '/v1/push/subscribe.php',
                'auth'    => true,
                'csrf'    => true,
                'summary' => 'Register a browser push subscription.',
                'body'    => "{\n  \"endpoint\": \"https://fcm.googleapis.com/...\",\n  \"keys\": { \"p256dh\": \"...\", \"auth\": \"...\" }\n}",
                'notes'   => 'Endpoint must be from a known push service. Keys are validated for correct format.',
            ],
            [
                'method'  => 'POST',
                'path'    => '/v1/push/unsubscribe.php',
                'auth'    => true,
                'csrf'    => true,
                'summary' => 'Remove a browser push subscription.',
                'body'    => "{\n  \"endpoint\": \"https://fcm.googleapis.com/...\"\n}",
            ],
        ],
    ],

    'Uploads' => [
        'description' => 'Image uploads for avatar, banner, and wallpaper. All uploads are re-encoded server-side to strip metadata and normalize format.',
        'endpoints' => [
            [
                'method'  => 'POST',
                'path'    => '/v1/upload/avatar.php',
                'auth'    => true,
                'csrf'    => true,
                'summary' => 'Upload a profile avatar.',
                'body'    => 'multipart/form-data — field name: file',
                'notes'   => 'Resized to 512×512 JPEG. Max 5 MB. Accepts JPEG, PNG, WebP. SVG rejected (XSS vector).',
            ],
            [
                'method'  => 'POST',
                'path'    => '/v1/upload/banner.php',
                'auth'    => true,
                'csrf'    => true,
                'summary' => 'Upload a profile banner.',
                'notes'   => 'Resized to 1500×500 JPEG.',
            ],
            [
                'method'  => 'POST',
                'path'    => '/v1/upload/wallpaper.php',
                'auth'    => true,
                'csrf'    => true,
                'summary' => 'Upload a profile wallpaper.',
                'notes'   => 'Resized to 1920×1080 JPEG.',
            ],
        ],
    ],
    'Premium Subscriptions' => [
        'description' => 'Monthly premium tier powered by Stripe Checkout. Users upgrade through a Stripe-hosted payment page; all subscription state is synced back via signed webhooks.',
        'endpoints' => [
            [
                'method'  => 'GET',
                'path'    => '/v1/premium/status.php',
                'auth'    => true,
                'csrf'    => false,
                'summary' => 'Return the current premium status for the authenticated user.',
                'response'=> '{"status":"ok","premium":{"is_premium":true,"premium_since":"2026-09-28T00:53:35+00:00","premium_expires_at":"2026-10-28T00:41:43+00:00","has_customer":true,"has_subscription":true,"stripe_status":"active"}}',
                'notes'   => 'Cheap lookup — safe to call on every page load. Combines our cached state with a live Stripe lookup when a subscription exists.',
            ],
            [
                'method'  => 'POST',
                'path'    => '/v1/premium/checkout.php',
                'auth'    => true,
                'csrf'    => true,
                'summary' => 'Create a Stripe Checkout session for the premium subscription.',
                'body'    => "{}",
                'response'=> '{"status":"ok","checkout_url":"https://checkout.stripe.com/c/pay/cs_...","session_id":"cs_..."}',
                'notes'   => 'Returns a URL to redirect the browser to. On success, Stripe sends the user to STRIPE_SUCCESS_URL with ?session_id= appended, and fires a checkout.session.completed webhook. Rate-limited to 10 requests per hour per user.',
            ],
            [
                'method'  => 'POST',
                'path'    => '/v1/premium/portal.php',
                'auth'    => true,
                'csrf'    => true,
                'summary' => 'Open the Stripe Customer Portal to manage or cancel the subscription.',
                'body'    => "{}",
                'response'=> '{"status":"ok","portal_url":"https://billing.stripe.com/p/session?secret=..."}',
                'notes'   => 'Users can update their payment method, download invoices, and cancel — either immediately or at the end of the billing period. When the subscription is canceled, Stripe fires a customer.subscription.deleted webhook and premium access ends at the period boundary. No additional endpoint is needed for cancellation.',
            ],
            [
                'method'  => 'POST',
                'path'    => '/v1/premium/webhook.php',
                'auth'    => false,
                'csrf'    => false,
                'summary' => 'Stripe → MyCitadel event delivery. Not for client use.',
                'notes'   => 'Called only by Stripe. Authenticity is enforced by HMAC-SHA256 signature verification against STRIPE_WEBHOOK_SECRET — never by session cookie or CSRF token. Handles checkout.session.completed, customer.subscription.created/updated/deleted, invoice.paid, invoice_payment.paid, and invoice.payment_failed. Events are deduplicated by event ID for idempotency.',
            ],
        ],
    ],    
];

/* ══════════════════════════════════════════════════════════════════════════
 * HELPER FUNCTIONS
 * ========================================================================== */

/** Escape text safely for HTML output. */
function e(?string $s): string
{
    return htmlspecialchars((string) $s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/** Count total endpoints for the header stat. */
function count_endpoints(array $groups): int
{
    $n = 0;
    foreach ($groups as $g) {
        $n += count($g['endpoints']);
    }
    return $n;
}

$totalEndpoints = count_endpoints($ENDPOINTS);

?><!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="referrer" content="strict-origin-when-cross-origin">
<title>MyCitadel API — Developer Reference</title>
<meta name="description" content="The MyCitadel API reference. Endpoints, authentication, CSRF, rate limits, error codes, and security guarantees for the privacy-first social platform.">
<link rel="stylesheet" href="https://vendors.mycitadel.lol/css/citadel.css">
<style>
    /* ── Page layout ──────────────────────────────────────────────── */
    body.api-docs {
        background-image:
            radial-gradient(ellipse at 20% 0%, rgba(0, 229, 255, 0.06) 0%, transparent 45%),
            radial-gradient(ellipse at 80% 100%, rgba(168, 85, 247, 0.05) 0%, transparent 45%),
            linear-gradient(rgba(0, 229, 255, 0.02) 1px, transparent 1px),
            linear-gradient(90deg, rgba(0, 229, 255, 0.02) 1px, transparent 1px);
        background-size: 100% 100%, 100% 100%, 44px 44px, 44px 44px;
    }

    .api-container {
        max-width: 1100px;
        margin: 0 auto;
        padding: 0 1.5rem 4rem;
    }

    /* ── Hero ─────────────────────────────────────────────────────── */
    .api-hero {
        padding: 5rem 1.5rem 3rem;
        text-align: center;
        border-bottom: 1px solid rgba(0, 229, 255, 0.15);
        margin-bottom: 3rem;
        position: relative;
        overflow: hidden;
    }
    .api-hero::after {
        content: '';
        position: absolute;
        left: 0; right: 0;
        height: 2px;
        background: linear-gradient(90deg, transparent, var(--c-cyan), transparent);
        opacity: 0.5;
        animation: scan-line 8s linear infinite;
    }
    .api-hero h1 {
        font-family: var(--f-display);
        font-size: clamp(2rem, 5vw, 3.5rem);
        letter-spacing: 0.14em;
        text-transform: uppercase;
        color: var(--c-cyan-bright);
        text-shadow: 0 0 10px rgba(0, 229, 255, 0.8), 0 0 30px rgba(0, 229, 255, 0.35);
        margin: 0 0 0.75rem;
    }
    .api-hero .version-badge {
        display: inline-block;
        padding: 0.35rem 0.9rem;
        font-family: var(--f-mono);
        font-size: 0.72rem;
        letter-spacing: 0.18em;
        text-transform: uppercase;
        color: var(--c-gold);
        border: 1px solid rgba(212, 175, 55, 0.5);
        border-radius: 999px;
        margin-bottom: 1rem;
        box-shadow: 0 0 8px rgba(212, 175, 55, 0.3);
    }
    .api-hero p {
        color: var(--c-text-dim);
        max-width: 720px;
        margin: 0 auto;
        font-size: 1.05rem;
        line-height: 1.6;
    }

    /* ── Quick facts grid ─────────────────────────────────────────── */
    .api-facts {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
        gap: 1rem;
        margin-bottom: 3rem;
    }
    .api-fact {
        padding: 1.25rem;
        background: rgba(0, 229, 255, 0.03);
        border: 1px solid rgba(0, 229, 255, 0.15);
        border-radius: var(--r-md);
    }
    .api-fact .label {
        font-family: var(--f-tech);
        font-size: 0.7rem;
        letter-spacing: 0.16em;
        text-transform: uppercase;
        color: var(--c-text-dim);
        margin-bottom: 0.4rem;
    }
    .api-fact .value {
        font-family: var(--f-mono);
        font-size: 1rem;
        color: var(--c-cyan-bright);
        word-break: break-all;
    }
    .api-fact .value.gold {
        color: var(--c-gold-bright);
        text-shadow: 0 0 8px rgba(212, 175, 55, 0.4);
    }

    /* ── Section ──────────────────────────────────────────────────── */
    .api-section {
        margin-bottom: 4rem;
    }
    .api-section-header {
        margin-bottom: 1.5rem;
        padding-bottom: 0.75rem;
        border-bottom: 1px solid rgba(0, 229, 255, 0.15);
    }
    .api-section-header h2 {
        font-family: var(--f-heading);
        font-size: 1.6rem;
        color: var(--c-gold-bright);
        margin: 0 0 0.4rem;
        letter-spacing: 0.08em;
    }
    .api-section-header p {
        color: var(--c-text-dim);
        margin: 0;
        font-size: 0.95rem;
        line-height: 1.6;
    }

    /* ── Endpoint card ────────────────────────────────────────────── */
    .api-endpoint {
        margin-bottom: 1.25rem;
        padding: 1.5rem;
        background: rgba(16, 21, 29, 0.6);
        border: 1px solid rgba(0, 229, 255, 0.12);
        border-left: 3px solid var(--c-cyan);
        border-radius: var(--r-md);
        transition: border-color 200ms, background 200ms;
    }
    .api-endpoint:hover {
        border-color: rgba(0, 229, 255, 0.35);
        background: rgba(16, 21, 29, 0.85);
    }

    .endpoint-head {
        display: flex;
        align-items: center;
        gap: 0.75rem;
        flex-wrap: wrap;
        margin-bottom: 0.75rem;
    }
    .method-badge {
        display: inline-block;
        padding: 0.25rem 0.7rem;
        font-family: var(--f-tech);
        font-size: 0.7rem;
        font-weight: 700;
        letter-spacing: 0.14em;
        border-radius: 4px;
        border: 1px solid currentColor;
    }
    .method-get    { color: var(--c-success); background: rgba(57, 255, 20, 0.08); }
    .method-post   { color: var(--c-cyan);    background: rgba(0, 229, 255, 0.08); }
    .method-put    { color: var(--c-gold);    background: rgba(212, 175, 55, 0.08); }
    .method-delete { color: var(--c-blood);   background: rgba(239, 68, 68, 0.08); }

    .endpoint-path {
        font-family: var(--f-mono);
        font-size: 0.95rem;
        color: var(--c-text);
        word-break: break-all;
    }

    .endpoint-tags {
        display: flex;
        gap: 0.4rem;
        flex-wrap: wrap;
        margin-left: auto;
    }
    .tag {
        padding: 0.15rem 0.55rem;
        font-family: var(--f-mono);
        font-size: 0.62rem;
        letter-spacing: 0.1em;
        text-transform: uppercase;
        border-radius: 999px;
        border: 1px solid currentColor;
    }
    .tag-auth  { color: var(--c-gold);   background: rgba(212, 175, 55, 0.06); }
    .tag-csrf  { color: var(--c-rune);   background: rgba(168, 85, 247, 0.06); }
    .tag-public{ color: var(--c-success);background: rgba(57, 255, 20, 0.06); }

    .endpoint-summary {
        color: var(--c-text);
        margin: 0.5rem 0 0.75rem;
        font-size: 0.95rem;
        line-height: 1.5;
    }

    .endpoint-block {
        margin-top: 0.75rem;
    }
    .endpoint-block .label {
        font-family: var(--f-tech);
        font-size: 0.65rem;
        letter-spacing: 0.16em;
        text-transform: uppercase;
        color: var(--c-text-dim);
        margin-bottom: 0.35rem;
        display: block;
    }

    .code-block {
        position: relative;
        padding: 0.9rem 1rem;
        background: #0a0e14;
        border: 1px solid rgba(0, 229, 255, 0.12);
        border-left: 3px solid var(--c-rune);
        border-radius: var(--r-sm);
        font-family: var(--f-mono);
        font-size: 0.82rem;
        line-height: 1.55;
        color: var(--c-text);
        overflow-x: auto;
        white-space: pre;
        margin: 0;
    }
    .code-block.cURL {
        border-left-color: var(--c-cyan);
    }
    .code-block.response {
        border-left-color: var(--c-success);
    }

    .copy-btn {
        position: absolute;
        top: 0.5rem;
        right: 0.5rem;
        padding: 0.25rem 0.6rem;
        font-family: var(--f-mono);
        font-size: 0.62rem;
        letter-spacing: 0.1em;
        text-transform: uppercase;
        color: var(--c-text-dim);
        background: rgba(0, 0, 0, 0.5);
        border: 1px solid rgba(0, 229, 255, 0.2);
        border-radius: 4px;
        cursor: pointer;
        transition: all 150ms;
        z-index: 2;
    }
    .copy-btn:hover {
        color: var(--c-cyan);
        border-color: var(--c-cyan);
        background: rgba(0, 229, 255, 0.08);
    }
    .copy-btn.copied {
        color: var(--c-success);
        border-color: var(--c-success);
    }

    .endpoint-notes {
        margin-top: 0.75rem;
        padding: 0.75rem 0.9rem;
        background: rgba(212, 175, 55, 0.04);
        border-left: 2px solid var(--c-gold);
        border-radius: var(--r-sm);
        font-size: 0.85rem;
        color: var(--c-text-dim);
        line-height: 1.55;
    }
    .endpoint-notes strong { color: var(--c-gold-bright); }

    /* ── Info panels (auth, errors, security) ─────────────────────── */
    .info-panel {
        padding: 1.5rem;
        background: rgba(0, 229, 255, 0.03);
        border: 1px solid rgba(0, 229, 255, 0.15);
        border-radius: var(--r-md);
        margin-bottom: 1.25rem;
    }
    .info-panel h3 {
        font-family: var(--f-heading);
        font-size: 1.1rem;
        color: var(--c-cyan);
        margin: 0 0 0.75rem;
        letter-spacing: 0.06em;
    }
    .info-panel p, .info-panel li {
        color: var(--c-text-dim);
        font-size: 0.92rem;
        line-height: 1.65;
    }
    .info-panel ul {
        padding-left: 1.25rem;
        margin: 0.5rem 0 0;
    }
    .info-panel li { margin-bottom: 0.35rem; }

    /* ── Error/status tables ──────────────────────────────────────── */
    .api-table {
        width: 100%;
        border-collapse: collapse;
        font-size: 0.88rem;
        margin-top: 0.5rem;
    }
    .api-table th, .api-table td {
        padding: 0.6rem 0.75rem;
        text-align: left;
        border-bottom: 1px solid rgba(0, 229, 255, 0.1);
    }
    .api-table th {
        font-family: var(--f-tech);
        font-size: 0.72rem;
        letter-spacing: 0.12em;
        text-transform: uppercase;
        color: var(--c-gold);
        border-bottom-color: rgba(212, 175, 55, 0.3);
    }
    .api-table td {
        color: var(--c-text);
        font-family: var(--f-mono);
        font-size: 0.82rem;
    }
    .api-table td.desc {
        font-family: var(--f-body);
        font-size: 0.88rem;
        color: var(--c-text-dim);
    }
    .api-table tr:hover td {
        background: rgba(0, 229, 255, 0.02);
    }

    /* ── Footer ───────────────────────────────────────────────────── */
    .api-footer {
        margin-top: 5rem;
        padding-top: 2rem;
        border-top: 1px solid rgba(0, 229, 255, 0.15);
        text-align: center;
        color: var(--c-text-dim);
        font-size: 0.85rem;
    }
    .api-footer a {
        color: var(--c-cyan);
        text-decoration: none;
        border-bottom: 1px dashed rgba(0, 229, 255, 0.35);
    }
    .api-footer a:hover {
        border-bottom-style: solid;
        color: var(--c-cyan-bright);
    }
    .api-footer .rune {
        display: block;
        margin: 1.5rem auto;
        font-family: var(--f-rune);
        font-size: 1.1rem;
        letter-spacing: 0.5em;
        color: var(--c-gold);
        opacity: 0.65;
    }

    /* ── Responsive ───────────────────────────────────────────────── */
    @media (max-width: 640px) {
        .api-hero { padding: 3rem 1rem 2rem; }
        .endpoint-tags { margin-left: 0; }
        .code-block { font-size: 0.75rem; }
    }
</style>
</head>
<body class="api-docs">

<header class="api-hero">
    <div class="version-badge">API v1</div>
    <h1>MyCitadel API</h1>
    <p>
        The zero-knowledge backend powering MyCitadel. Argon2id authentication,
        envelope-encrypted PII, Web Push notifications, and a complete social
        graph — all behind a defense-in-depth API that treats every request
        as untrusted until proven otherwise.
    </p>
</header>

<main class="api-container">

    <!-- ═══════════════════════════════════════════════════════════════
         QUICK FACTS
         ═══════════════════════════════════════════════════════════════ -->
    <section class="api-facts">
        <div class="api-fact">
            <div class="label">Base URL</div>
            <div class="value">https://api.mycitadel.lol/v1</div>
        </div>
        <div class="api-fact">
            <div class="label">Format</div>
            <div class="value">JSON (UTF-8)</div>
        </div>
        <div class="api-fact">
            <div class="label">Endpoints</div>
            <div class="value gold"><?= $totalEndpoints ?></div>
        </div>
        <div class="api-fact">
            <div class="label">Version</div>
            <div class="value">v1</div>
        </div>
    </section>

    <!-- ═══════════════════════════════════════════════════════════════
         AUTHENTICATION
         ═══════════════════════════════════════════════════════════════ -->
    <section class="api-section">
        <div class="api-section-header">
            <h2>Authentication Model</h2>
            <p>Every authenticated request rides on three things: a session cookie, a CSRF token, and the client header.</p>
        </div>

        <div class="info-panel">
            <h3>1. Session Cookie</h3>
            <p>
                After successful login, the server sets an <code>HttpOnly</code> session cookie.
                It is invisible to JavaScript and is automatically included by browsers on every request to the same origin.
                Non-browser clients (Android, iOS, CLI tools) must persist and resend the cookie manually.
            </p>
            <p>
                <strong>Attributes:</strong>
                <code>Secure</code> (HTTPS only),
                <code>SameSite=Strict</code> (no cross-site sends),
                <code>HttpOnly</code> (JS cannot read it).
            </p>
        </div>

        <div class="info-panel">
            <h3>2. CSRF Token</h3>
            <p>
                The API uses the <strong>double-submit cookie</strong> pattern.
                Fetch a token from <code>/v1/auth/csrf.php</code> and send it in the
                <code>X-CSRF-Token</code> header on every unsafe method
                (<code>POST</code>, <code>PUT</code>, <code>PATCH</code>, <code>DELETE</code>).
            </p>
            <p>
                The token rotates automatically after login, logout, register, password change, and 2FA events.
                Always read the latest <code>csrf_token</code> from any response that includes one.
            </p>
        </div>

        <div class="info-panel">
            <h3>3. Client Header</h3>
            <p>
                Every request must include <code>X-Citadel-Client: browser/1.0.0</code> (or <code>android/1.0.0</code>, <code>ios/1.0.0</code>, <code>api/1.0.0</code>).
                This tells the API which class of client is calling, and is required by the request gate.
            </p>
        </div>

        <div class="info-panel">
            <h3>Typical Browser Flow</h3>
            <p>First load of any page, in order:</p>
            <ol>
                <li>Call <code>GET /v1/auth/csrf.php</code> — stores the CSRF cookie.</li>
                <li>Call <code>POST /v1/auth/login.php</code> with credentials + CSRF header — establishes the session.</li>
                <li>Every subsequent unsafe request carries both the session cookie and the current CSRF header.</li>
            </ol>
        </div>
    </section>

    <!-- ═══════════════════════════════════════════════════════════════
         RESPONSE ENVELOPE
         ═══════════════════════════════════════════════════════════════ -->
    <section class="api-section">
        <div class="api-section-header">
            <h2>Response Envelope</h2>
            <p>Every response — success or failure — follows the same shape.</p>
        </div>

        <div class="endpoint-block">
            <span class="label">Success</span>
<pre class="code-block response">
{
  "status": "ok",
  "request_id": "a1b2c3d4e5f6...",
  "ts": "2026-09-27T22:00:00+00:00",
  ... payload
}</pre>
        </div>

        <div class="endpoint-block" style="margin-top:1rem;">
            <span class="label">Error</span>
<pre class="code-block response">
{
  "status": "error",
  "request_id": "a1b2c3d4e5f6...",
  "ts": "2026-09-27T22:00:00+00:00",
  "code": "invalid_credentials",
  "message": "Invalid credentials."
}</pre>
        </div>

        <div class="info-panel" style="margin-top:1.5rem;">
            <h3>Common Error Codes</h3>
            <table class="api-table">
                <thead>
                    <tr><th>Code</th><th>HTTP</th><th class="desc">Meaning</th></tr>
                </thead>
                <tbody>
                    <tr><td>unauthenticated</td><td>401</td><td class="desc">No valid session.</td></tr>
                    <tr><td>invalid_credentials</td><td>401</td><td class="desc">Wrong username/email or password.</td></tr>
                    <tr><td>csrf_invalid</td><td>403</td><td class="desc">Missing or expired CSRF token.</td></tr>
                    <tr><td>origin_required</td><td>403</td><td class="desc">Missing Origin or X-Citadel-Client header.</td></tr>
                    <tr><td>rate_limited</td><td>429</td><td class="desc">Too many requests. See Retry-After header.</td></tr>
                    <tr><td>user_exists</td><td>409</td><td class="desc">Username or email already registered.</td></tr>
                    <tr><td>user_not_found</td><td>404</td><td class="desc">Also returned for blocked or hidden users.</td></tr>
                    <tr><td>invalid_field</td><td>400</td><td class="desc">A submitted field failed validation.</td></tr>
                    <tr><td>internal_error</td><td>500</td><td class="desc">Something broke on our side. Report the request_id.</td></tr>
                </tbody>
            </table>
        </div>

        <div class="info-panel">
            <h3>Request IDs</h3>
            <p>
                Every response carries a <code>request_id</code>. Include it in any bug report — it maps to a
                structured log entry on our side.
            </p>
        </div>
    </section>

    <!-- ═══════════════════════════════════════════════════════════════
         ENDPOINT CATALOG — GENERATED FROM $ENDPOINTS
         ═══════════════════════════════════════════════════════════════ -->
    <?php foreach ($ENDPOINTS as $groupName => $group): ?>
    <section class="api-section">
        <div class="api-section-header">
            <h2><?= e($groupName) ?></h2>
            <p><?= e($group['description']) ?></p>
        </div>

        <?php foreach ($group['endpoints'] as $ep): ?>
        <div class="api-endpoint">
            <div class="endpoint-head">
                <span class="method-badge method-<?= strtolower(e($ep['method'])) ?>">
                    <?= e($ep['method']) ?>
                </span>
                <span class="endpoint-path"><?= e($ep['path']) ?></span>
                <span class="endpoint-tags">
                    <?php if (!empty($ep['auth'])): ?>
                        <span class="tag tag-auth">Auth</span>
                    <?php else: ?>
                        <span class="tag tag-public">Public</span>
                    <?php endif; ?>
                    <?php if (!empty($ep['csrf'])): ?>
                        <span class="tag tag-csrf">CSRF</span>
                    <?php endif; ?>
                </span>
            </div>

            <p class="endpoint-summary"><?= e($ep['summary'] ?? '') ?></p>

            <?php if (!empty($ep['body'])): ?>
            <div class="endpoint-block">
                <span class="label">Request Body</span>
                <pre class="code-block"><?= e($ep['body']) ?></pre>
            </div>
            <?php endif; ?>

            <?php if (!empty($ep['response'])): ?>
            <div class="endpoint-block">
                <span class="label">Success Response</span>
                <pre class="code-block response"><?= e($ep['response']) ?></pre>
            </div>
            <?php endif; ?>

            <?php if (!empty($ep['notes'])): ?>
            <div class="endpoint-notes">
                <?= e($ep['notes']) ?>
            </div>
            <?php endif; ?>
        </div>
        <?php endforeach; ?>
    </section>
    <?php endforeach; ?>

    <!-- ═══════════════════════════════════════════════════════════════
         SECURITY GUARANTEES
         ═══════════════════════════════════════════════════════════════ -->
    <section class="api-section">
        <div class="api-section-header">
            <h2>Security Guarantees</h2>
            <p>What we promise, and what we explicitly do not promise.</p>
        </div>

        <div class="info-panel">
            <h3>What we do</h3>
            <ul>
                <li>Argon2id password hashing (256 MiB memory, 4 iterations, 2 threads) with silent rehash on login.</li>
                <li>Envelope encryption at rest for all PII — email, phone, real name, address, DOB.</li>
                <li>Blind indexes for email and username lookups that never store plaintext.</li>
                <li>Session fingerprint binding (User-Agent + Accept-Language + UA client hints).</li>
                <li>Session rotation on login, logout, and password change.</li>
                <li>CSRF double-submit cookies with automatic rotation.</li>
                <li>Rate limiting per-IP, per-account, and per-endpoint.</li>
                <li>Progressive delay and soft lockout on repeated failed logins.</li>
                <li>Silent 404s for blocked, hidden, or non-visible users — never leaks existence.</li>
                <li>IDOR-proof authorization: every mutation is scoped to the session user.</li>
                <li>Web Push with SSRF allowlist, payload encryption, and dead-subscription pruning.</li>
                <li>Upload hardening: magic-byte MIME detection, re-encode via GD, EXIF stripping, no user-controlled filenames, storage outside webroot.</li>
                <li>Two-factor authentication (TOTP) with per-user secrets, encrypted at rest, single-use recovery codes.</li>
                <li>Structured audit logging with hashed IPs and per-request correlation IDs.</li>
            </ul>
        </div>

        <div class="info-panel">
            <h3>What we explicitly do NOT promise</h3>
            <ul>
                <li>Zero-knowledge in v1. Email is decrypted server-side for verification and password reset. Server holds the master key.</li>
                <li>Immunity to account compromise if the user's email account is compromised.</li>
                <li>Protection against a compromised client device (malware, physical access).</li>
                <li>Protection against lawful requests we are legally compelled to honor.</li>
            </ul>
        </div>
    </section>

    <!-- ═══════════════════════════════════════════════════════════════
         FOOTER
         ═══════════════════════════════════════════════════════════════ -->
    <footer class="api-footer">
        <span class="rune">ᚠ ᚢ ᚦ ᚨ ᚱ ᚲ</span>
        <p>
            MyCitadel — <em>Your digital fortress. Your rules.</em>
        </p>
        <p>
            <a href="https://mycitadel.lol">Website</a> ·
            <a href="https://github.com/BeardedVikingTX/API_MyCitadel">Source</a> ·
            <a href="https://mycitadel.lol/privacy.html">Privacy</a> ·
            <a href="https://mycitadel.lol/terms.html">Terms</a>
        </p>
        <p style="margin-top:1.5rem;color:var(--c-text-faint);font-size:0.75rem;">
            Because your data should be yours alone.
        </p>
    </footer>

</main>

<script>
/* ============================================================================
 * COPY-TO-CLIPBOARD FOR CODE BLOCKS
 * ----------------------------------------------------------------------------
 * Adds a "Copy" button to every pre.code-block on the page. No dependencies.
 * ========================================================================== */
(function () {
    'use strict';

    document.querySelectorAll('pre.code-block').forEach(function (block) {
        var btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'copy-btn';
        btn.textContent = 'Copy';

        btn.addEventListener('click', function () {
            var text = block.textContent || '';
            var done = function () {
                btn.textContent = 'Copied';
                btn.classList.add('copied');
                setTimeout(function () {
                    btn.textContent = 'Copy';
                    btn.classList.remove('copied');
                }, 1400);
            };
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(text).then(done).catch(function () {});
            } else {
                // Fallback for older browsers
                var ta = document.createElement('textarea');
                ta.value = text;
                document.body.appendChild(ta);
                ta.select();
                try { document.execCommand('copy'); done(); } catch (e) {}
                document.body.removeChild(ta);
            }
        });

        block.style.position = 'relative';
        block.appendChild(btn);
    });
})();
</script>

</body>
</html>