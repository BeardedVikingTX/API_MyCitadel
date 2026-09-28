<?php
/* ============================================================================
 * ███ PREMIUM/CHECKOUT.PHP ███
 * Route : POST /v1/premium/checkout
 * Auth  : Required
 * CSRF  : Required
 * Rate  : 10 per hour per user
 *
 * Creates a Stripe Checkout session for the premium subscription and
 * returns the URL the browser should be redirected to.
 *
 * THE FLOW:
 *   1. User clicks "Upgrade to Premium" on the frontend
 *   2. Frontend calls this endpoint
 *   3. We create (or reuse) a Stripe customer for the user
 *   4. We create a subscription-mode checkout session
 *   5. We return the checkout URL
 *   6. Frontend does window.location = url
 *   7. User pays on Stripe's hosted page
 *   8. Stripe redirects to /premium/success?session_id=cs_...
 *   9. In parallel, Stripe fires checkout.session.completed to our webhook
 *  10. Our webhook sets is_premium = 1 on the user
 *
 * SECURITY:
 *   • Session user_id comes from the session cookie, never from the request.
 *   • We never send our own card form — always Stripe hosted checkout.
 *   • Customer ID is stored server-side, never exposed to the client.
 *   • Session ID is embedded in the redirect URL — the success page
 *     re-verifies it with Stripe before trusting anything.
 * ========================================================================== */

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';
require_once CITADEL_CONFIG . '/db.php';
require_once CITADEL_CONFIG . '/stripe.php';

citadel_rate_limit('premium_checkout', 10, 3600);
citadel_require_csrf();
citadel_require_auth('json');

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    header('Allow: POST');
    citadel_json_error('method_not_allowed', 'POST only.', 405);
}

if (!citadel_stripe_enabled()) {
    citadel_json_error('premium_disabled',
        'Premium subscriptions are not currently available.', 503);
}

$me = (int) citadel_current_user_id();

// Refuse if already premium
$current = db_scalar('SELECT is_premium FROM users WHERE id = ? LIMIT 1', [$me]);
if ((int) $current === 1) {
    citadel_json_error('already_premium',
        'You already have an active premium subscription.', 409);
}

try {
    $customerId = citadel_stripe_ensure_customer($me);

    $priceId  = citadel_stripe_config('STRIPE_PREMIUM_PRICE_ID');
    $successUrl = citadel_stripe_config('STRIPE_SUCCESS_URL');
    $cancelUrl  = citadel_stripe_config('STRIPE_CANCEL_URL');

    if (!$priceId || !$successUrl || !$cancelUrl) {
        citadel_json_error('misconfigured',
            'Premium checkout is temporarily unavailable.', 503);
    }

    $session = citadel_stripe()->checkout->sessions->create([
        'mode'                 => 'subscription',
        'customer'             => $customerId,
        'line_items'           => [[
            'price'    => $priceId,
            'quantity' => 1,
        ]],
        'success_url'          => $successUrl . '?session_id={CHECKOUT_SESSION_ID}',
        'cancel_url'           => $cancelUrl,
        'allow_promotion_codes'=> true,
        'billing_address_collection' => 'auto',
        'client_reference_id'  => (string) $me,
        'subscription_data'    => [
            'metadata' => [
                'mycitadel_user_id' => (string) $me,
            ],
        ],
        'metadata'             => [
            'mycitadel_user_id' => (string) $me,
        ],
    ]);

    citadel_log('stripe', 'info', 'Checkout session created', [
        'user_id'    => $me,
        'session_id' => substr($session->id, 0, 12) . '…',
    ]);

    citadel_json_ok([
        'checkout_url' => $session->url,
        'session_id'   => $session->id,
    ]);

} catch (\Stripe\Exception\ApiErrorException $e) {
    citadel_log('stripe', 'error', 'Checkout session creation failed', [
        'user_id' => $me,
        'error'   => $e->getMessage(),
    ]);
    citadel_json_error('checkout_failed',
        'Could not start checkout. Please try again.', 500);
}