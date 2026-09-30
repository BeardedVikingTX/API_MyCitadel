<?php
/* ============================================================================
 * ███ PREMIUM/PORTAL.PHP ███
 * Route : POST /v1/premium/portal
 * Auth  : Required
 * CSRF  : Required
 *
 * Redirects the user to the Stripe Customer Portal where they can:
 *   • Update payment method
 *   • Cancel subscription
 *   • Download invoices
 *   • Reactivate a canceled subscription
 *
 * We do NOT build these screens ourselves. Stripe hosts them. This is
 * PCI-compliant, audit-proof, and saves us weeks of work.
 *
 * SECURITY:
 *   The customer ID is looked up server-side from the session user. A
 *   client cannot request the portal for another user's customer.
 * ========================================================================== */

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';
require_once CITADEL_CONFIG . '/db.php';
require_once CITADEL_CONFIG . '/stripe.php';

citadel_rate_limit('premium_portal', 20, 3600);
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

$customerId = (string) (db_scalar(
    'SELECT stripe_customer_id FROM users WHERE id = ? LIMIT 1',
    [$me]
) ?? '');

if ($customerId === '') {
    citadel_json_error('no_customer',
        'You have no subscription to manage.', 404);
}

try {
    $portalUrl = citadel_stripe_config('STRIPE_CUSTOMER_PORTAL_URL');

    $session = citadel_stripe()->billingPortal->sessions->create([
        'customer'   => $customerId,
        'return_url' => rtrim(getenv('APP_URL') ?: 'https://mycitadel.lol', '/') . '/users/dashboard.php',
    ]);

    citadel_log('stripe', 'info', 'Customer portal opened', ['user_id' => $me]);

    citadel_json_ok([
        'portal_url' => $session->url,
    ]);

} catch (\Stripe\Exception\ApiErrorException $e) {
    citadel_log('stripe', 'error', 'Portal session creation failed', [
        'user_id' => $me,
        'error'   => $e->getMessage(),
    ]);
    citadel_json_error('portal_failed',
        'Could not open the billing portal. Please try again.', 500);
}