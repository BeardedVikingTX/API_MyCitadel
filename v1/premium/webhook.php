<?php
/* ============================================================================
 * ███ PREMIUM/WEBHOOK.PHP ███
 * Route : POST /v1/premium/webhook
 * Auth  : NONE (Stripe is the caller)
 * CSRF  : NONE (Stripe cannot send CSRF tokens)
 * Origin: NONE (Stripe sends no Origin or X-Citadel-Client header)
 *
 * ⚠️  THIS ENDPOINT IS A SECURITY-CRITICAL EXCEPTION TO NORMAL RULES ⚠️
 *
 *   Every other endpoint in this API requires:
 *     • Origin or X-Citadel-Client header
 *     • CSRF token for unsafe methods
 *     • Session cookie for auth
 *
 *   This endpoint requires NONE of those. It replaces them with something
 *   STRONGER: cryptographic signature verification of the request body
 *   using STRIPE_WEBHOOK_SECRET, which only Stripe and this server know.
 *
 *   An attacker who finds this URL CANNOT:
 *     ✗ Forge an event — signature won't match
 *     ✗ Replay an event — event_id is tracked, duplicates ignored
 *     ✗ Tamper with the payload — signature covers the body
 *
 *   An attacker who steals STRIPE_WEBHOOK_SECRET CAN forge events. That is
 *   why the secret must never leave this server.
 *
 * ══════════════════════════════════════════════════════════════════════════
 * EVENTS WE HANDLE
 * ══════════════════════════════════════════════════════════════════════════
 *
 *   checkout.session.completed         → link customer to user, set premium
 *   customer.subscription.created      → activate
 *   customer.subscription.updated      → handle status changes (active/past_due/canceled)
 *   customer.subscription.deleted      → revoke premium
 *   invoice.paid                       → extend premium_expires_at
 *   invoice.payment_failed             → mark for follow-up (do NOT revoke immediately)
 *
 *   All other events are acknowledged (200) but ignored.
 * ========================================================================== */

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';
require_once CITADEL_CONFIG . '/db.php';
require_once CITADEL_CONFIG . '/stripe.php';

// ── Method check ──────────────────────────────────────────────────────────
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    http_response_code(405);
    header('Allow: POST');
    exit;
}

if (!citadel_stripe_enabled()) {
    http_response_code(503);
    exit;
}

// ── Read raw body (Stripe signature covers the RAW bytes, not parsed JSON) ─
$payload   = file_get_contents('php://input');
$signature = $_SERVER['HTTP_STRIPE_SIGNATURE'] ?? '';

if ($payload === false || $payload === '' || $signature === '') {
    http_response_code(400);
    exit;
}

// ── Verify signature ──────────────────────────────────────────────────────
$webhookSecret = citadel_stripe_config('STRIPE_WEBHOOK_SECRET');
if (!$webhookSecret) {
    citadel_log('stripe', 'error', 'Webhook received but STRIPE_WEBHOOK_SECRET not set');
    http_response_code(500);
    exit;
}

try {
    $event = \Stripe\Webhook::constructEvent($payload, $signature, $webhookSecret);
} catch (\UnexpectedValueException $e) {
    // Malformed payload — treat as an attack
    citadel_log('stripe', 'warning', 'Webhook signature failed: malformed payload');
    http_response_code(400);
    exit;
} catch (\Stripe\Exception\SignatureVerificationException $e) {
    // Signature mismatch — attacker or misconfigured secret
    citadel_log('stripe', 'warning', 'Webhook signature failed: verification error', [
        'error' => $e->getMessage(),
    ]);
    http_response_code(400);
    exit;
}

// ── Idempotency ───────────────────────────────────────────────────────────
if (citadel_stripe_event_seen($event->id)) {
    // Already processed — acknowledge silently
    http_response_code(200);
    exit;
}

citadel_log('stripe', 'info', 'Webhook received', [
    'event_id'   => $event->id,
    'event_type' => $event->type,
]);

// ══════════════════════════════════════════════════════════════════════════
// EVENT HANDLERS
// ══════════════════════════════════════════════════════════════════════════

try {
    $data = $event->data->object;

    switch ($event->type) {

        /* ── Checkout completed — first subscription ─────────────────── */
        case 'checkout.session.completed':
            $userId = (int) ($data->client_reference_id ?? 0)
                   ?: (int) ($data->metadata->mycitadel_user_id ?? 0);

            if ($userId > 0 && !empty($data->customer)) {
                // Persist customer ID linkage
                db_query(
                    'UPDATE users SET stripe_customer_id = ?, updated_at = UTC_TIMESTAMP()
                      WHERE id = ? AND (stripe_customer_id IS NULL OR stripe_customer_id = "")',
                    [(string) $data->customer, $userId]
                );

                // If subscription is on the session, sync it
                if (!empty($data->subscription)) {
                    try {
                        $sub = citadel_stripe()->subscriptions->retrieve((string) $data->subscription);
                        citadel_stripe_sync_subscription($userId, $sub);

                        citadel_stripe_log_event(
                            $userId,
                            'activated',
                            $event->id,
                            (string) $sub->id,
                            (string) $data->customer,
                            (int) ($sub->current_period_end ?? 0)
                        );
                    } catch (Throwable $e) {
                        citadel_log('stripe', 'error', 'Failed to sync subscription after checkout', [
                            'user_id' => $userId,
                            'error'   => $e->getMessage(),
                        ]);
                    }
                }
            }
            break;

        /* ── Subscription created or updated ────────────────────────── */
        case 'customer.subscription.created':
        case 'customer.subscription.updated':
            $customerId = (string) ($data->customer ?? '');
            $userId = (int) (db_scalar(
                'SELECT id FROM users WHERE stripe_customer_id = ? LIMIT 1',
                [$customerId]
            ) ?? 0);

            if ($userId > 0) {
                citadel_stripe_sync_subscription($userId, $data);

                $status = $data->status ?? 'unknown';
                $action = match ($status) {
                    'active'    => 'renewed',
                    'trialing'  => 'trialing',
                    'past_due'  => 'past_due',
                    'canceled'  => 'canceled',
                    'unpaid'    => 'unpaid',
                    default     => 'updated',
                };

                citadel_stripe_log_event(
                    $userId,
                    $action,
                    $event->id,
                    (string) ($data->id ?? ''),
                    $customerId,
                    (int) ($data->current_period_end ?? 0)
                );
            }
            break;

        /* ── Subscription deleted (canceled) ────────────────────────── */
        case 'customer.subscription.deleted':
            $customerId = (string) ($data->customer ?? '');
            $userId = (int) (db_scalar(
                'SELECT id FROM users WHERE stripe_customer_id = ? LIMIT 1',
                [$customerId]
            ) ?? 0);

            if ($userId > 0) {
                citadel_stripe_sync_subscription($userId, null);

                citadel_stripe_log_event(
                    $userId,
                    'canceled',
                    $event->id,
                    (string) ($data->id ?? ''),
                    $customerId,
                    (int) ($data->current_period_end ?? 0)
                );
            }
            break;

        /* ── Invoice paid (renewal) ─────────────────────────────────── */
        case 'invoice.paid':
        case 'invoice_payment.paid':
            $customerId = (string) ($data->customer ?? '');
            $userId = (int) (db_scalar(
                'SELECT id FROM users WHERE stripe_customer_id = ? LIMIT 1',
                [$customerId]
            ) ?? 0);

            if ($userId > 0 && !empty($data->subscription)) {
                try {
                    $sub = citadel_stripe()->subscriptions->retrieve((string) $data->subscription);
                    citadel_stripe_sync_subscription($userId, $sub);

                    citadel_stripe_log_event(
                        $userId,
                        'renewed',
                        $event->id,
                        (string) $sub->id,
                        $customerId,
                        (int) ($sub->current_period_end ?? 0),
                        (int) ($data->amount_paid ?? 0)
                    );
                } catch (Throwable $e) {
                    citadel_log('stripe', 'error', 'Invoice-paid sync failed', [
                        'user_id' => $userId,
                        'error'   => $e->getMessage(),
                    ]);
                }
            }
            break;

        /* ── Payment failed — DO NOT revoke immediately ─────────────── */
        /* Stripe retries over ~3 weeks. We let it. Only when Stripe gives  */
        /* up does the subscription transition to deleted/unpaid.          */
        case 'invoice.payment_failed':
            $customerId = (string) ($data->customer ?? '');
            $userId = (int) (db_scalar(
                'SELECT id FROM users WHERE stripe_customer_id = ? LIMIT 1',
                [$customerId]
            ) ?? 0);

            if ($userId > 0) {
                citadel_stripe_log_event(
                    $userId,
                    'payment_failed',
                    $event->id,
                    null,
                    $customerId,
                    null,
                    (int) ($data->amount_due ?? 0)
                );
            }
            break;

        /* ── Anything else — acknowledge, don't act ──────────────────── */
        default:
            citadel_log('stripe', 'info', 'Unhandled webhook event type', [
                'event_type' => $event->type,
            ]);
            break;
    }

    // Mark this event processed (idempotency)
    citadel_stripe_mark_event($event->id, $event->type, [
        'handled' => true,
    ]);

    http_response_code(200);
    echo json_encode(['received' => true]);
    exit;

} catch (Throwable $e) {
    citadel_log('stripe', 'error', 'Webhook handler exception', [
        'event_id' => $event->id,
        'type'     => $event->type,
        'error'    => $e->getMessage(),
    ]);
    // Return 500 so Stripe retries. The event stays unmarked, so retry is safe.
    http_response_code(500);
    exit;
}