<?php
/* ============================================================================
 * ███ UPLOAD/BANNER.PHP ███
 * Route  : POST /v1/upload/banner
 * Target : 1500×500 JPEG
 * ========================================================================== */

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';
require_once CITADEL_CONFIG . '/db.php';
require_once CITADEL_CONFIG . '/upload.php';

citadel_rate_limit('upload_banner', 20, 3600);
citadel_require_csrf();
citadel_require_auth('json');

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    header('Allow: POST');
    citadel_json_error('method_not_allowed', 'POST only.', 405);
}

$me = (int) citadel_current_user_id();

if (empty($_FILES['file']) || !isset($_FILES['file']['tmp_name'])) {
    citadel_json_error('missing_file', 'No file uploaded.', 400);
}

$file = $_FILES['file'];

if ($file['error'] !== UPLOAD_ERR_OK) {
    citadel_json_error('upload_error', 'Upload failed.', 400);
}

$oldUrl = db_scalar(
    'SELECT banner_url FROM user_profiles WHERE user_id = ? LIMIT 1',
    [$me]
);

$result = citadel_upload_process($file['tmp_name'], 'banner', $me);

if (!$result['ok']) {
    citadel_log('api', 'warning', 'Banner upload rejected', [
        'user_id' => $me, 'reason' => $result['error'],
    ]);
    citadel_json_error($result['error'], 'Banner upload failed.', 400);
}

try {
    db_query(
        'UPDATE user_profiles SET banner_url = ?, updated_at = UTC_TIMESTAMP() WHERE user_id = ?',
        [$result['url'], $me]
    );
} catch (Throwable $e) {
    @unlink($result['path']);
    citadel_log('api', 'error', 'Banner profile update failed', [
        'user_id' => $me, 'error' => $e->getMessage(),
    ]);
    citadel_json_error('update_failed', 'Could not save banner.', 500);
}

if (is_string($oldUrl) && $oldUrl !== '') {
    citadel_upload_delete_by_url($oldUrl);
}

citadel_log('api', 'info', 'Banner uploaded', [
    'user_id' => $me, 'filename' => $result['filename'],
]);

citadel_json_ok([
    'url'     => $result['url'],
    'message' => 'Banner updated.',
]);