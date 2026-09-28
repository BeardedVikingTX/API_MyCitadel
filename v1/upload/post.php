<?php
/* ============================================================================
 * ███ UPLOADS/POST.PHP ███
 * Route : POST /v1/uploads/post
 * Accepts multipart file, stores it, returns an attachment token + URL.
 * The token is then attached to a post at /v1/posts/create.php by sending
 * the array "attachment_tokens".
 *
 * We do NOT require post_id up front — attachments are uploaded first,
 * then bound when the post is created. Unattached uploads are cleaned up
 * by a cron after 1 hour.
 * ========================================================================== */

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';
require_once CITADEL_CONFIG . '/db.php';
require_once CITADEL_CONFIG . '/attachments.php';

citadel_rate_limit('upload_post_media', 60, 3600);
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
    citadel_json_error('upload_error', 'Upload failed. Code: ' . $file['error'], 400);
}

$result = citadel_media_process(
    $file['tmp_name'],
    $me,
    $file['name'] ?? null
);

if (!$result['ok']) {
    $messages = [
        'invalid_upload'   => 'Upload was not recognized.',
        'empty_file'       => 'The file is empty.',
        'too_large'        => 'File exceeds the size limit.',
        'unknown_type'     => 'Could not determine file type.',
        'unsupported_type' => 'This file type is not allowed.',
        'invalid_image'    => 'The image is corrupt or too large.',
        'storage_error'    => 'Could not store the file.',
        'save_failed'      => 'Could not save the file.',
    ];
    citadel_json_error(
        $result['error'],
        $messages[$result['error']] ?? 'Upload failed.',
        400
    );
}

// Record the pending attachment. post_id stays NULL until the post is created.
try {
    db_query(
        'INSERT INTO post_attachments
            (post_id, comment_id, user_id, kind, mime_type, original_name,
             stored_path, file_size, width, height, served_token, created_at)
         VALUES
            (NULL, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, UTC_TIMESTAMP())',
        [
            $me,
            $result['kind'],
            $result['mime'],
            $result['original_name'],
            $result['storage_path'],
            $result['size'],
            $result['width'],
            $result['height'],
            $result['token'],
        ]
    );
} catch (Throwable $e) {
    @unlink($result['storage_path']);
    citadel_log('api', 'error', 'Media attachment insert failed', [
        'user_id' => $me, 'error' => $e->getMessage(),
    ]);
    citadel_json_error('storage_error', 'Could not record the upload.', 500);
}

$attachmentId = db_last_id();
$servedUrl    = CITADEL_SITE_URL . '/i/media/' . $result['token'];

citadel_log('api', 'info', 'Media uploaded', [
    'user_id' => $me,
    'kind'    => $result['kind'],
    'mime'    => $result['mime'],
    'size'    => $result['size'],
]);

citadel_json_ok([
    'attachment_id' => (int) $attachmentId,
    'token'         => $result['token'],
    'url'           => $servedUrl,
    'kind'          => $result['kind'],
    'mime'          => $result['mime'],
    'size'          => $result['size'],
    'width'         => $result['width'],
    'height'        => $result['height'],
    'name'          => $result['original_name'],
], 201);