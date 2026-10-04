<?php
/**
 * VULNERABLE file upload handler.
 *
 * Deliberately insecure, for lab/demo purposes only:
 *  - No extension allowlist (only a weak client-side hint on the form)
 *  - No content/MIME verification (trusts the client-supplied Content-Type)
 *  - File is stored with its ORIGINAL name, inside a web-accessible folder
 *  - No filename sanitisation (path traversal possible via ../../)
 *  - No file size limit
 *
 * This mirrors real-world CWE-434 (Unrestricted Upload of File with
 * Dangerous Type) findings commonly seen in OWASP Top 10 / A04 reports.
 */

$uploadDir = __DIR__ . '/uploads/';

if (!isset($_FILES['avatar'])) {
    http_response_code(400);
    die('No file uploaded.');
}

$file = $_FILES['avatar'];

if ($file['error'] !== UPLOAD_ERR_OK) {
    http_response_code(400);
    die('Upload error: ' . $file['error']);
}

// VULNERABLE: filename taken straight from the client, no sanitisation,
// no extension check, no content inspection.
$destination = $uploadDir . basename($file['name']);

if (move_uploaded_file($file['tmp_name'], $destination)) {
    echo "Uploaded to: " . htmlspecialchars($destination) . "\n";
    echo "<a href='uploads/" . rawurlencode(basename($file['name'])) . "'>View / execute file</a>";
} else {
    http_response_code(500);
    echo "Upload failed.";
}
