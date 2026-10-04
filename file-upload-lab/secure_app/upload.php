<?php
/**
 * HARDENED file upload handler — mitigates CWE-434 (Unrestricted Upload
 * of File with Dangerous Type) against the same attack used in
 * ../exploit/exploit.sh and ../vulnerable_app/upload.php.
 *
 * Defence-in-depth layers (every layer is independently load-bearing —
 * defeating one alone is not enough to get code execution):
 *
 *  1. Allowlist of permitted *declared* extensions (reject everything else).
 *  2. Server-side MIME sniffing with fileinfo (ignores the client-supplied
 *     Content-Type header, which is trivially spoofable).
 *  3. Real image validation with getimagesize() — a webshell renamed to
 *     .jpg will fail this because it is not a decodable image.
 *  4. Re-encoding the image through GD. This throws away every byte that
 *     is not part of the actual pixel data, which destroys embedded PHP
 *     payloads used in "polyglot" GIF/JPEG + PHP tricks.
 *  5. A brand-new, randomly generated filename with an extension chosen
 *     by the SERVER from the detected image type — never from user input.
 *     Even if an attacker could smuggle a payload through, they cannot
 *     control the extension it is served under, so it will never be
 *     executed as a script by the web server.
 *  6. Files are stored under uploads/ with a size cap and the directory
 *     is additionally locked down via .htaccess (script execution off)
 *     for defence-in-depth on Apache-class deployments.
 */

const MAX_BYTES = 2 * 1024 * 1024; // 2 MB

const ALLOWED_TYPES = [
    IMAGETYPE_JPEG => ['ext' => 'jpg', 'mime' => 'image/jpeg'],
    IMAGETYPE_PNG  => ['ext' => 'png', 'mime' => 'image/png'],
    IMAGETYPE_GIF  => ['ext' => 'gif', 'mime' => 'image/gif'],
];

function reject(string $reason): void {
    http_response_code(400);
    die("Upload rejected: {$reason}\n");
}

$uploadDir = __DIR__ . '/uploads/';

if (!isset($_FILES['avatar'])) {
    reject('no file received');
}

$file = $_FILES['avatar'];

if ($file['error'] !== UPLOAD_ERR_OK) {
    reject('transport error ' . $file['error']);
}

// Layer: size limit (defends against trivial DoS via disk exhaustion).
if ($file['size'] > MAX_BYTES || $file['size'] === 0) {
    reject('file too large or empty');
}

// Layer: declared-extension allowlist (cheap first filter, NOT trusted alone).
$declaredExt = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
$allowedExts = array_column(ALLOWED_TYPES, 'ext');
if (!in_array($declaredExt, $allowedExts, true)) {
    reject("extension '.$declaredExt' is not permitted");
}

// Layer: server-side MIME sniffing via libmagic — ignores the
// attacker-controlled Content-Type header entirely.
$finfo = finfo_open(FILEINFO_MIME_TYPE);
$sniffedMime = finfo_file($finfo, $file['tmp_name']);
finfo_close($finfo);

$allowedMimes = array_column(ALLOWED_TYPES, 'mime');
if (!in_array($sniffedMime, $allowedMimes, true)) {
    reject("detected content type '{$sniffedMime}' is not an allowed image type");
}

// Layer: structural validation — must actually decode as an image.
// A PHP webshell renamed shell.php.jpg or a GIF89a-prefixed polyglot
// shell will fail getimagesize() or fail to decode below.
$imageInfo = @getimagesize($file['tmp_name']);
if ($imageInfo === false || !array_key_exists($imageInfo[2], ALLOWED_TYPES)) {
    reject('file is not a valid, decodable image');
}

$detectedType = ALLOWED_TYPES[$imageInfo[2]];

// Layer: re-encode through GD. This rebuilds the file from decoded pixel
// data only, which drops any trailing/embedded payload bytes a polyglot
// attack relies on (e.g. PHP appended after a valid GIF trailer).
switch ($imageInfo[2]) {
    case IMAGETYPE_JPEG:
        $image = @imagecreatefromjpeg($file['tmp_name']);
        break;
    case IMAGETYPE_PNG:
        $image = @imagecreatefrompng($file['tmp_name']);
        break;
    case IMAGETYPE_GIF:
        $image = @imagecreatefromgif($file['tmp_name']);
        break;
    default:
        $image = false;
}

if ($image === false) {
    reject('image failed to decode during re-encoding pass');
}

// Layer: server-generated random filename + server-chosen extension.
// The attacker never controls either value, so even a successful bypass
// of every check above cannot result in a .php file being written.
$randomName = bin2hex(random_bytes(16)) . '.' . $detectedType['ext'];
$destination = $uploadDir . $randomName;

$ok = match ($imageInfo[2]) {
    IMAGETYPE_JPEG => imagejpeg($image, $destination, 90),
    IMAGETYPE_PNG  => imagepng($image, $destination),
    IMAGETYPE_GIF  => imagegif($image, $destination),
    default => false,
};
imagedestroy($image);

if (!$ok) {
    reject('failed to write sanitised image');
}

chmod($destination, 0644);

echo "Upload accepted.\n";
echo "Stored as: " . htmlspecialchars($randomName) . "\n";
echo "<a href='uploads/" . rawurlencode($randomName) . "'>View file</a>";
