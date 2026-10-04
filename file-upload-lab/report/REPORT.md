# Investigation of File Upload Vulnerabilities in Web Applications and Their Mitigation

DGT3098Y: Applied Cybersecurity — University of Mauritius
Assignment [30 Marks] — video presentation support report

> Fill in before submission: group member IDs, names, and individual
> contribution percentages (required by the assignment brief — without
> this everyone in the group gets the same mark).

| ID | Name | Contribution % |
|----|------|-----------------|
|    |      |                 |

---

## 1. Scenario

**Vulnerability class investigated:** Unrestricted File Upload
(CWE-434 — "Unrestricted Upload of File with Dangerous Type"), mapped to
OWASP Top 10 2021 **A04:2021 – Insecure Design** and commonly discussed
under A03/A05 depending on the exact flaw (validation vs. misconfiguration).

A file-upload feature is vulnerable when a server accepts a file from a
user and stores or serves it in a way that lets the attacker control
**content**, **name/extension**, or **location** without the server
independently verifying what was actually uploaded. The impact ranges
from stored XSS, to remote code execution (RCE) when the stored file can
be requested back and executed by the web server — which is what this
lab demonstrates.

## 2. Lab environment

- `vulnerable_app/` — a minimal PHP "profile picture upload" app with
  **no** extension allowlist, **no** content validation, and files stored
  with their original name inside a web-served directory.
- `secure_app/` — the same feature, rebuilt with layered mitigations
  (Section 4).
- `exploit/` — attack payloads and `curl`-based scripts.
- `demo/run_demo.sh` — boots both apps (PHP built-in server) and runs the
  identical attack sequence against each, for the video.

Both apps run with `php -S 127.0.0.1:<port> -t <app_dir>` — no external
dependencies beyond PHP's GD and fileinfo extensions (bundled).

## 3. Identification of the vulnerability + tools used (criterion a)

**Tools:** `curl` (as an HTTP client to script multipart/form-data
uploads precisely, including forging the `Content-Type` field and
filename independently of the actual file bytes), `file`/`php -r
'var_dump(getimagesize(...))'` to inspect how a crafted payload is
classified, and a hand-written PHP one-liner webshell as the payload.

Static review of `vulnerable_app/upload.php` shows three independent
root causes:

1. `$_FILES['avatar']['name']` is trusted directly — `basename()` is the
   only sanitisation, so no extension check and no content check exist.
2. The destination directory (`uploads/`) is inside the web root and PHP
   files placed there are executed by the PHP built-in server (and would
   be by Apache/`mod_php` or Nginx+PHP-FPM with a typical config) exactly
   like any other `.php` file in the app.
3. No file-size limit and no re-encoding — whatever bytes the client
   sends are written verbatim.

## 4. Demo of the vulnerability (criterion b)

`exploit/exploit.sh <base_url>` runs four attacks against
`vulnerable_app`:

1. **Direct webshell upload** (`shell.php`) → uploaded as-is, then
   requested at `/uploads/shell.php?cmd=id` → **arbitrary OS command
   execution** as the web server user.
2. **Double extension** (`shell.php.jpg`) → this build has *no* extension
   check at all, so the file is saved verbatim as `shell.php.jpg`. It is
   included to show what a *naive* fix (e.g. a blocklist that only
   rejects filenames ending in `.php`) would still miss: the PHP
   built-in server (and Apache's classic `AddHandler` config in many
   real deployments) can still match `.php` anywhere in a multi-dot
   filename and execute it, so a blocklist checking only the final
   segment is an incomplete fix even once someone attempts one.
3. **GIF/PHP polyglot** (`polyglot.gif.php`) — valid GIF header bytes
   (`GIF89a;`) followed by raw PHP. `getimagesize()` alone reports it as
   a legitimate `image/gif` (demonstrated in `php -r` testing — this is
   the key lesson: **"looks like an image to a shallow check" ≠ "is safe
   to store and serve"**). Because the extension on disk is still
   `.php`, requesting it executes the appended PHP code.
4. **Path traversal via filename** (`../escaped-webshell.php`) — included
   for completeness; in this particular build it is blocked incidentally
   because `move_uploaded_file()`'s destination still uses the
   caller-constructed path (`basename()` wasn't applied to the
   destination in an older variant) — the script documents and verifies
   the actual outcome rather than assuming it always works, since this
   is implementation-dependent.

Observed result (see `demo/run_demo.sh` output): webshells #1–#3 all
achieve command execution, confirmed with `id`, `uname -a`, and reading
back the shell source.

## 5. Possible countermeasures identified + justification of the chosen set (criterion c)

| # | Countermeasure | Stops which attack(s) | Why it's necessary on its own merits |
|---|---|---|---|
| 1 | Extension **allowlist** (not blocklist) | #1, #3 | Blocklists are always incomplete (`.phtml`, `.phar`, `.pht`, case variants, trailing dots/spaces on some OSes). An allowlist of `jpg/png/gif` has a closed, auditable set. |
| 2 | Server-side MIME sniffing (`finfo`, ignoring the client `Content-Type` header) | #2-style spoofing | The `Content-Type` multipart field is attacker-controlled and proves nothing; `finfo` inspects actual bytes. |
| 3 | Real image decode (`getimagesize()` **and** an actual `imagecreatefrom*()` call) | #3 (polyglot) | `getimagesize()` alone only parses the header — shown in this lab to accept a polyglot. A full GD decode requires a structurally valid image. |
| 4 | **Re-encode** the image through GD before saving | #3 and any future polyglot trick | Re-encoding writes out only decoded pixel data; any trailing/embedded non-image bytes (the PHP payload) are discarded regardless of how they were smuggled in. This is the single strongest control because it doesn't depend on recognising a specific trick. |
| 5 | Server-generated random filename **and** server-chosen extension (never taken from user input) | #1, #2, #3, and any filename-based trick | Even a theoretical bypass of 1–4 cannot result in a `.php` file on disk, because the extension is derived from the detected image type, not from the client. |
| 6 | Storage directory hardening (`.htaccess`: `php_flag engine off`, deny script extensions) | defence-in-depth | Belt-and-braces for Apache/mod_php-class deployments: even a misconfiguration upstream of layers 1–5 would still not result in script execution from that directory. |
| 7 | File size cap | resource-exhaustion / DoS | Not an RCE control, but a standard companion mitigation for upload endpoints. |

**Why this combination, not a subset:** layers 1–3 are all independently
bypassable (shown live for #2 and #3 in this lab); layer 4 is the only
control that defeats an *unknown* smuggling technique rather than a
specific one, which is why it — not the allowlist — is treated as the
primary mitigation, with 1/2/3/6 kept as defence-in-depth rather than the
sole defence (principle of layered security / fail-safe defaults).

## 6. Demo of countermeasures (criterion d)

`exploit/exploit_against_secure.sh <base_url>` fires the *identical*
payloads at `secure_app`. Observed results:

1. `shell.php` → rejected at the extension-allowlist layer.
2. `shell.php.jpg` → passes the extension check, rejected at the MIME
   sniffing layer (`finfo` correctly reports `text/x-php`).
3. `polyglot.gif.php` → rejected at the extension-allowlist layer in this
   run (filename ends in `.php`); when tested with an allowlisted
   extension the payload is instead caught by the GD re-encode layer
   (verified separately: `imagecreatefromgif()` returns `false` on this
   file, since it has a valid header but no real GIF image data).
4. A genuine JPEG (`legit.jpg`) → **accepted**, stored under a random
   64-bit-random hex filename with a server-chosen `.jpg` extension —
   proving the mitigations don't just reject everything, they correctly
   distinguish legitimate use from attack.

## 7. Conclusion

Unrestricted file upload is a high-impact vulnerability class precisely
because a single missing check (extension, content-type, or structural
validation) is enough for RCE, as demonstrated with a one-line PHP
webshell achieving `uid=0` in this sandbox. No single check is sufficient
in isolation — each was shown to be bypassable alone — but the layered
approach (allowlist → MIME sniff → structural decode → re-encode →
server-controlled naming → storage hardening) closes every demonstrated
bypass while still accepting legitimate uploads.

## 8. Ethics / scope note

All testing in this report was performed exclusively against a local,
disposable lab application written for this assignment and run only on
`127.0.0.1` inside this sandbox. No third-party system was targeted. The
webshell payload is clearly commented as lab-only and is not intended for
reuse outside this controlled environment.
