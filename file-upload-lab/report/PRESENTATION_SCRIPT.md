# Video presentation script (target: 6 minutes)

Record with screen capture + mic. Structure follows the assignment's
marking breakdown exactly: a) identification+tools [5] b) demo of
vulnerability [10] c) countermeasures+justification [5] d) demo of
mitigation [10].

**First few seconds — required by the brief:** title card with the
assignment title, student IDs/names, and each member's contribution %.

---

### 0:00–0:30 — Title & scenario (criterion a, part 1)
- Show title card.
- "We investigated unrestricted file upload vulnerabilities —
  CWE-434 / OWASP A04 — using a small PHP upload app we built as our lab
  target, run locally and never exposed to the internet."

### 0:30–1:30 — Identification + tools (criterion a, part 2)
- Open `vulnerable_app/upload.php` on screen, narrate the three flaws:
  no extension check, trusted original filename, file stored inside the
  web-served directory.
- Name the tools: `curl` for scripted multipart uploads, `file`/
  `getimagesize()` inspection to show how a crafted payload is classified,
  and a one-line PHP webshell as payload.

### 1:30–3:30 — Demo of the vulnerability (criterion b)
- Run `demo/run_demo.sh` (or just the Part A section) live.
- Narrate as each attack fires:
  1. Raw `shell.php` upload → request `?cmd=id` → **point at the `uid=0`
     output** — this is the money shot, pause on it.
  2. Double-extension `shell.php.jpg` → same result, explain why a naive
     blocklist fix would still miss this.
  3. GIF/PHP polyglot → show the `file`/`getimagesize()` output first
     (looks like a legitimate GIF!), then show it still executes as PHP
     when requested — "a shallow check can be completely fooled."

### 3:30–4:00 — Countermeasures identified + choice (criterion c)
- Show the table from `report/REPORT.md` section 5 (or narrate it over
  `secure_app/upload.php`).
- State the justification in one sentence: "No single check was enough —
  we showed MIME headers can be spoofed and getimagesize() can be
  tricked — so we layered allowlist → MIME sniff → real image decode →
  **re-encode** → server-chosen random filename, with re-encoding as the
  strongest layer because it defeats smuggling tricks we haven't even
  thought of yet."

### 4:00–5:45 — Demo of mitigation (criterion d)
- Run the same three attacks against `secure_app` (Part B of
  `demo/run_demo.sh`).
- Narrate each rejection message.
- Finish by uploading `legit.jpg` successfully, showing the random
  filename it gets stored as, to prove the fix isn't just "reject
  everything."

### 5:45–6:00 — Close
- One-sentence recap: "Unrestricted upload went from root-level RCE to a
  fully functional, safely validated upload feature using layered,
  justified controls."
- End card.

**Timing note:** run through once un-recorded first; `run_demo.sh`
prints a lot — consider trimming curl output or speaking over a paused
frame rather than waiting on screen for every line, to stay under 7:00.
