# File Upload Vulnerabilities — Lab (DGT3098Y Assignment)

Supporting lab/code for: **"Investigation of File Upload Vulnerabilities
in Web Applications and Their Mitigation."**

Everything here runs locally (`127.0.0.1`) with no external services
contacted. Requires PHP with the `gd` and `fileinfo` extensions (both
bundled in standard PHP builds) and `curl`.

## Layout

```
vulnerable_app/   intentionally insecure upload endpoint (the "before")
secure_app/       hardened upload endpoint (the "after")
exploit/          attack payloads + curl-based exploit scripts
demo/run_demo.sh  one command: boots both apps, runs every attack twice
report/           written report (REPORT.md) + video script
```

## Quick start

```bash
# Runs everything: starts both servers, fires all attacks at the
# vulnerable app, then the identical attacks at the hardened app.
bash demo/run_demo.sh
```

Or drive it manually:

```bash
php -S 127.0.0.1:8001 -t vulnerable_app &
bash exploit/exploit.sh http://127.0.0.1:8001

php -S 127.0.0.1:8002 -t secure_app &
bash exploit/exploit_against_secure.sh http://127.0.0.1:8002
```

See `report/REPORT.md` for the write-up mapped to the four marking
criteria, and `report/PRESENTATION_SCRIPT.md` for a timed video script.

## Safety note

The webshell in `exploit/webshell.php` is for this local lab only. Don't
deploy it or point these scripts at anything other than
`vulnerable_app`/`secure_app` running on localhost.
