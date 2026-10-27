# AIORI-3-HACKATHON-PROJECTS
This repository will contain the code and resources for the AIORI-3 hackathon that will be developed during the AIORI-3

---

## PS-013 — Incident Timeline and Evidence Collection for Small Teams

A lightweight web tool that turns scattered Linux authentication/security logs into a single, searchable,
chronological incident timeline, and lets analysts collect and export evidence.

**Zero dependencies** — only Node.js (18+) is required. No database, API keys or external services.
Logs are parsed entirely in the browser; nothing is uploaded.

### Run

```bash
npm start        # http://localhost:3000
npm test         # parser / correlation / export unit tests
```

### Demo (2 minutes)

1. Click **Load Demo Data** — loads `src/public/samples/demo-auth.log`, a clearly labelled **simulated** scenario
   (fictional host and RFC 5737 documentation IPs): SSH brute force → compromised `backup` account →
   sudo abuse (`/etc/shadow`) → backdoor user `sysupdate` added to `sudo` → payload download.
2. Dashboard shows total events, critical alerts, failed logins and evidence collected, plus severity breakdown,
   top source IPs and recent high-severity activity.
3. Click the `203.0.113.45` IP (or type in search), filter by severity, set a From/To range, change ordering.
4. Tick events (or **Select visible**) → **Add to Evidence**. Each item records collection time and a SHA-256 of the raw line; add analyst notes and a case name.
5. Export evidence or the filtered timeline as **JSON** or **CSV**.
6. **Import Logs** accepts your own `auth.log`/`secure` files (drag & drop or paste). Malformed lines are skipped and listed under *Skipped Lines*; the demo contains one on purpose.

### Features

- Parses classic syslog (`Oct 27 09:14:04 host sshd[123]: …`) and ISO-8601 headers; normalises all times to UTC.
- Recognises failed/accepted SSH logins, invalid users, scans, sudo/su usage and failures, account and group changes, password changes, PAM sessions.
- Rule-based indicators (`brute-force-pattern`, `login-after-failures`, `sensitive-command`, `privileged-group`, `external-ip`) — labelled as heuristics, not confirmed detections.
- Input validation: 5 MB file limit, line-length and binary-content checks, invalid dates rejected, all log text HTML-escaped, CSV formula-injection protection.
- Evidence persists in browser `localStorage` across reloads.

### Architecture

```
src/
├── server.js                 # zero-dependency static HTTP server (path-traversal safe, CSP headers)
├── public/
│   ├── index.html            # dashboard, timeline, evidence panel, import dialog
│   ├── css/styles.css        # dark responsive theme
│   ├── js/parser.js          # parse → normalise → correlate → summarise → CSV (shared by browser & tests)
│   ├── js/app.js             # UI state, filters, evidence, exports
│   └── samples/demo-auth.log # SIMULATED sample data
└── tests/parser.test.js      # node:test unit tests
```

Syslog timestamps have no year/timezone; they are interpreted as UTC in the year chosen at import (demo: 2026).
