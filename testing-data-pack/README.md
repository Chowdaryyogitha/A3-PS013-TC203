# PS-013 Testing Data Pack (SYNTHETIC)

Sample data for demonstrating and testing the **PS-013 Incident Timeline & Evidence Collection** web app.

> **All data is synthetic.** Hosts (`lab-web01`, `lab-bastion01`) are fictional, and every IP address comes from the
> RFC 5737 documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`). Nothing here is a real security event.
> Because these ranges are not private networks, the app tags them `external-ip`.

## Scenario (2026-10-28, UTC)

| Time (UTC) | What happens | File |
|---|---|---|
| 08:01–08:30 | Normal admin login (`deploy`) | auth.log |
| 13:55 | Port scan from 198.51.100.77, blocked by UFW and SSH probe | syslog.log, auth.log |
| 13:58–14:01 | Web probing from 203.0.113.45: `.env`, `.git`, path traversal, SQLi, login spraying | sample-access.log |
| 14:05–14:08 | SSH brute force from 203.0.113.45 | auth.log |
| 14:09:15 | **Successful login as `webadmin` after failures** | auth.log |
| 14:10–14:14 | sudo misuse: `/etc/shadow`, backdoor user `svc-backup` added to `sudo`, payload download, crontab | suspicious-activity.log, syslog.log (audit) |
| 14:16 | fail2ban bans the IP too late (logged as `+05:30` to test time-zone normalisation) | syslog.log |
| 14:20 | Attacker returns as `svc-backup` and clears shell history | suspicious-activity.log |

Separate files: `failed-logins.log` covers a password-spraying run on `lab-bastion01`, and `normal-activity.log` is a quiet baseline day (2026-10-27).

## Importing into the app

1. Run `npm start` in the project and open http://localhost:3000.
2. Click **Import Logs** and leave **Year for syslog timestamps** set to **2026**.
3. Drop in one `.log` file, or several at once.
4. To build the full incident, import `auth.log`, `suspicious-activity.log`, `syslog.log` and `sample-access.log` together.
   You can also import them one at a time with **Append to current timeline** ticked.
5. Compare the dashboard against `expected-test-results.json`. The full-incident scenario should show **75 events, 10 critical, 13 high, 12 failed logins**.

### Suggested test cases

| Test | File(s) | Expected |
|---|---|---|
| Brute-force correlation | failed-logins.log | 34 events, 33 failed logins, 29 high, `brute-force-pattern` on 203.0.113.80 |
| Login after failures | auth.log | `webadmin` login at 14:09:15 is **critical** (`login-after-failures`) |
| Privilege escalation | suspicious-activity.log | 8 critical (sensitive sudo, privileged group) |
| Baseline / false positives | normal-activity.log | 21 events, 0 critical, 0 high, 0 failed logins |
| Error handling | malformed-sample.log | 2 events loaded, 10 lines listed under **Skipped Lines** |
| Mixed timestamp formats | syslog.log | RFC 3339 lines, and the `+05:30` line shows as 14:16:12 UTC |
| Search / filters | full incident | search `203.0.113.45`, filter Critical, date range 14:00–14:15 |
| Evidence export | full incident | add critical events to evidence, then export JSON/CSV |

## File formats

- **`.log` files** can be imported. They use classic syslog lines (`Oct 28 14:05:03 host sshd[123]: …`), or RFC 3339 lines in `syslog.log`.
  `sample-access.log` uses nginx access lines forwarded through syslog, so the app accepts them. Web, firewall and audit lines
  load as **Other / info** events you can search, because the current parser only applies its detection rules to SSH, sudo, su and account events.
- **`sample-security-events.json`** and **`incident-events.csv`** are reference outputs. They hold the normalised full-incident timeline in the
  same schema as the app's Timeline export, for comparing exports or feeding other tools. The app does not import them.
- **`expected-test-results.json`** lists the counts the project's own parser produces for each file and each scenario.
- **`manifest.json`** lists every file with its format, purpose, size and SHA-256.
