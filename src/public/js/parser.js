/*
 * Log parser + normaliser for Linux authentication/security logs (auth.log / secure).
 * Works in the browser (window.LogParser) and in Node (module.exports) so it can be unit tested.
 *
 * Supports two header formats:
 *   Classic syslog:  "Oct 27 09:14:02 host sshd[1234]: message"   (no year/zone -> assumed year, UTC)
 *   RFC 3339 / ISO:  "2026-10-27T09:14:02.123+00:00 host sshd[1234]: message"
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.LogParser = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
  const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  const MONTHS = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };
  const MAX_LINE_LENGTH = 4096;

  const SYSLOG_RE = /^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\S+)\s+([^\s:[]+)(?:\[(\d+)\])?:\s*(.*)$/;
  const ISO_RE = /^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?)(Z|[+-]\d{2}:?\d{2})?\s+(\S+)\s+([^\s:[]+)(?:\[(\d+)\])?:\s*(.*)$/;

  const SENSITIVE_CMD_RE = /(\/etc\/shadow|\/etc\/sudoers|\/etc\/passwd|useradd|usermod|adduser|passwd\b|chmod\s+[ugoa]*\+s|chmod\s+[0-7]?[4-7][0-7]{3}|\bnc\b|ncat|netcat|wget\s|curl\s|\/tmp\/|base64|bash\s+-i|\/dev\/tcp|python[0-9.]*\s+-c|crontab|iptables\s+-F|history\s+-c)/i;
  const PRIV_GROUP_RE = /^(sudo|wheel|admin|root|adm)$/;

  // Each rule: process filter (optional), regex on the message, and a builder returning event fields.
  const RULES = [
    { re: /^Failed (password|publickey) for (invalid user )?(\S+) from (\S+) port (\d+)/, build: (m) => ({
      type: 'failed_login', severity: 'medium', user: m[3], ip: m[4], port: +m[5],
      description: `Failed ${m[1]} authentication for ${m[2] ? 'invalid user ' : 'user '}${m[3]}` }) },
    { re: /^error: maximum authentication attempts exceeded for (invalid user )?(\S+) from (\S+) port (\d+)/, build: (m) => ({
      type: 'failed_login', severity: 'high', user: m[2], ip: m[3], port: +m[4],
      description: `Maximum authentication attempts exceeded for ${m[1] ? 'invalid user ' : 'user '}${m[2]}` }) },
    { re: /^Invalid user (\S*) from (\S+)(?: port (\d+))?/, build: (m) => ({
      type: 'invalid_user', severity: 'medium', user: m[1] || null, ip: m[2], port: m[3] ? +m[3] : null,
      description: `Login attempt with non-existent username "${m[1]}"` }) },
    { re: /^Accepted (\S+) for (\S+) from (\S+) port (\d+)/, build: (m) => ({
      type: 'successful_login', severity: 'low', user: m[2], ip: m[3], port: +m[4],
      description: `Successful login for ${m[2]} via ${m[1]}` }) },
    { re: /^Did not receive identification string from (\S+)(?: port (\d+))?/, build: (m) => ({
      type: 'recon', severity: 'medium', ip: m[1], port: m[2] ? +m[2] : null,
      description: 'Connection opened without SSH handshake (possible port scan)' }) },
    { re: /^(?:Disconnected from|Connection closed by) (?:(?:authenticating|invalid) )?(?:user (\S+) )?(\S+) port (\d+)/, build: (m) => ({
      type: 'disconnect', severity: 'info', user: m[1] || null, ip: m[2], port: +m[3],
      description: `Connection closed${m[1] ? ' for ' + m[1] : ''}` }) },
    { re: /^Received disconnect from (\S+) port (\d+)/, build: (m) => ({
      type: 'disconnect', severity: 'info', ip: m[1], port: +m[2], description: 'Client disconnected' }) },
    { re: /^pam_unix\(([^:]+):session\): session opened for user (\S+?)(?:\(uid=\d+\))?(?: by (\S+?)(?:\(uid=\d+\))?)?\s*$/, build: (m) => ({
      type: 'session_opened', severity: m[1] === 'su' || m[1].startsWith('sudo') ? 'low' : 'info', user: m[2],
      description: `${m[1]} session opened for ${m[2]}${m[3] ? ' by ' + m[3] : ''}` }) },
    { re: /^pam_unix\(([^:]+):session\): session closed for user (\S+)/, build: (m) => ({
      type: 'session_closed', severity: 'info', user: m[2], description: `${m[1]} session closed for ${m[2]}` }) },
    { re: /^pam_unix\(([^:]+):auth\): authentication failure;(.*)$/, build: (m) => {
      const rhost = /rhost=(\S+)/.exec(m[2]); const user = /\suser=(\S+)/.exec(m[2]);
      return { type: 'auth_failure', severity: 'low', ip: rhost ? rhost[1] : null, user: user ? user[1] : null,
        description: `PAM authentication failure (${m[1]})` }; } },
    { proc: 'sudo', re: /^\s*(\S+) : (\d+) incorrect password attempts? ;.*?USER=(\S+) ; COMMAND=(.*)$/, build: (m) => ({
      type: 'sudo_failure', severity: 'high', user: m[1], targetUser: m[3], command: m[4].trim(),
      description: `${m[2]} incorrect sudo password attempt(s) by ${m[1]}` }) },
    { proc: 'sudo', re: /^\s*(\S+) : user NOT in sudoers ;.*?COMMAND=(.*)$/, build: (m) => ({
      type: 'sudo_failure', severity: 'high', user: m[1], command: m[2].trim(),
      description: `${m[1]} attempted sudo but is NOT in sudoers` }) },
    { proc: 'sudo', re: /^\s*(\S+) : TTY=\S+ ; PWD=\S+ ; USER=(\S+) ; COMMAND=(.*)$/, build: (m) => {
      const cmd = m[3].trim(); const sensitive = SENSITIVE_CMD_RE.test(cmd);
      return { type: 'privilege_escalation', severity: sensitive ? 'critical' : 'medium', user: m[1], targetUser: m[2], command: cmd,
        description: `sudo as ${m[2]} by ${m[1]}: ${cmd}`, tags: sensitive ? ['sensitive-command'] : [] }; } },
    { proc: 'su', re: /^FAILED SU \(to (\S+)\) (\S+) on (\S+)/, build: (m) => ({
      type: 'su_failure', severity: 'high', user: m[2], targetUser: m[1], description: `Failed su to ${m[1]} by ${m[2]} on ${m[3]}` }) },
    { proc: 'su', re: /^(?:Successful su for (\S+) by (\S+)|\(to (\S+)\) (\S+) on (\S+))/, build: (m) => {
      const target = m[1] || m[3]; const by = m[2] || m[4];
      return { type: 'privilege_escalation', severity: target === 'root' ? 'high' : 'medium', user: by, targetUser: target,
        description: `su to ${target} by ${by}` }; } },
    { re: /^new user: name=([^,]+),\s*UID=(\d+)/, build: (m) => ({
      type: 'account_created', severity: 'high', user: m[1], description: `New user account created: ${m[1]} (UID ${m[2]})` }) },
    { re: /^new group: name=([^,]+)/, build: (m) => ({
      type: 'account_change', severity: 'medium', description: `New group created: ${m[1]}` }) },
    { re: /^add '([^']+)' to (?:shadow )?group '([^']+)'/, build: (m) => {
      const priv = PRIV_GROUP_RE.test(m[2]);
      return { type: 'account_change', severity: priv ? 'critical' : 'medium', user: m[1],
        description: `User ${m[1]} added to group '${m[2]}'${priv ? ' (privileged group)' : ''}`, tags: priv ? ['privileged-group'] : [] }; } },
    { re: /^delete user '([^']+)'/, build: (m) => ({
      type: 'account_change', severity: 'high', user: m[1], description: `User account deleted: ${m[1]}` }) },
    { re: /^pam_unix\(passwd:chauthtok\): password changed for (\S+)/, build: (m) => ({
      type: 'credential_change', severity: 'medium', user: m[1], description: `Password changed for ${m[1]}` }) },
  ];

  const TYPE_LABELS = {
    failed_login: 'Failed login', invalid_user: 'Invalid user', successful_login: 'Successful login', recon: 'Reconnaissance',
    disconnect: 'Disconnect', session_opened: 'Session opened', session_closed: 'Session closed', auth_failure: 'Auth failure',
    sudo_failure: 'Sudo failure', privilege_escalation: 'Privilege escalation', su_failure: 'su failure',
    account_created: 'Account created', account_change: 'Account change', credential_change: 'Credential change', other: 'Other',
  };

  function isPrivateIp(ip) {
    if (!ip) return true;
    if (ip === '::1' || /^f[cd]/i.test(ip) || /^fe80/i.test(ip)) return true;
    const p = ip.split('.').map(Number);
    if (p.length !== 4 || p.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return false;
    return p[0] === 10 || p[0] === 127 || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) || (p[0] === 192 && p[1] === 168);
  }

  // Short non-cryptographic hash so event ids stay stable and unique across re-imports.
  function fnv1a(str) {
    let h = 0x811c9dc5;
    for (let i = 0; i < str.length; i++) { h ^= str.charCodeAt(i); h = Math.imul(h, 0x01000193); }
    return (h >>> 0).toString(16).padStart(8, '0');
  }

  function parseTimestamp(line, year) {
    let m = SYSLOG_RE.exec(line);
    if (m) {
      const mon = MONTHS[m[1]];
      if (mon === undefined) return { error: `Unknown month "${m[1]}"` };
      const d = Date.UTC(year, mon, +m[2], +m[3], +m[4], +m[5]);
      const check = new Date(d);
      if (check.getUTCDate() !== +m[2] || +m[3] > 23 || +m[4] > 59 || +m[5] > 59) return { error: 'Invalid date/time values' };
      return { epoch: d, host: m[6], process: m[7], pid: m[8] ? +m[8] : null, message: m[9], format: 'syslog' };
    }
    m = ISO_RE.exec(line);
    if (m) {
      const d = Date.parse(m[1].replace(' ', 'T') + (m[2] ? m[2].replace(/^([+-]\d{2})(\d{2})$/, '$1:$2') : 'Z'));
      if (Number.isNaN(d)) return { error: 'Invalid ISO timestamp' };
      return { epoch: d, host: m[3], process: m[4], pid: m[5] ? +m[5] : null, message: m[6], format: 'iso' };
    }
    return null;
  }

  /**
   * Parse raw log text into normalised events.
   * @param {string} text  raw log contents
   * @param {{source?: string, year?: number}} opts
   * @returns {{events: object[], errors: object[], stats: object}}
   */
  function parseLog(text, opts = {}) {
    if (typeof text !== 'string') throw new TypeError('Log input must be text');
    const source = opts.source || 'input.log';
    const year = opts.year || new Date().getUTCFullYear();
    const events = []; const errors = [];
    let skipped = 0;
    const lines = text.replace(/^﻿/, '').split(/\r?\n/);

    lines.forEach((rawLine, i) => {
      const lineNo = i + 1;
      const line = rawLine.trim();
      if (!line || line.startsWith('#')) { skipped++; return; }
      if (line.length > MAX_LINE_LENGTH) { errors.push({ source, line: lineNo, text: line.slice(0, 200) + '…', reason: 'Line exceeds 4096 characters' }); return; }
      if (/[\x00-\x08\x0e-\x1f]/.test(line)) { errors.push({ source, line: lineNo, text: line.slice(0, 200), reason: 'Contains binary/control characters' }); return; }
      const hdr = parseTimestamp(line, year);
      if (!hdr) { errors.push({ source, line: lineNo, text: line.slice(0, 200), reason: 'Unrecognised log format (expected syslog or ISO timestamp header)' }); return; }
      if (hdr.error) { errors.push({ source, line: lineNo, text: line.slice(0, 200), reason: hdr.error }); return; }

      const proc = hdr.process.replace(/^.*\//, '');
      let fields = null;
      for (const rule of RULES) {
        if (rule.proc && rule.proc !== proc) continue;
        const m = rule.re.exec(hdr.message);
        if (m) { fields = rule.build(m); break; }
      }
      if (!fields) fields = { type: 'other', severity: 'info', description: hdr.message.slice(0, 300) || '(empty message)' };

      events.push({
        id: `${source}:${lineNo}:${fnv1a(line)}`,
        source, lineNo,
        epoch: hdr.epoch,
        timestamp: new Date(hdr.epoch).toISOString(),
        host: hdr.host, process: proc, pid: hdr.pid,
        type: fields.type, typeLabel: TYPE_LABELS[fields.type] || fields.type,
        severity: fields.severity,
        user: fields.user || null, targetUser: fields.targetUser || null,
        ip: fields.ip || null, port: fields.port || null, command: fields.command || null,
        description: fields.description,
        tags: fields.tags ? fields.tags.slice() : [],
        raw: line,
      });
    });

    return { events, errors, stats: { totalLines: lines.length, parsed: events.length, skipped, errors: errors.length } };
  }

  function raise(ev, sev) { if (SEV_RANK[sev] > SEV_RANK[ev.severity]) ev.severity = sev; }
  function tag(ev, t) { if (!ev.tags.includes(t)) ev.tags.push(t); }

  /**
   * Heuristic correlation across all events (mutates and returns sorted events).
   * These are rule-based indicators to guide an analyst, not confirmed detections.
   */
  function correlate(events, cfg = {}) {
    const bruteThreshold = cfg.bruteThreshold || 5;
    const bruteWindowMs = cfg.bruteWindowMs || 10 * 60 * 1000;
    const priorWindowMs = cfg.priorWindowMs || 60 * 60 * 1000;
    const sorted = events.slice().sort((a, b) => a.epoch - b.epoch || a.source.localeCompare(b.source) || a.lineNo - b.lineNo);
    const failsByIp = new Map();

    for (const ev of sorted) {
      if (ev.ip && !isPrivateIp(ev.ip) && /^[\d.:a-f]+$/i.test(ev.ip)) tag(ev, 'external-ip');
      if (!ev.ip) continue;
      if (ev.type === 'failed_login' || ev.type === 'invalid_user') {
        const list = failsByIp.get(ev.ip) || [];
        list.push(ev); failsByIp.set(ev.ip, list);
        const recent = list.filter((e) => ev.epoch - e.epoch <= bruteWindowMs);
        if (recent.length >= bruteThreshold) recent.forEach((e) => { tag(e, 'brute-force-pattern'); raise(e, 'high'); });
      } else if (ev.type === 'successful_login') {
        const prior = (failsByIp.get(ev.ip) || []).filter((e) => ev.epoch - e.epoch <= priorWindowMs);
        if (prior.length >= 3) {
          tag(ev, 'login-after-failures'); raise(ev, 'critical');
          ev.description += ` — after ${prior.length} failed attempts from this IP`;
        }
      }
    }
    return sorted;
  }

  function summarize(events) {
    const bySeverity = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
    const ipCounts = new Map(); const userSet = new Set();
    let failedLogins = 0;
    for (const e of events) {
      bySeverity[e.severity]++;
      if (e.type === 'failed_login' || e.type === 'invalid_user') failedLogins++;
      if (e.ip) ipCounts.set(e.ip, (ipCounts.get(e.ip) || 0) + 1);
      if (e.user) userSet.add(e.user);
    }
    const topIps = [...ipCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5).map(([ip, count]) => ({ ip, count, external: !isPrivateIp(ip) }));
    const first = events.length ? Math.min(...events.map((e) => e.epoch)) : null;
    const last = events.length ? Math.max(...events.map((e) => e.epoch)) : null;
    return { total: events.length, bySeverity, failedLogins, critical: bySeverity.critical, topIps, uniqueUsers: userSet.size, first, last };
  }

  /** RFC 4180 CSV with spreadsheet formula-injection protection. */
  function toCsv(rows, columns) {
    const cell = (v) => {
      let s = v === null || v === undefined ? '' : Array.isArray(v) ? v.join('; ') : String(v);
      if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
      return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
    };
    const head = columns.map((c) => cell(c.label)).join(',');
    return [head, ...rows.map((r) => columns.map((c) => cell(c.get(r))).join(','))].join('\r\n');
  }

  return { parseLog, correlate, summarize, toCsv, isPrivateIp, SEVERITIES, SEV_RANK, TYPE_LABELS };
});
