const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const P = require('../public/js/parser.js');

const demo = fs.readFileSync(path.join(__dirname, '../public/samples/demo-auth.log'), 'utf8');

test('parses the sample log with one intentionally malformed line', () => {
  const r = P.parseLog(demo, { source: 'demo', year: 2026 });
  assert.ok(r.events.length >= 40);
  assert.strictEqual(r.errors.length, 1);
  assert.match(r.errors[0].reason, /Unrecognised/);
});

test('normalises syslog and ISO timestamps to UTC ISO strings', () => {
  const r = P.parseLog([
    'Oct 27 09:14:04 h sshd[1]: Failed password for root from 203.0.113.45 port 1 ssh2',
    '2026-10-27T11:00:00.500+02:00 h sshd[2]: Accepted publickey for bob from 10.0.0.2 port 22 ssh2',
  ].join('\n'), { year: 2026 });
  assert.strictEqual(r.events[0].timestamp, '2026-10-27T09:14:04.000Z');
  assert.strictEqual(r.events[1].timestamp, '2026-10-27T09:00:00.500Z');
  assert.strictEqual(r.events[0].type, 'failed_login');
  assert.strictEqual(r.events[0].ip, '203.0.113.45');
  assert.strictEqual(r.events[1].user, 'bob');
});

test('classifies privilege escalation and account changes', () => {
  const r = P.parseLog([
    'Oct 27 09:21:02 h sudo:   eve : TTY=pts/1 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow',
    'Oct 27 09:21:03 h sudo:   eve : TTY=pts/1 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/ls',
    "Oct 27 09:22:39 h usermod[9]: add 'x' to group 'sudo'",
    'Oct 27 09:22:14 h useradd[9]: new user: name=x, UID=1005, GID=1005',
  ].join('\n'), { year: 2026 });
  assert.deepStrictEqual(r.events.map((e) => [e.type, e.severity]), [
    ['privilege_escalation', 'critical'], ['privilege_escalation', 'medium'], ['account_change', 'critical'], ['account_created', 'high'],
  ]);
});

test('rejects malformed input without throwing', () => {
  const r = P.parseLog('garbage\nFeb 30 10:00:00 h sshd[1]: x\n\u0000\u0001bin\n# comment\n', { year: 2026 });
  assert.strictEqual(r.events.length, 0);
  assert.strictEqual(r.errors.length, 3);
  assert.throws(() => P.parseLog(null), TypeError);
});

test('correlation flags brute force and login after failures', () => {
  const r = P.parseLog(demo, { source: 'demo', year: 2026 });
  const events = P.correlate(r.events);
  for (let i = 1; i < events.length; i++) assert.ok(events[i].epoch >= events[i - 1].epoch);
  const brute = events.filter((e) => e.tags.includes('brute-force-pattern'));
  assert.ok(brute.length >= 5 && brute.every((e) => e.ip === '203.0.113.45'));
  const compromised = events.find((e) => e.type === 'successful_login' && e.user === 'backup');
  assert.strictEqual(compromised.severity, 'critical');
  assert.ok(compromised.tags.includes('login-after-failures'));
  const legit = events.find((e) => e.type === 'successful_login' && e.user === 'deploy');
  assert.strictEqual(legit.severity, 'low');
  const s = P.summarize(events);
  assert.strictEqual(s.total, events.length);
  assert.ok(s.critical >= 4 && s.failedLogins >= 10);
});

test('event ids are unique and stable', () => {
  const a = P.parseLog(demo, { source: 'demo', year: 2026 }).events.map((e) => e.id);
  const b = P.parseLog(demo, { source: 'demo', year: 2026 }).events.map((e) => e.id);
  assert.strictEqual(new Set(a).size, a.length);
  assert.deepStrictEqual(a, b);
});

test('CSV export escapes quotes and neutralises formula injection', () => {
  const csv = P.toCsv([{ a: '=HYPERLINK("x")', b: 'a,b' }], [{ label: 'a', get: (r) => r.a }, { label: 'b', get: (r) => r.b }]);
  assert.strictEqual(csv, 'a,b\r\n"\'=HYPERLINK(""x"")","a,b"');
});
