/* Incident Timeline & Evidence Collection — UI controller (vanilla JS, no build step). */
(function () {
  'use strict';
  const P = window.LogParser;
  const $ = (id) => document.getElementById(id);
  const MAX_FILE_BYTES = 5 * 1024 * 1024;
  const MAX_RENDER = 1500;
  const STORE_KEY = 'ps013.evidence.v1';
  const APP_VERSION = '1.0.0';

  const state = {
    events: [], errors: [], sources: [], isDemo: false,
    selected: new Set(),
    evidence: new Map(), // id -> { event, addedAt, note, sha256 }
    filters: { q: '', sevs: new Set(P.SEVERITIES), from: null, to: null, order: 'asc' },
    visible: [],
  };

  // ---------- helpers ----------
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const fmtTime = (ms) => new Date(ms).toISOString().slice(11, 19);
  const fmtDate = (ms) => new Date(ms).toISOString().slice(0, 10);
  const fmtFull = (ms) => new Date(ms).toISOString().replace('T', ' ').replace(/\.\d+Z$/, 'Z');
  const debounce = (fn, ms) => { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; };

  let toastTimer;
  function toast(msg) {
    const el = $('toast'); el.textContent = msg; el.classList.add('show');
    clearTimeout(toastTimer); toastTimer = setTimeout(() => el.classList.remove('show'), 2400);
  }
  function showError(msg) { const b = $('error-banner'); b.textContent = msg; b.classList.toggle('hidden', !msg); }

  async function sha256(text) {
    try {
      if (!window.crypto || !crypto.subtle) return null;
      const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
      return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
    } catch { return null; }
  }

  function download(filename, content, mime) {
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = Object.assign(document.createElement('a'), { href: url, download: filename });
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  const stamp = () => new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const caseSlug = () => ($('case-name').value.trim() || 'incident').replace(/[^\w.-]+/g, '_').slice(0, 40);

  // ---------- persistence (evidence only) ----------
  function saveEvidence() {
    try {
      localStorage.setItem(STORE_KEY, JSON.stringify({ caseName: $('case-name').value, items: [...state.evidence.values()] }));
    } catch { /* storage unavailable — evidence stays in memory */ }
  }
  function loadEvidence() {
    try {
      const data = JSON.parse(localStorage.getItem(STORE_KEY) || 'null');
      if (!data || !Array.isArray(data.items)) return;
      $('case-name').value = typeof data.caseName === 'string' ? data.caseName : '';
      for (const it of data.items) if (it && it.event && it.event.id) state.evidence.set(it.event.id, it);
    } catch { /* ignore corrupt storage */ }
  }

  // ---------- loading data ----------
  function ingest(results, { append, isDemo }) {
    if (!append) { state.events = []; state.errors = []; state.sources = []; state.selected.clear(); }
    for (const r of results) {
      state.events.push(...r.events);
      state.errors.push(...r.errors);
      state.sources.push({ name: r.source, ...r.stats });
    }
    state.events = P.correlate(state.events);
    state.isDemo = append ? state.isDemo || isDemo : isDemo;
    $('demo-banner').classList.toggle('hidden', !state.isDemo);
    renderAll();
  }

  async function loadDemo() {
    const btn = $('btn-demo');
    btn.classList.add('loading'); btn.querySelector('.ico').textContent = '⟳';
    showError('');
    renderLoading();
    try {
      const res = await fetch('samples/demo-auth.log', { cache: 'no-store' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const text = await res.text();
      const r = P.parseLog(text, { source: 'demo-auth.log (SAMPLE)', year: 2026 });
      r.source = 'demo-auth.log (SAMPLE)';
      resetFilters(false);
      ingest([r], { append: false, isDemo: true });
      toast(`Loaded ${r.events.length} sample events`);
    } catch (err) {
      showError(`Could not load demo data (${err.message}). Run the app with "npm start" rather than opening the HTML file directly.`);
      renderAll();
    } finally {
      btn.classList.remove('loading'); btn.querySelector('.ico').textContent = '▶';
    }
  }

  // ---------- filtering ----------
  function applyFilters() {
    const f = state.filters;
    const q = f.q.trim().toLowerCase();
    const terms = q ? q.split(/\s+/) : [];
    let list = state.events.filter((e) => {
      if (!f.sevs.has(e.severity)) return false;
      if (f.from !== null && e.epoch < f.from) return false;
      if (f.to !== null && e.epoch > f.to) return false;
      if (terms.length) {
        const hay = [e.description, e.user, e.targetUser, e.ip, e.host, e.process, e.typeLabel, e.command, e.raw, e.tags.join(' ')].join(' ').toLowerCase();
        return terms.every((t) => hay.includes(t));
      }
      return true;
    });
    if (f.order === 'desc') list = list.slice().reverse();
    else if (f.order === 'sev') list = list.slice().sort((a, b) => P.SEV_RANK[b.severity] - P.SEV_RANK[a.severity] || a.epoch - b.epoch);
    state.visible = list;
  }

  const parseLocalUtc = (v) => { if (!v) return null; const t = Date.parse(v.length === 16 ? v + ':00Z' : v + 'Z'); return Number.isNaN(t) ? null : t; };

  function resetFilters(render = true) {
    state.filters = { q: '', sevs: new Set(P.SEVERITIES), from: null, to: null, order: 'asc' };
    $('f-search').value = ''; $('f-from').value = ''; $('f-to').value = ''; $('f-order').value = 'asc';
    if (render) renderTimelineAndControls();
  }

  // ---------- rendering ----------
  function renderAll() {
    renderStats();
    renderSide();
    renderErrors();
    renderTimelineAndControls();
    renderEvidence();
  }

  function renderLoading() {
    $('timeline').innerHTML = '<div class="skeleton"></div>'.repeat(6);
  }

  function renderStats() {
    const s = P.summarize(state.events);
    $('stat-total').textContent = s.total;
    $('stat-range').textContent = s.total ? `${fmtFull(s.first)} → ${fmtTime(s.last)}Z` : 'No data loaded';
    $('stat-critical').textContent = s.critical;
    $('stat-high').textContent = `${s.bySeverity.high} high severity`;
    $('stat-failed').textContent = s.failedLogins;
    const failIps = new Set(state.events.filter((e) => (e.type === 'failed_login' || e.type === 'invalid_user') && e.ip).map((e) => e.ip));
    $('stat-ips').textContent = `${failIps.size} source IP${failIps.size === 1 ? '' : 's'}`;
    $('stat-evidence').textContent = state.evidence.size;
    $('btn-clear').disabled = !state.events.length;
    return s;
  }

  function renderSide() {
    const s = P.summarize(state.events);
    const max = Math.max(1, ...Object.values(s.bySeverity));
    $('sev-chart').innerHTML = P.SEVERITIES.map((sev) => `
      <div class="bar-row sev-${sev}"><span>${sev}</span><div class="bar"><span style="width:${(s.bySeverity[sev] / max) * 100}%"></span></div><span class="n">${s.bySeverity[sev]}</span></div>`).join('');

    $('top-ips').innerHTML = s.topIps.length
      ? s.topIps.map((t) => `<li data-q="${esc(t.ip)}" title="Filter timeline by ${esc(t.ip)}"><span>${esc(t.ip)}${t.external ? '<span class="ext">EXTERNAL</span>' : ''}</span><span class="muted">${t.count}</span></li>`).join('')
      : '<li class="side-empty">No IP activity yet</li>';

    const recent = state.events.filter((e) => P.SEV_RANK[e.severity] >= 3).slice(-6).reverse();
    $('recent').innerHTML = recent.length
      ? recent.map((e) => `<li class="sev-${e.severity}" data-id="${esc(e.id)}"><span class="rail"></span><div><time>${fmtFull(e.epoch)}</time>${esc(e.description)}</div></li>`).join('')
      : '<li class="side-empty">No high or critical events</li>';
  }

  function renderErrors() {
    const errs = state.errors;
    $('errors-panel').classList.toggle('hidden', !errs.length);
    $('error-count').textContent = errs.length;
    $('errors').innerHTML = errs.slice(0, 50).map((e) => `<li><span class="r">${esc(e.source)} · line ${e.line}: ${esc(e.reason)}</span><code>${esc(e.text)}</code></li>`).join('')
      + (errs.length > 50 ? `<li class="muted">…and ${errs.length - 50} more</li>` : '');
  }

  function renderSevToggles() {
    const counts = Object.fromEntries(P.SEVERITIES.map((s) => [s, 0]));
    state.events.forEach((e) => counts[e.severity]++);
    $('f-sev').innerHTML = P.SEVERITIES.map((s) => `<button type="button" class="sev-toggle sev-${s}" data-sev="${s}" aria-pressed="${state.filters.sevs.has(s)}"><span class="dot"></span>${s} <span class="n">${counts[s]}</span></button>`).join('');
  }

  function eventHtml(e) {
    const sel = state.selected.has(e.id); const inEv = state.evidence.has(e.id);
    const chips = [
      e.ip && `<span class="chip" data-q="${esc(e.ip)}"><b>ip</b> ${esc(e.ip)}</span>`,
      e.user && `<span class="chip" data-q="${esc(e.user)}"><b>user</b> ${esc(e.user)}</span>`,
      e.targetUser && `<span class="chip" data-q="${esc(e.targetUser)}"><b>as</b> ${esc(e.targetUser)}</span>`,
      `<span class="chip" data-q="${esc(e.host)}"><b>host</b> ${esc(e.host)}</span>`,
      `<span class="chip" data-q="${esc(e.process)}"><b>proc</b> ${esc(e.process)}${e.pid ? '[' + e.pid + ']' : ''}</span>`,
    ].filter(Boolean).join('');
    const tags = e.tags.map((t) => `<span class="tag t-${esc(t)}" title="Heuristic indicator — verify before concluding">${esc(t)}</span>`).join('');
    return `<article class="event sev-${e.severity}${sel ? ' selected' : ''}${inEv ? ' in-evidence' : ''}" data-id="${esc(e.id)}">
      <input type="checkbox" class="sel" aria-label="Select event" ${sel ? 'checked' : ''}>
      <time class="time" datetime="${e.timestamp}" title="${e.timestamp}">${fmtTime(e.epoch)}</time>
      <span class="rail"></span>
      <div class="event-main">
        <div class="event-top"><span class="badge">${e.severity}</span><span class="etype">${esc(e.typeLabel)}</span>${tags}</div>
        <p class="desc">${esc(e.description)}</p>
        <div class="meta">${chips}</div>
        <details class="raw"><summary>Raw log · ${esc(e.source)}:${e.lineNo}</summary><pre>${esc(e.raw)}</pre></details>
      </div>
    </article>`;
  }

  function renderTimelineAndControls() {
    renderSevToggles();
    applyFilters();
    const list = state.visible; const tl = $('timeline');
    const has = state.events.length > 0;
    $('result-count').textContent = has ? `${list.length} of ${state.events.length} events` : '';
    ['btn-export-tl-json', 'btn-export-tl-csv'].forEach((id) => { $(id).disabled = !list.length; });

    if (!has) {
      tl.innerHTML = `<div class="empty"><div class="big">🛡️</div><h3>No logs loaded</h3>
        <p>Load the clearly labelled sample dataset or import your own <code>auth.log</code> to build an incident timeline.</p>
        <button class="btn btn-primary" data-action="demo">▶ Load Demo Data</button> <button class="btn" data-action="import">Import Logs</button></div>`;
    } else if (!list.length) {
      tl.innerHTML = '<div class="empty"><div class="big">🔍</div><h3>No events match your filters</h3><p>Try a different keyword, severity or time range.</p><button class="btn" data-action="reset">Reset filters</button></div>';
    } else {
      let html = ''; let lastDay = '';
      const shown = list.slice(0, MAX_RENDER);
      for (const e of shown) {
        const day = fmtDate(e.epoch);
        if (state.filters.order !== 'sev' && day !== lastDay) { html += `<div class="day">${day} (UTC)</div>`; lastDay = day; }
        html += eventHtml(e);
      }
      if (list.length > MAX_RENDER) html += `<div class="truncate-note">Showing first ${MAX_RENDER} of ${list.length} matching events — refine filters to see more. Exports include all matches.</div>`;
      tl.innerHTML = html;
    }
    updateSelectionControls();
  }

  function updateSelectionControls() {
    const visIds = state.visible.slice(0, MAX_RENDER).map((e) => e.id);
    const selVisible = visIds.filter((id) => state.selected.has(id)).length;
    const all = $('sel-all');
    all.checked = visIds.length > 0 && selVisible === visIds.length;
    all.indeterminate = selVisible > 0 && selVisible < visIds.length;
    all.disabled = !visIds.length;
    const btn = $('btn-add-evidence');
    btn.disabled = state.selected.size === 0;
    btn.textContent = state.selected.size ? `+ Add ${state.selected.size} to Evidence` : '+ Add to Evidence';
  }

  function renderEvidence() {
    const items = [...state.evidence.values()].sort((a, b) => a.event.epoch - b.event.epoch);
    $('evidence-count').textContent = items.length;
    $('stat-evidence').textContent = items.length;
    ['btn-export-ev-json', 'btn-export-ev-csv', 'btn-clear-ev'].forEach((id) => { $(id).disabled = !items.length; });
    $('evidence').innerHTML = items.length
      ? items.map(({ event: e, addedAt, note, sha256: h }) => `<li class="ev-item sev-${e.severity}" data-id="${esc(e.id)}">
          <div class="ev-head"><span class="badge">${e.severity}</span><span class="t">${fmtFull(e.epoch)}</span><button class="ev-remove" title="Remove from evidence" aria-label="Remove">×</button></div>
          <div class="d"><strong>${esc(e.typeLabel)}</strong> — ${esc(e.description)}</div>
          <div class="t">Collected ${fmtFull(addedAt)} · ${esc(e.source)}:${e.lineNo}</div>
          ${h ? `<div class="hash" title="SHA-256 of the raw log line">sha256 ${h}</div>` : ''}
          <textarea class="ev-note" rows="1" maxlength="500" placeholder="Analyst note…">${esc(note)}</textarea>
        </li>`).join('')
      : '<li class="side-empty">Select timeline events and click <b>Add to Evidence</b> to build your case file.</li>';
  }

  // ---------- evidence ----------
  async function addSelectedToEvidence() {
    const byId = new Map(state.events.map((e) => [e.id, e]));
    let added = 0;
    for (const id of state.selected) {
      const e = byId.get(id);
      if (!e || state.evidence.has(id)) continue;
      state.evidence.set(id, { event: e, addedAt: Date.now(), note: '', sha256: await sha256(e.raw) });
      added++;
    }
    state.selected.clear();
    saveEvidence();
    renderEvidence(); renderStats(); renderTimelineAndControls();
    toast(added ? `Added ${added} event${added === 1 ? '' : 's'} to evidence` : 'Selected events are already in evidence');
  }

  // ---------- exports ----------
  const EVENT_COLUMNS = [
    { label: 'timestamp_utc', get: (e) => e.timestamp }, { label: 'severity', get: (e) => e.severity },
    { label: 'event_type', get: (e) => e.type }, { label: 'description', get: (e) => e.description },
    { label: 'username', get: (e) => e.user }, { label: 'target_user', get: (e) => e.targetUser },
    { label: 'source_ip', get: (e) => e.ip }, { label: 'port', get: (e) => e.port }, { label: 'host', get: (e) => e.host },
    { label: 'process', get: (e) => e.process }, { label: 'command', get: (e) => e.command }, { label: 'indicators', get: (e) => e.tags },
    { label: 'source_file', get: (e) => e.source }, { label: 'line', get: (e) => e.lineNo }, { label: 'raw', get: (e) => e.raw },
  ];
  const cleanEvent = ({ epoch, typeLabel, ...rest }) => rest;
  function exportMeta(extra) {
    return {
      tool: 'PS-013 Incident Timeline', version: APP_VERSION, case: $('case-name').value.trim() || null,
      exportedAt: new Date().toISOString(), timezone: 'UTC', containsSampleData: state.isDemo,
      sources: state.sources.map((s) => ({ name: s.name, parsed: s.parsed, errors: s.errors })),
      note: 'Indicators/tags are rule-based heuristics to guide investigation, not confirmed detections.', ...extra,
    };
  }
  function exportTimeline(fmt) {
    const list = state.visible;
    if (!list.length) return;
    const name = `${caseSlug()}_timeline_${stamp()}`;
    if (fmt === 'json') download(`${name}.json`, JSON.stringify({ ...exportMeta({ filters: { query: state.filters.q, severities: [...state.filters.sevs], order: state.filters.order }, eventCount: list.length }), events: list.map(cleanEvent) }, null, 2), 'application/json');
    else download(`${name}.csv`, P.toCsv(list, EVENT_COLUMNS), 'text/csv');
    toast(`Exported ${list.length} timeline events (${fmt.toUpperCase()})`);
  }
  function exportEvidence(fmt) {
    const items = [...state.evidence.values()].sort((a, b) => a.event.epoch - b.event.epoch);
    if (!items.length) return;
    const name = `${caseSlug()}_evidence_${stamp()}`;
    if (fmt === 'json') {
      download(`${name}.json`, JSON.stringify({ ...exportMeta({ itemCount: items.length }), evidence: items.map((it, i) => ({
        evidenceId: `EV-${String(i + 1).padStart(3, '0')}`, collectedAt: new Date(it.addedAt).toISOString(), analystNote: it.note || '',
        rawSha256: it.sha256, event: cleanEvent(it.event) })) }, null, 2), 'application/json');
    } else {
      const cols = [{ label: 'evidence_id', get: (it) => it._eid }, { label: 'collected_at_utc', get: (it) => new Date(it.addedAt).toISOString() },
        { label: 'analyst_note', get: (it) => it.note }, { label: 'raw_sha256', get: (it) => it.sha256 },
        ...EVENT_COLUMNS.map((c) => ({ label: c.label, get: (it) => c.get(it.event) }))];
      download(`${name}.csv`, P.toCsv(items.map((it, i) => ({ ...it, _eid: `EV-${String(i + 1).padStart(3, '0')}` })), cols), 'text/csv');
    }
    toast(`Exported ${items.length} evidence items (${fmt.toUpperCase()})`);
  }

  // ---------- import ----------
  const dlg = $('import-dialog');
  let pendingFiles = [];
  function openImport() {
    $('year-input').value = $('year-input').value || new Date().getFullYear();
    $('import-error').classList.add('hidden');
    $('append-input').checked = false; $('append-input').disabled = !state.events.length;
    if (typeof dlg.showModal === 'function') dlg.showModal(); else dlg.setAttribute('open', '');
  }
  function setFiles(files) {
    pendingFiles = [...files];
    $('file-names').textContent = pendingFiles.length ? pendingFiles.map((f) => `${f.name} (${(f.size / 1024).toFixed(1)} KB)`).join(', ') : 'Max 5 MB per file';
  }
  function importError(msg) { const el = $('import-error'); el.textContent = msg; el.classList.remove('hidden'); }

  async function doImport(ev) {
    ev.preventDefault();
    const year = Number($('year-input').value);
    if (!Number.isInteger(year) || year < 1990 || year > 2100) return importError('Enter a valid year between 1990 and 2100.');
    const pasted = $('paste-input').value;
    if (!pendingFiles.length && !pasted.trim()) return importError('Choose at least one log file or paste log lines.');
    const tooBig = pendingFiles.find((f) => f.size > MAX_FILE_BYTES);
    if (tooBig) return importError(`${tooBig.name} exceeds the 5 MB limit.`);

    const btn = $('btn-do-import'); btn.disabled = true; btn.textContent = 'Parsing…';
    try {
      const inputs = await Promise.all(pendingFiles.map(async (f) => ({ name: f.name, text: await f.text() })));
      if (pasted.trim()) inputs.push({ name: 'pasted-input', text: pasted });
      const results = inputs.map((inp) => { const r = P.parseLog(inp.text, { source: inp.name, year }); r.source = inp.name; return r; });
      const parsed = results.reduce((n, r) => n + r.events.length, 0);
      const errs = results.reduce((n, r) => n + r.errors.length, 0);
      if (!parsed) return importError(`No recognisable log events found${errs ? ` (${errs} line${errs === 1 ? '' : 's'} rejected)` : ''}. Expected Linux auth.log lines such as "Oct 27 09:14:04 host sshd[1301]: Failed password for root from 203.0.113.45 port 52211 ssh2".`);
      const append = $('append-input').checked;
      if (!append) resetFilters(false);
      showError('');
      ingest(results, { append, isDemo: false });
      dlg.close(); setFiles([]); $('file-input').value = ''; $('paste-input').value = '';
      toast(`Imported ${parsed} events${errs ? ` · ${errs} line${errs === 1 ? '' : 's'} skipped` : ''}`);
    } catch (err) {
      importError(`Import failed: ${err.message}`);
    } finally {
      btn.disabled = false; btn.textContent = 'Parse & Load';
    }
  }

  // ---------- events ----------
  function setQuery(q) { $('f-search').value = q; state.filters.q = q; renderTimelineAndControls(); $('f-search').focus(); }

  $('btn-demo').addEventListener('click', loadDemo);
  $('btn-import').addEventListener('click', openImport);
  $('btn-clear').addEventListener('click', () => {
    state.events = []; state.errors = []; state.sources = []; state.selected.clear(); state.isDemo = false;
    $('demo-banner').classList.add('hidden'); showError(''); resetFilters(false); renderAll(); toast('Timeline cleared (evidence kept)');
  });
  $('f-search').addEventListener('input', debounce((e) => { state.filters.q = e.target.value; renderTimelineAndControls(); }, 150));
  $('f-order').addEventListener('change', (e) => { state.filters.order = e.target.value; renderTimelineAndControls(); });
  $('f-from').addEventListener('change', (e) => { state.filters.from = parseLocalUtc(e.target.value); renderTimelineAndControls(); });
  $('f-to').addEventListener('change', (e) => { state.filters.to = parseLocalUtc(e.target.value); renderTimelineAndControls(); });
  $('btn-reset').addEventListener('click', () => resetFilters());
  $('f-sev').addEventListener('click', (e) => {
    const b = e.target.closest('.sev-toggle'); if (!b) return;
    const s = b.dataset.sev; const sevs = state.filters.sevs;
    if (sevs.has(s)) sevs.delete(s); else sevs.add(s);
    renderTimelineAndControls();
  });

  $('timeline').addEventListener('click', (e) => {
    const action = e.target.closest('[data-action]');
    if (action) { ({ demo: loadDemo, import: openImport, reset: () => resetFilters() })[action.dataset.action](); return; }
    const chip = e.target.closest('.chip'); if (chip) { setQuery(chip.dataset.q); return; }
    if (e.target.closest('details, a, button')) return;
    const card = e.target.closest('.event'); if (!card) return;
    const id = card.dataset.id;
    if (state.selected.has(id)) state.selected.delete(id); else state.selected.add(id);
    card.classList.toggle('selected', state.selected.has(id));
    card.querySelector('.sel').checked = state.selected.has(id);
    updateSelectionControls();
  });
  $('sel-all').addEventListener('change', (e) => {
    const ids = state.visible.slice(0, MAX_RENDER).map((ev) => ev.id);
    ids.forEach((id) => (e.target.checked ? state.selected.add(id) : state.selected.delete(id)));
    renderTimelineAndControls();
  });
  $('btn-add-evidence').addEventListener('click', addSelectedToEvidence);

  $('top-ips').addEventListener('click', (e) => { const li = e.target.closest('li[data-q]'); if (li) setQuery(li.dataset.q); });
  $('recent').addEventListener('click', (e) => {
    const li = e.target.closest('li[data-id]'); if (!li) return;
    if (!state.visible.some((ev) => ev.id === li.dataset.id)) resetFilters();
    const card = $('timeline').querySelector(`.event[data-id="${CSS.escape(li.dataset.id)}"]`);
    if (card) { card.scrollIntoView({ behavior: 'smooth', block: 'center' }); card.animate([{ boxShadow: '0 0 0 2px #22d3ee' }, { boxShadow: '0 0 0 0 transparent' }], { duration: 1400 }); }
  });

  $('evidence').addEventListener('click', (e) => {
    const rm = e.target.closest('.ev-remove'); if (!rm) return;
    state.evidence.delete(rm.closest('.ev-item').dataset.id);
    saveEvidence(); renderEvidence(); renderStats(); renderTimelineAndControls();
  });
  $('evidence').addEventListener('input', debounce((e) => {
    if (!e.target.classList.contains('ev-note')) return;
    const it = state.evidence.get(e.target.closest('.ev-item').dataset.id);
    if (it) { it.note = e.target.value; saveEvidence(); }
  }, 300));
  $('case-name').addEventListener('input', debounce(saveEvidence, 300));
  $('btn-clear-ev').addEventListener('click', () => {
    if (!confirm('Remove all items from the evidence collection?')) return;
    state.evidence.clear(); saveEvidence(); renderEvidence(); renderStats(); renderTimelineAndControls();
  });

  $('btn-export-tl-json').addEventListener('click', () => exportTimeline('json'));
  $('btn-export-tl-csv').addEventListener('click', () => exportTimeline('csv'));
  $('btn-export-ev-json').addEventListener('click', () => exportEvidence('json'));
  $('btn-export-ev-csv').addEventListener('click', () => exportEvidence('csv'));

  $('import-form').addEventListener('submit', (e) => { if (e.submitter && e.submitter.value === 'cancel') return; doImport(e); });
  $('file-input').addEventListener('change', (e) => setFiles(e.target.files));
  const drop = $('drop');
  ['dragenter', 'dragover'].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.add('over'); }));
  ['dragleave', 'drop'].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.remove('over'); }));
  drop.addEventListener('drop', (e) => { if (e.dataTransfer && e.dataTransfer.files.length) setFiles(e.dataTransfer.files); });

  // ---------- init ----------
  loadEvidence();
  renderAll();
})();
