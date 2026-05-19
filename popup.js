'use strict';

// ── Privacy Score calculation ─────────────────────────────────────────────
// Methodology:
//   Base: 100 pts
//   -5  per unique known-tracker domain             (max -30)
//   -1  per 3 extra third-party connections >5      (max -10)
//   -3  per third-party cookie                      (max -15)
//   -5  if total cookies > 20                       (max  -5)
//   -5  per supercookie (ETag / HSTS)               (max -20)
//   -15 if Canvas fingerprinting detected           (max -15)
//   -10 if WebGL fingerprinting detected            (max -10)
//   -10 if AudioContext fingerprinting detected     (max -10)
//   -10 per suspicious dynamic-script injection     (max -20)
//   -15 if any cross-origin redirect detected       (max -15)
//   Final score clamped to [0, 100].
//
// Grades:
//   80-100 → Bom   (page respects user privacy)
//   60-79  → Razoável (minor tracking)
//   40-59  → Ruim  (significant tracking / fingerprinting)
//   0-39   → Crítico (heavy tracking, fingerprinting or hijacking)
function calcPrivacyScore(data) {
  let score = 100;
  const breakdown = [];

  const trackers = (data.thirdPartyRequests || []).filter(r => r.isTracker);
  const nonTrackers = (data.thirdPartyRequests || []).filter(r => !r.isTracker);
  const cookies = data.cookies || [];
  const thirdCookies = cookies.filter(c => !c.isFirstParty);
  const fp = data.fingerprinting || [];
  const supercookies = data.supercookies || [];
  const scripts = (data.hijacking || {}).suspiciousScripts || [];
  const redirects = (data.hijacking || {}).redirects || [];

  // Trackers
  if (trackers.length) {
    const d = Math.min(trackers.length * 5, 30);
    score -= d;
    breakdown.push(`-${d}: ${trackers.length} domínio(s) rastreador(es) conhecido(s)`);
  }

  // Generic third-party connections
  const extraConnections = Math.max(0, nonTrackers.length - 5);
  if (extraConnections > 0) {
    const d = Math.min(Math.ceil(extraConnections / 3), 10);
    score -= d;
    breakdown.push(`-${d}: muitas conexões de terceiros (${nonTrackers.length})`);
  }

  // Third-party cookies
  if (thirdCookies.length) {
    const d = Math.min(thirdCookies.length * 3, 15);
    score -= d;
    breakdown.push(`-${d}: ${thirdCookies.length} cookie(s) de terceiros`);
  }

  // Excessive total cookies
  if (cookies.length > 20) {
    score -= 5;
    breakdown.push(`-5: excesso de cookies (${cookies.length} no total)`);
  }

  // Supercookies
  if (supercookies.length) {
    const d = Math.min(supercookies.length * 5, 20);
    score -= d;
    breakdown.push(`-${d}: ${supercookies.length} supercookie(s) (ETag/HSTS)`);
  }

  // Fingerprinting
  if (fp.some(f => f.api === 'Canvas')) {
    score -= 15;
    breakdown.push('-15: fingerprinting via Canvas API detectado');
  }
  if (fp.some(f => f.api === 'WebGL')) {
    score -= 10;
    breakdown.push('-10: fingerprinting via WebGL detectado');
  }
  if (fp.some(f => f.api === 'AudioContext')) {
    score -= 10;
    breakdown.push('-10: fingerprinting via AudioContext detectado');
  }

  // Suspicious scripts
  if (scripts.length) {
    const d = Math.min(scripts.length * 10, 20);
    score -= d;
    breakdown.push(`-${d}: ${scripts.length} script(s) externo(s) injetado(s) dinamicamente`);
  }

  // Redirects
  if (redirects.length) {
    score -= 15;
    breakdown.push(`-15: ${redirects.length} redirecionamento(s) cross-origin`);
  }

  score = Math.max(0, score);

  let grade, cls;
  if (score >= 80)      { grade = 'Bom';      cls = 'grade-good'; }
  else if (score >= 60) { grade = 'Razoável'; cls = 'grade-fair'; }
  else if (score >= 40) { grade = 'Ruim';     cls = 'grade-poor'; }
  else                  { grade = 'Crítico';  cls = 'grade-bad';  }

  return { score, grade, cls, breakdown };
}

// ── DOM helpers ───────────────────────────────────────────────────────────
function el(id) { return document.getElementById(id); }

function tag(name, cls, text) {
  const s = document.createElement('span');
  s.className = 'tag ' + cls;
  s.textContent = text;
  return s;
}

function row(...children) {
  const div = document.createElement('div');
  div.className = 'data-row';
  children.forEach(c => {
    if (typeof c === 'string') {
      const span = document.createElement('span');
      span.textContent = c;
      div.appendChild(span);
    } else if (c) {
      div.appendChild(c);
    }
  });
  return div;
}

function domainSpan(text) {
  const s = document.createElement('span');
  s.className = 'domain';
  s.textContent = text;
  s.title = text;
  return s;
}

function metaSpan(text) {
  const s = document.createElement('span');
  s.className = 'meta';
  s.textContent = text;
  return s;
}

function tagsDiv(tags) {
  const d = document.createElement('div');
  d.className = 'tags';
  tags.forEach(t => d.appendChild(t));
  return d;
}

// ── Render functions ──────────────────────────────────────────────────────
function renderScore(data) {
  const { score, grade, cls, breakdown } = calcPrivacyScore(data);

  el('score-number').textContent = score;
  const gradeEl = el('score-grade');
  gradeEl.textContent = grade;
  gradeEl.className = cls;

  // SVG arc
  const arc = el('score-arc');
  const circumference = 213.6;
  const offset = circumference - (score / 100) * circumference;
  arc.style.strokeDashoffset = offset;
  const colorMap = {
    'grade-good': '#22c55e',
    'grade-fair': '#eab308',
    'grade-poor': '#f97316',
    'grade-bad':  '#ef4444'
  };
  arc.style.stroke = colorMap[cls];

  const bkList = el('score-breakdown');
  bkList.innerHTML = '';
  if (breakdown.length === 0) {
    const li = document.createElement('li');
    li.textContent = 'Nenhuma ameaça à privacidade identificada.';
    bkList.appendChild(li);
  } else {
    breakdown.forEach(item => {
      const li = document.createElement('li');
      li.textContent = item;
      bkList.appendChild(li);
    });
  }
}

function renderTracking(data) {
  const requests = data.thirdPartyRequests || [];
  const badge = el('badge-tracking');
  badge.textContent = requests.length;
  badge.className = 'badge' + (requests.some(r => r.isTracker) ? ' danger' : requests.length > 0 ? ' warn' : '');

  const list = el('tracking-list');
  list.innerHTML = '';

  if (requests.length === 0) {
    list.innerHTML = '<p class="empty-msg">Nenhuma conexão de terceiros detectada.</p>';
    return;
  }

  // Sort: trackers first, then by count desc
  const sorted = [...requests].sort((a, b) => {
    if (a.isTracker !== b.isTracker) return b.isTracker - a.isTracker;
    return b.count - a.count;
  });

  sorted.forEach(req => {
    const tags = [];
    if (req.isTracker) tags.push(tag('tag-tracker', 'tag-tracker', 'RASTREADOR'));
    tags.push(tag('tag-type', 'tag-type', req.type));
    if (req.count > 1) tags.push(tag('tag-type', 'tag-type', `×${req.count}`));

    list.appendChild(
      row(domainSpan(req.domain), metaSpan(req.url), tagsDiv(tags))
    );
  });
}

function renderCookies(data) {
  const cookies = data.cookies || [];
  const supercookies = data.supercookies || [];
  const badge = el('badge-cookies');
  badge.textContent = cookies.length;

  const thirdCount = cookies.filter(c => !c.isFirstParty).length;
  badge.className = 'badge' + (thirdCount > 0 ? ' danger' : cookies.length > 5 ? ' warn' : '');

  const list = el('cookies-list');
  list.innerHTML = '';

  if (cookies.length === 0) {
    list.innerHTML = '<p class="empty-msg">Nenhum cookie detectado.</p>';
  } else {
    const sorted = [...cookies].sort((a, b) => {
      if (a.isFirstParty !== b.isFirstParty) return a.isFirstParty - b.isFirstParty;
      return 0;
    });

    sorted.forEach(c => {
      const tags = [];
      tags.push(c.isFirstParty
        ? tag('tag-first', 'tag-first', '1ª parte')
        : tag('tag-third', 'tag-third', '3ª parte'));
      tags.push(c.isSession
        ? tag('tag-session', 'tag-session', 'sessão')
        : tag('tag-persist', 'tag-persist', 'persistente'));
      if (c.httpOnly) tags.push(tag('tag-type', 'tag-type', 'HttpOnly'));
      if (c.secure)   tags.push(tag('tag-type', 'tag-type', 'Secure'));

      const meta = `${c.domain}  •  ${c.size} bytes`;
      list.appendChild(row(domainSpan(c.name), metaSpan(meta), tagsDiv(tags)));
    });
  }

  const superSection = el('supercookies-section');
  const superList = el('supercookies-list');
  if (supercookies.length > 0) {
    superSection.style.display = 'block';
    superList.innerHTML = '';
    supercookies.forEach(sc => {
      const t = sc.type === 'HSTS'
        ? tag('tag-hsts', 'tag-hsts', 'HSTS')
        : tag('tag-etag', 'tag-etag', 'ETag');
      const desc = document.createElement('span');
      desc.className = 'meta';
      desc.textContent = sc.description;
      list.appendChild(row(domainSpan(sc.domain), desc, tagsDiv([t])));
    });
  } else {
    superSection.style.display = 'none';
  }
}

function renderStorage(data) {
  const storage = data.storage;
  const container = el('storage-content');
  container.innerHTML = '';

  if (!storage) {
    container.innerHTML = '<p class="empty-msg">Aguardando coleta de armazenamento...</p>';
    return;
  }

  function buildGroup(title, items) {
    const group = document.createElement('div');
    group.className = 'storage-group';

    const titleEl = document.createElement('div');
    titleEl.className = 'storage-group-title';
    const keys = Object.keys(items);
    titleEl.textContent = `${title} — ${keys.length} entr${keys.length === 1 ? 'ada' : 'adas'}`;
    group.appendChild(titleEl);

    if (keys.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'storage-empty';
      empty.textContent = 'Vazio';
      group.appendChild(empty);
    } else {
      keys.slice(0, 50).forEach(k => {
        const entry = document.createElement('div');
        entry.className = 'storage-entry';

        const keyEl = document.createElement('span');
        keyEl.className = 'storage-key';
        keyEl.textContent = k;
        keyEl.title = k;

        const prevEl = document.createElement('span');
        prevEl.className = 'storage-preview';
        prevEl.textContent = items[k].preview || '—';

        const sizeEl = document.createElement('span');
        sizeEl.className = 'storage-size';
        sizeEl.textContent = `${items[k].size} B`;

        entry.appendChild(keyEl);
        entry.appendChild(prevEl);
        entry.appendChild(sizeEl);
        group.appendChild(entry);
      });
      if (keys.length > 50) {
        const more = document.createElement('div');
        more.className = 'storage-empty';
        more.textContent = `... e mais ${keys.length - 50} entradas`;
        group.appendChild(more);
      }
    }
    return group;
  }

  container.appendChild(buildGroup('localStorage', storage.localStorage || {}));
  container.appendChild(buildGroup('sessionStorage', storage.sessionStorage || {}));

  // IndexedDB
  const idb = storage.indexedDB || [];
  const idbGroup = document.createElement('div');
  idbGroup.className = 'storage-group';
  const idbTitle = document.createElement('div');
  idbTitle.className = 'storage-group-title';
  idbTitle.textContent = `IndexedDB — ${idb.length} banco(s)`;
  idbGroup.appendChild(idbTitle);

  if (idb.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'storage-empty';
    empty.textContent = 'Nenhum banco IndexedDB encontrado';
    idbGroup.appendChild(empty);
  } else {
    idb.forEach(db => {
      const entry = document.createElement('div');
      entry.className = 'storage-entry';
      const keyEl = document.createElement('span');
      keyEl.className = 'storage-key';
      keyEl.textContent = db.name;
      const verEl = document.createElement('span');
      verEl.className = 'storage-size';
      verEl.textContent = `v${db.version}`;
      entry.appendChild(keyEl);
      entry.appendChild(verEl);
      idbGroup.appendChild(entry);
    });
  }
  container.appendChild(idbGroup);
}

function renderFingerprinting(data) {
  const fp = data.fingerprinting || [];
  const badge = el('badge-fp');
  badge.textContent = fp.length;
  badge.className = 'badge' + (fp.length > 0 ? ' danger' : '');

  const list = el('fingerprint-list');
  list.innerHTML = '';

  if (fp.length === 0) {
    list.innerHTML = '<p class="empty-msg">Nenhuma tentativa de fingerprinting detectada.</p>';
    return;
  }

  fp.forEach(f => {
    const apiTag = tag('tag-fp', 'tag-fp', f.api);
    const countTag = tag('tag-type', 'tag-type', `×${f.count}`);
    const meta = metaSpan(f.method);
    list.appendChild(row(domainSpan(f.api), meta, tagsDiv([apiTag, countTag])));
  });
}

function renderHijacking(data) {
  const scripts = (data.hijacking || {}).suspiciousScripts || [];
  const redirects = (data.hijacking || {}).redirects || [];
  const total = scripts.length + redirects.length;

  const badge = el('badge-hijack');
  badge.textContent = total;
  badge.className = 'badge' + (total > 0 ? ' danger' : '');

  const list = el('hijacking-list');
  list.innerHTML = '';

  if (total === 0) {
    list.innerHTML = '<p class="empty-msg">Nenhuma ameaça de hijacking detectada.</p>';
    return;
  }

  scripts.forEach(s => {
    const t = tag('tag-hijack', 'tag-hijack', 'script dinâmico');
    const meta = metaSpan(s.reason || s.url || '—');
    list.appendChild(row(domainSpan(s.domain || '?'), meta, tagsDiv([t])));
  });

  redirects.forEach(r => {
    const t = tag('tag-hijack', 'tag-hijack', `${r.statusCode}`);
    const meta = metaSpan(`${r.fromDomain} → ${r.toDomain}`);
    list.appendChild(row(domainSpan('Redirecionamento'), meta, tagsDiv([t])));
  });
}

// ── Main render ───────────────────────────────────────────────────────────
function render(data) {
  if (!data) {
    el('page-domain').textContent = '(sem dados)';
    el('score-number').textContent = '?';
    el('score-grade').textContent = 'Recarregue a página';
    return;
  }

  el('page-domain').textContent = data.pageDomain || '—';

  const ts = data.lastUpdate ? new Date(data.lastUpdate).toLocaleTimeString() : '—';
  el('last-update').textContent = `Atualizado: ${ts}`;

  renderScore(data);
  renderTracking(data);
  renderCookies(data);
  renderStorage(data);
  renderFingerprinting(data);
  renderHijacking(data);
}

async function loadData() {
  try {
    const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
    if (!tab) return;
    const data = await browser.runtime.sendMessage({ type: 'GET_TAB_DATA', tabId: tab.id });
    render(data);
  } catch (e) {
    console.error('Privacy Guard popup error:', e);
  }
}

// ── Tab switching ─────────────────────────────────────────────────────────
document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById('tab-' + btn.dataset.tab).classList.add('active');
  });
});

el('btn-refresh').addEventListener('click', loadData);

// ── Theme / color customization ───────────────────────────────────────────
const DEFAULT_COLOR = '#1e40af';

function applyAccentColor(color) {
  document.documentElement.style.setProperty('--accent', color);
  el('color-custom').value = color;

  // Mark the matching swatch as active
  document.querySelectorAll('.swatch').forEach(s => {
    s.classList.toggle('active', s.dataset.color === color);
  });
}

async function loadSavedColor() {
  try {
    const result = await browser.storage.local.get('accentColor');
    applyAccentColor(result.accentColor || DEFAULT_COLOR);
  } catch {
    applyAccentColor(DEFAULT_COLOR);
  }
}

async function saveColor(color) {
  applyAccentColor(color);
  try {
    await browser.storage.local.set({ accentColor: color });
  } catch { /* ignore storage errors */ }
}

// Toggle theme panel
el('btn-theme').addEventListener('click', (e) => {
  e.stopPropagation();
  const panel = el('theme-panel');
  panel.hidden = !panel.hidden;
});

// Close panel when clicking outside
document.addEventListener('click', (e) => {
  if (!el('theme-panel').hidden &&
      !el('theme-panel').contains(e.target) &&
      e.target !== el('btn-theme')) {
    el('theme-panel').hidden = true;
  }
});

// Swatch clicks
document.querySelectorAll('.swatch').forEach(swatch => {
  swatch.addEventListener('click', () => saveColor(swatch.dataset.color));
});

// Custom color input (debounced — fires as user picks)
el('color-custom').addEventListener('input', (e) => saveColor(e.target.value));

// ── Init ──────────────────────────────────────────────────────────────────
loadSavedColor();
loadData();
