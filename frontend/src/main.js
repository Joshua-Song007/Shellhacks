import gsap from 'gsap';
import { feed, state, inject, suppress, ALLELES, evaluate } from './data.js';
import { createHelix } from './helix.js';
import { createMesh, LABEL } from './mesh.js';

const $ = (s, r = document) => r.querySelector(s);
const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;
const fmt = (n) => n.toLocaleString('en-US');
const short = (h) => (h ? `${h.slice(0, 6)}…${h.slice(-4)}` : '—');
const nameOf = (id) => state.devices.find((d) => d.id === id)?.name ?? 'Another network';
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => `&#${c.charCodeAt(0)};`);
const COLOR = { clean: '#4ff5d2', watching: '#ffc46b', isolated: '#ff3b5c', cured: '#8f7bff' };

function ago(ms) {
  const s = Math.max(0, Math.round((Date.now() - ms) / 1000));
  if (s < 5) return 'just now';
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  const d = Math.floor(s / 86400);
  return d === 1 ? 'yesterday' : `${d} days ago`;
}

// ---------- Mode switch ----------
const pill = $('.mode-pill');
function placePill(btn, animate = true) {
  gsap.to(pill, { x: btn.offsetLeft - 4, width: btn.offsetWidth, duration: animate && !reduced ? 0.45 : 0, ease: 'expo.out' });
}
document.querySelectorAll('.modes button').forEach((btn) =>
  btn.addEventListener('click', () => {
    const mode = btn.dataset.mode;
    if (document.body.dataset.mode === mode) return;
    document.body.dataset.mode = mode;
    document.querySelectorAll('.modes button').forEach((b) => b.setAttribute('aria-selected', b === btn));
    placePill(btn);
    const show = $(`#${mode}`);
    const hide = $(`#${mode === 'standard' ? 'advanced' : 'standard'}`);
    hide.hidden = true;
    show.hidden = false;
    // fromTo, not from: a toggle mid-fade would otherwise make the half-faded value the new end state.
    if (!reduced) gsap.fromTo(show.children, { opacity: 0, y: 10 }, { opacity: 1, y: 0, duration: 0.5, ease: 'power3.out', stagger: 0.04, overwrite: true });
    if (mode === 'advanced') scrollTerm();
  }),
);
document.fonts.ready.then(() => placePill($('.modes [aria-selected="true"]'), false));

// ---------- Health ring (one segment per device) ----------
const R = 108;
const C = 2 * Math.PI * R;
const segs = state.devices.map((d, i) => {
  const gap = 10;
  const len = C / state.devices.length - gap;
  const c = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
  Object.entries({ cx: 130, cy: 130, r: R, 'stroke-dasharray': `${len} ${C - len}`, 'stroke-dashoffset': -(i * C) / state.devices.length - gap / 2 }).forEach(([k, v]) => c.setAttribute(k, v));
  c.style.stroke = c.style.color = COLOR.clean;
  $('#ring-segs').append(c);
  const t = document.createElementNS('http://www.w3.org/2000/svg', 'title');
  c.append(t);
  return { c, t };
});
if (!reduced) gsap.to('.ring-orbit', { rotation: 360, svgOrigin: '130 130', duration: 90, repeat: -1, ease: 'none' });

const COPY = {
  clean: () => ["Everything's safe", 'T-Cell is watching every device on your home network. Nothing needs your attention.'],
  watching: (d) => [`Checking something on ${d}`, 'A program is acting unusually. T-Cell is keeping a close eye on it. You don’t need to do anything.'],
  isolated: (d, t) => [`Threat paused on ${d}`, `Something that behaves like ${t.toLowerCase()} tried to run. T-Cell froze it before it could do damage and is building a cure.`],
  cured: (d, t, tti) => ['Fixed. Your devices are immune.', `Found, frozen and fixed in ${tti} seconds. The cure found on ${d} was shared with your other devices, so this threat can’t hurt them.`],
};
let phase = 'clean';
function renderHealth() {
  const safe = state.devices.filter((d) => d.status === 'clean' || d.status === 'cured').length;
  state.devices.forEach((d, i) => {
    gsap.to(segs[i].c, { stroke: COLOR[d.status], color: COLOR[d.status], duration: 0.6 });
    segs[i].t.textContent = `${d.name}: ${LABEL[d.status]}`;
  });
  const inc = state.incident;
  const tti = inc?.marks.immune ? ((inc.marks.immune - inc.t0) / 1000).toFixed(1) : '';
  const [title, sub] = COPY[phase](inc ? nameOf(inc.device) : '', inc?.threat ?? '', tti);
  const h = $('#health-title');
  if (h.textContent !== title) {
    h.textContent = title;
    $('#health-sub').textContent = sub;
    if (!reduced) gsap.fromTo(['#health-title', '#health-sub'], { opacity: 0, y: 8 }, { opacity: 1, y: 0, duration: 0.5, ease: 'power3.out', stagger: 0.06, overwrite: true });
  }
  $('.health').dataset.s = phase;
  $('#f-safe').textContent = `${safe} of ${state.devices.length}`;
  $('#f-stopped').textContent = state.stoppedThisWeek;
  $('#f-cures').textContent = state.genes.filter((g) => !g.suppressed).length;
  $('#live-text').textContent = phase === 'clean' ? `Protecting ${state.devices.length} devices` : LABEL[phase === 'cured' ? 'cured' : phase];
  document.body.dataset.alert = phase;
}

// ---------- Mesh ----------
const mesh = createMesh($('#mesh'), state.devices, state.self, { reduced });

// ---------- Local genome helix ----------
const probe = $('#local-probe');
let probeI = -1;
const helix = createHelix($('#local-gl'), {
  hashes: state.genes.map((g) => g.gene),
  tilt: 0,
  bg: 0x060a16,
  length: 0.9,
  thickness: 0.62,
  reduced,
  onHover(h) {
    probe.classList.toggle('on', !!h);
    if (!h) return (probeI = -1);
    // Narrow column: keep the card inside the box instead of clipping off the right edge.
    probe.style.transform = `translate(${Math.min(h.x, probe.parentElement.clientWidth - probe.offsetWidth - 28)}px, ${h.y}px)`;
    if (h.index === probeI) return;
    probeI = h.index;
    const g = state.genes[h.index];
    $('strong', probe).textContent = g.name;
    $('span', probe).textContent = `${g.from === state.self ? 'Found by this Mac' : g.from === 'network' ? 'Learned from the network' : `Shared by ${nameOf(g.from)}`}, ${ago(g.time)}`;
  },
});
$('#open-genome').addEventListener('click', () => (window.tcell ? window.tcell.openGenome() : open('genome.html', 'genome', 'width=1100,height=760')));

// ---------- Contributions ----------
function renderContrib() {
  const list = state.contributions;
  const cures = list.filter((b) => b.kind === 'commit_gene').length;
  $('#contrib-sub').textContent = list.length
    ? `This Mac has written ${list.length} ${list.length === 1 ? 'block' : 'blocks'} to the shared chain${cures ? `, including ${cures} ${cures === 1 ? 'cure' : 'cures'} other people now use` : ''}.`
    : '';
  $('#contrib-list').innerHTML = list.length
    ? list
        .map(
          (b) => `<li class="${{ commit_gene: 'is-cure', suppress_gene: 'is-off' }[b.kind] ?? 'is-report'}">
            <span class="c-icon" aria-hidden="true"></span>
            <div><strong>${{ commit_gene: 'Shared a cure', suppress_gene: 'Turned off a cure' }[b.kind] ?? 'Reported a new threat'}</strong>
            <span>${esc(b.name ?? 'Unknown threat')}</span></div>
            <div class="c-meta"><span>Block ${fmt(b.slot)}</span><time data-t="${b.time}">${ago(b.time)}</time></div>
          </li>`,
        )
        .join('')
    : `<li class="empty">Nothing yet. When this Mac is the first to catch a threat, the cure it writes to the chain shows up here.</li>`;
}

// ---------- Terminal ----------
const term = $('#term');
const SRC = ['tes', 'scout', 'soldier', 'ledger', 'mesh'];
const counts = Object.fromEntries(SRC.map((s) => [s, 0]));
const hiddenSrc = new Set();
let follow = true;
$('#chips').innerHTML = SRC.map((s) => `<button class="chip" data-src="${s}" aria-pressed="true">${s}<span>0</span></button>`).join('');
$('#chips').addEventListener('click', (e) => {
  const b = e.target.closest('.chip');
  if (!b) return;
  const on = b.getAttribute('aria-pressed') !== 'true';
  b.setAttribute('aria-pressed', on);
  on ? hiddenSrc.delete(b.dataset.src) : hiddenSrc.add(b.dataset.src);
  term.dataset.hide = [...hiddenSrc].join(' ');
  scrollTerm();
});
const followBtn = $('#follow');
function setFollow(on) {
  follow = on;
  followBtn.classList.toggle('is-on', on);
  followBtn.setAttribute('aria-pressed', on);
  if (on) scrollTerm();
}
followBtn.addEventListener('click', () => setFollow(!follow));
// Scrolling up unpins; scrolling back to the bottom re-pins.
term.addEventListener('wheel', () => requestAnimationFrame(() => setFollow(term.scrollHeight - term.scrollTop - term.clientHeight < 8)));
function scrollTerm() {
  if (follow) term.scrollTop = term.scrollHeight;
}
const clock = (t) => new Date(t).toTimeString().slice(0, 8) + '.' + String(t % 1000).padStart(3, '0');
feed.addEventListener('log', ({ detail: l }) => {
  counts[l.src]++;
  $(`.chip[data-src="${l.src}"] span`).textContent = fmt(counts[l.src]);
  const li = document.createElement('li');
  li.className = `ln src-${l.src} lv-${l.level}`;
  li.innerHTML = `<time>${clock(l.t)}</time><b>${l.src}</b><span>${esc(l.msg)}</span>`;
  term.append(li);
  while (term.children.length > 600) term.firstElementChild.remove();
  scrollTerm();
});

// ---------- System stats ----------
function spark(id, data, max) {
  const m = max ?? Math.max(...data, 1) * 1.15;
  $(id).setAttribute('points', data.map((v, i) => `${(i / 59) * 120},${32 - (v / m) * 30}`).join(' '));
}
function renderStats() {
  const s = state.stats;
  $('#g-cpu').textContent = `${s.cpu.toFixed(1)}%`;
  $('#g-mem').textContent = `${s.mem.toFixed(0)}%`;
  $('#g-eps').textContent = fmt(s.eps);
  $('#k-lag').textContent = `${s.lag} ms`;
  $('#k-drop').textContent = fmt(s.dropped);
  $('#k-gap').textContent = fmt(s.gaps);
  spark('#sp-cpu', state.history.cpu, 100);
  spark('#sp-mem', state.history.mem, 100);
  spark('#sp-eps', state.history.eps);

  $('#peers').innerHTML = state.devices
    .map((d) => `<tr><td>${esc(d.name)}${d.id === state.self ? ' <em>self</em>' : ''}</td><td><code>${short(d.pubkey)}</code></td><td><span class="st" data-s="${d.status}">${d.status}</span></td><td>${((Date.now() - d.heartbeat) / 1000).toFixed(1)}s</td></tr>`)
    .join('');
}

function renderLedger() {
  $('#ledger').innerHTML = state.blocks
    .slice(-14)
    .reverse()
    .map((b) => `<tr class="${b.mine ? 'mine' : ''}"><td>${fmt(b.slot)}</td><td><span class="ix ix-${b.kind}">${b.kind}</span></td><td><code>${short(b.threat)}</code></td><td><code>${short(b.gene)}</code></td><td><code>${short(b.sig)}</code></td></tr>`)
    .join('');
}

// ---------- Threat response: time to immunity, lineage tree, allele search, suppress ----------
const STEPS = [['detect', 'Frozen'], ['gene', 'Cure evolved'], ['regress', 'Apps checked'], ['commit', 'On chain'], ['immune', 'Home immune']];
const ACT_LABEL = { ExecFromTempOrCache: 'Ran from a temp folder', RecoverySnapshotTamper: 'Deleted backups', RapidFileModBurst: 'Mass file rewrite' };
const base = (p) => p.split('/').pop();
const sign = (n) => (n >= 0 ? `+${n}` : `${n}`);
const alleleNames = (mask) => ALLELES.filter((_, i) => mask & (1 << i)).map((a) => a.label);
const watchText = (ms) => `${String(Math.floor(ms / 60000)).padStart(2, '0')}:${((ms / 1000) % 60).toFixed(2).padStart(5, '0')}`;

let watchRaf = 0;
function tick() {
  const inc = state.incident;
  $('#watch').textContent = watchText((inc.marks.immune ?? Date.now()) - inc.t0);
  if (!inc.marks.immune) watchRaf = requestAnimationFrame(tick);
}

const node = (id, title, sub, cls = '') => `<button class="node ${cls}" data-node="${id}"><span>${esc(title)}</span><small>${sub}</small></button>`;
function renderIncident() {
  const inc = state.incident;
  $('#inject').disabled = !!inc && !inc.done;
  if (!inc) {
    $('#inc-body').innerHTML = '<p class="empty">No threats yet. Scout is watching every process on this network. Run a test threat to see the full response.</p>';
    return;
  }
  cancelAnimationFrame(watchRaf);
  tick();
  $('.inc').dataset.live = inc.marks.immune ? 'done' : 'on';
  $('#tti').innerHTML = STEPS.map(([k, label]) => `<li class="${inc.marks[k] ? 'on' : ''}"><span>${label}</span><b>${inc.marks[k] ? `+${((inc.marks[k] - inc.t0) / 1000).toFixed(2)}s` : '—'}</b></li>`).join('');

  const { parent: p, child: c, acts } = inc.tree;
  const tree = `<div class="tree">
    ${node('parent', base(p.exe), `pid ${p.pid}`)}<i class="edge"></i>
    ${node('child', base(c.exe), `pid ${c.pid}, score ${inc.score}/100`, 'is-threat')}<i class="edge"></i>
    <ul class="acts">${acts.map((a, i) => `<li>${node(i, ACT_LABEL[a.action], `+${a.weight} ${a.attack}`, 'is-act')}</li>`).join('')}${acts.length < 3 ? '<li class="wait">watching…</li>' : ''}</ul>
  </div>`;

  const S = inc.search;
  let search = '<p class="al-sum">The cure search starts once the threat is frozen.</p>';
  if (S) {
    const searching = !inc.gene;
    const cls = (m, r) => {
      if (m >= S.tested) return m & (1 << r) ? 'c b' : 'c';
      const st = m === S.best ? 'best' : searching && m === S.tested - 1 ? 'cur' : 'no';
      return `c ${m & (1 << r) ? 'b' : ''} ${st}`;
    };
    const e = evaluate(S.best, inc.actions);
    search = `<div class="alleles" role="img" aria-label="Allele combinations tested: ${S.tested} of 32">
      ${ALLELES.map((a, r) => `<span class="al-name">${a.label}<em>${a.cost}</em></span>${Array.from({ length: 32 }, (_, m) => `<i class="${cls(m, r)}"></i>`).join('')}`).join('')}
    </div>
    <p class="al-sum">${searching ? `Testing ${S.tested} of 32 combinations. Best so far: ` : 'Winner: '}<b>${alleleNames(S.best).join(' + ') || 'none'}</b>, fitness ${sign(e.fitness)} (stops ${e.containment} pts, costs ${e.cost})${inc.gene ? `, gene <code>${short(inc.gene)}</code>` : ''}</p>`;
  }

  let foot = '';
  if (inc.suppress?.done) foot = '<p class="sup-done">Cure turned off on every device. Epigenetic_Status is now suppressed, so no node will run it.</p>';
  else if (inc.suppress) foot = `<p class="sup-wait">Turning off the cure: ${inc.suppress.sigs} of 3 signatures</p>`;
  else if (inc.marks.commit) foot = '<button class="btn-ghost" id="suppress">Turn off this cure</button><p>Use this if the cure breaks a legitimate app. It needs 3 of 5 signatures.</p>';

  $('#inc-body').innerHTML = `${tree}<h3>Cure search</h3>${search}<div class="inc-foot">${foot}</div>`;
  if (inspecting && inspecting.inc !== inc) closeInspect();
}

let inspecting = null;
function closeInspect() {
  inspecting = null;
  $('#inspect').hidden = true;
}
$('#inspect-x').addEventListener('click', closeInspect);
$('#inject').addEventListener('click', inject);
$('#inc-body').addEventListener('click', (e) => {
  if (e.target.closest('#suppress')) return suppress();
  const b = e.target.closest('[data-node]');
  if (!b) return;
  const inc = state.incident;
  const id = b.dataset.node;
  const n = id === 'parent' ? inc.tree.parent : id === 'child' ? inc.tree.child : inc.tree.acts[+id];
  let title, note;
  if (id === 'parent') [title, note] = [base(n.exe), 'Parent process. It started the flagged program, but its own behaviour scored nothing.'];
  else if (id === 'child') [title, note] = [base(n.exe), 'Root of the flagged lineage. Everything it and its children do adds to one score, and Scout freezes it (SIGSTOP) at 100.'];
  else {
    const stops = inc.gene ? alleleNames(inc.search.best).filter((l) => ALLELES.find((a) => a.label === l).stops.includes(n.action)) : [];
    title = `${n.action} (+${n.weight}, ${n.attack})`;
    note = inc.gene ? `Neutralised by: ${stops.join(', ') || 'nothing in the winning cure'}.` : 'Waiting for the cure search to pick alleles.';
  }
  inspecting = { inc };
  $('#inspect-title').textContent = title;
  $('#inspect-note').textContent = note;
  $('#inspect-json').textContent = JSON.stringify(n.tes, null, 2).replace(/"(ts_ns|recv_ns)": "(\d+)"/g, '"$1": $2');
  $('#inspect').hidden = false;
});
addEventListener('keydown', (e) => e.key === 'Escape' && closeInspect());

// ---------- Wiring ----------
feed.addEventListener('devices', () => {
  mesh.update(state.devices);
  renderHealth();
});
feed.addEventListener('incident', ({ detail }) => {
  phase = detail.phase === 'clear' ? 'clean' : detail.phase;
  renderHealth();
});
feed.addEventListener('mesh', ({ detail }) => mesh.propagate(detail.from, detail.to));
feed.addEventListener('genes', () => {
  helix.add(state.genes.at(-1).gene);
  renderHealth();
});
feed.addEventListener('block', ({ detail }) => {
  if (detail.mine) renderContrib();
  renderLedger();
renderIncident();
});
feed.addEventListener('stats', renderStats);
feed.addEventListener('threat', () => {
  renderIncident();
  renderHealth();
});
setInterval(() => document.querySelectorAll('time[data-t]').forEach((t) => (t.textContent = ago(+t.dataset.t))), 5000);

renderHealth();
renderContrib();
renderStats();
renderLedger();
renderIncident();
