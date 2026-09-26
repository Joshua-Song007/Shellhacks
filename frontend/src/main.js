import gsap from 'gsap';
import { feed, state } from './data.js';
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
    if (!reduced) gsap.from(show.children, { opacity: 0, y: 10, duration: 0.5, ease: 'power3.out', stagger: 0.04 });
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
  cured: (d) => ['Fixed. Your devices are immune.', `The cure found on ${d} was shared with your other devices, so this threat can’t hurt them.`],
};
let phase = 'clean';
function renderHealth() {
  const safe = state.devices.filter((d) => d.status === 'clean' || d.status === 'cured').length;
  state.devices.forEach((d, i) => {
    gsap.to(segs[i].c, { stroke: COLOR[d.status], color: COLOR[d.status], duration: 0.6 });
    segs[i].t.textContent = `${d.name}: ${LABEL[d.status]}`;
  });
  const inc = state.incident;
  const [title, sub] = COPY[phase](inc ? nameOf(inc.device) : '', inc?.threat ?? '');
  const h = $('#health-title');
  if (h.textContent !== title) {
    h.textContent = title;
    $('#health-sub').textContent = sub;
    if (!reduced) gsap.from(['#health-title', '#health-sub'], { opacity: 0, y: 8, duration: 0.5, ease: 'power3.out', stagger: 0.06 });
  }
  $('.health').dataset.s = phase;
  $('#f-safe').textContent = `${safe} of ${state.devices.length}`;
  $('#f-stopped').textContent = state.stoppedThisWeek;
  $('#f-cures').textContent = state.genes.length;
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
  tilt: Math.PI / 2,
  bg: 0x060a16,
  length: 0.8,
  thickness: 0.34,
  reduced,
  onHover(h) {
    probe.classList.toggle('on', !!h);
    if (!h) return (probeI = -1);
    probe.style.transform = `translate(${h.x}px, ${h.y}px)`;
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
          (b) => `<li class="${b.kind === 'commit_gene' ? 'is-cure' : 'is-report'}">
            <span class="c-icon" aria-hidden="true"></span>
            <div><strong>${b.kind === 'commit_gene' ? 'Shared a cure' : 'Reported a new threat'}</strong>
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

  $('#lineages').innerHTML = state.lineages.length
    ? state.lineages
        .map(
          (l) => `<li><div><code>${l.pid}</code><span>${esc(l.exe)}</span></div>
          <div class="bar-track"><i style="--p:${Math.min(1, l.score / 100)}"></i></div><b>${l.score}</b>
          <p>${l.actions.join(' → ') || 'no Stage-1 actions yet'}</p></li>`,
        )
        .join('')
    : '<li class="empty">No lineage above 0. Scout is idle.</li>';

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
});
feed.addEventListener('stats', renderStats);
setInterval(() => document.querySelectorAll('time[data-t]').forEach((t) => (t.textContent = ago(+t.dataset.t))), 5000);

renderHealth();
renderContrib();
renderStats();
renderLedger();
