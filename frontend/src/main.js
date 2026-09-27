import gsap from 'gsap';
import { feed, state, inject, clearIncident, suppress, ALLELES, ACT_LABEL, ATTACK, THREATS, evaluate, startPairing, cancelPairing, revoke, joinByUri, getReview, watchingLineages, pauseLineage, resumeLineage, escalateLineage, dismissLineage, clearLocalGenome } from './data.js';
import QRCode from 'qrcode';
import { createHelix } from './helix.js';
import { createMesh, LABEL, GLYPH } from './mesh.js';
import { createAdvisorAvatar } from './advisor.js';

const $ = (s, r = document) => r.querySelector(s);
const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;
const fmt = (n) => n.toLocaleString('en-US');
const short = (h) => (h ? `${h.slice(0, 6)}…${h.slice(-4)}` : '—');
const nameOf = (id) => state.devices.find((d) => d.id === id)?.name ?? 'Another network';
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => `&#${c.charCodeAt(0)};`);
const COLOR = { clean: '#4ff5d2', watching: '#ffc46b', isolated: '#ff3b5c', cured: '#8f7bff' };

// state.source is set once, synchronously, before this module's top-level code runs.
const sourceBadge = $('#source-badge');
sourceBadge.hidden = false;
sourceBadge.textContent = state.source === 'live' ? 'Live' : 'Simulated';
sourceBadge.dataset.source = state.source;

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
let segs = [];
// Rebuilt whenever a device joins, so there is always one segment per device.
function buildRing() {
  $('#ring-segs').replaceChildren();
  segs = state.devices.map((d, i) => {
    // A lone device gets a full ring: gaps (the seams) only mean something between devices.
    const gap = state.devices.length > 1 ? 5 : 0;
    const len = C / state.devices.length - gap;
    const c = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    Object.entries({ cx: 130, cy: 130, r: R, 'stroke-dasharray': `${len} ${C - len}`, 'stroke-dashoffset': -(i * C) / state.devices.length - gap / 2 }).forEach(([k, v]) => c.setAttribute(k, v));
    if (!gap) c.removeAttribute('stroke-dasharray');
    c.style.stroke = c.style.color = COLOR[d.status];
    $('#ring-segs').append(c);
    const t = document.createElementNS('http://www.w3.org/2000/svg', 'title');
    c.append(t);
    return { c, t };
  });
}
buildRing();
if (!reduced) gsap.to('.ring-orbit', { rotation: 360, svgOrigin: '130 130', duration: 90, repeat: -1, ease: 'none' });

const COPY = {
  clean: () => ["Everything's safe", 'T-Cell is watching every device on your home network. Nothing needs your attention.'],
  watching: (d) => [`Checking something on ${d}`, 'A program is acting unusually. T-Cell is keeping a close eye on it. You don’t need to do anything.'],
  isolated: (d, t) => [`Threat paused on ${d}`, `Something that behaves like ${t.toLowerCase()} tried to run. T-Cell froze it before it could do damage and is building a cure.`],
  cured: (d, t, tti) => ['Fixed. Your devices are immune.', `Found, frozen and fixed in ${tti} seconds. The cure found on ${d} was shared with your other devices, so this threat can’t hurt them.`],
};
let phase = 'clean';
function renderHealth() {
  if (segs.length !== state.devices.length) buildRing();
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
  $('#live-text').textContent = phase === 'clean' ? `Protecting ${state.devices.length} device${state.devices.length === 1 ? '' : 's'}` : LABEL[phase === 'cured' ? 'cured' : phase];
  document.body.dataset.alert = phase;
  avatar.setMood(phase);
}

// ---------- Advisor (weekly review + incident notes from advisor-service) ----------
const avatar = createAdvisorAvatar($('#advisor-gl'), { reduced });
const reviewPop = $('#review');
const say = (text) => ($('#advisor-say').textContent = text);
const unread = (on) => ($('#advisor-dot').hidden = !on);

async function loadReview(force = false) {
  reviewPop.dataset.busy = '';
  if (force) say('Looking over your week…');
  const r = await getReview(force);
  delete reviewPop.dataset.busy;
  if (!r) {
    say('Weekly reviews need the advisor. It isn’t connected.');
    $('#review-head').textContent = 'The advisor isn’t connected, so there’s no weekly review yet.';
    $('#review-tips').replaceChildren();
    $('#review-when').textContent = 'Set TCELL_ADVISOR_URL to turn it on';
    $('#review-again').hidden = true;
    return;
  }
  if (r.error) {
    say('Couldn’t reach the advisor. Click me to try again.');
    $('#review-head').textContent = 'Couldn’t reach the advisor to review your week.';
    $('#review-tips').replaceChildren();
    $('#review-when').textContent = 'Your devices are still protected';
    return;
  }
  say(force ? 'Your review is updated. Click me to read it.' : 'Your weekly review is ready. Click me to read it.');
  $('#review-head').textContent = r.review.headline;
  $('#review-tips').replaceChildren(...r.review.tips.map((t) => Object.assign(document.createElement('li'), { textContent: t })));
  $('#review-when').innerHTML = `Reviewed <time data-t="${r.at}">${ago(r.at)}</time>`;
  unread(true);
  avatar.nudge();
}

$('#advisor-btn').addEventListener('click', (e) => {
  if (!avatar.takeClick()) return e.preventDefault(); // that was a drag, not a tap
  avatar.hop();
});
reviewPop.addEventListener('toggle', (e) => {
  $('#advisor-btn').setAttribute('aria-expanded', e.newState === 'open');
  if (e.newState === 'open') {
    unread(false);
    say('Click me any time for your weekly review.');
  }
});
$('#review-again').addEventListener('click', () => loadReview(true));
feed.addEventListener('advice', ({ detail }) => {
  $('#review-note-text').textContent = detail.narration;
  $('#review-note').hidden = false;
  say('I have a note about the threat I just saw.');
  unread(true);
  avatar.nudge();
});

// ---------- Mesh ----------
const mesh = createMesh($('#mesh'), state.devices, state.self, { reduced, onPick: (id) => showDevice(id) });

// ---------- Add / remove trusted devices (FR-M-1 pairing, FR-M-7 revocation) ----------
const pairDlg = $('#pair');
let pairTimer = 0;
let pairBar = null;
let removing = null;
let viewing = null; // device whose details are open, kept fresh as its status changes
function pairStep(step) {
  pairDlg.querySelectorAll('.pair-step').forEach((s) => (s.hidden = s.dataset.step !== step));
  const shown = pairDlg.querySelector(`[data-step="${step}"]`);
  if (!reduced) gsap.fromTo(shown.children, { opacity: 0, y: 8 }, { opacity: 1, y: 0, duration: 0.45, ease: 'power3.out', stagger: 0.05, overwrite: true });
  shown.querySelector('footer .btn, footer button')?.focus();
}
function stopPairClock() {
  clearInterval(pairTimer);
  pairBar?.kill();
}
function openDialog(step) {
  pairDlg.showModal();
  if (!reduced) gsap.fromTo(pairDlg, { opacity: 0, scale: 0.96, y: 10 }, { opacity: 1, scale: 1, y: 0, duration: 0.45, ease: 'expo.out' });
  pairStep(step);
}
async function beginPairing() {
  $('#show-join').hidden = state.source !== 'live'; // no real peer to join against in simulated mode
  const code = await startPairing();
  // Light modules on dark: phone cameras read either, and this keeps the panel from flashing white.
  $('#pair-qr').innerHTML = await QRCode.toString(code.uri, { type: 'svg', margin: 0, errorCorrectionLevel: 'M', color: { dark: '#e6eef0', light: '#0000' } });
  // Live joins need the whole link (it carries this device's address), not just the nonce.
  $('#pair-hex').textContent = state.source === 'live' ? code.uri : code.nonce.match(/.{4}/g).join(' ');
  $('#pair-copy').textContent = 'Copy';
  stopPairClock();
  const left = () => {
    const s = Math.max(0, Math.ceil((code.expires - Date.now()) / 1000));
    $('#pair-left').textContent = `Expires in ${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;
  };
  left();
  pairTimer = setInterval(left, 1000);
  pairBar = gsap.fromTo('#pair-bar', { scaleX: 1 }, { scaleX: 0, duration: (code.expires - Date.now()) / 1000, ease: 'none' });
  pairStep('code');
  if (!reduced) gsap.fromTo('#pair-qr svg', { opacity: 0, scale: 0.9, filter: 'blur(6px)' }, { opacity: 1, scale: 1, filter: 'blur(0px)', duration: 0.7, ease: 'expo.out', delay: 0.1 });
}
function closePairing() {
  stopPairClock();
  cancelPairing();
  removing = null;
  viewing = null;
  $('#join-uri').value = '';
  $('#join-wait').hidden = true;
  if (!pairDlg.open) return;
  if (reduced) return pairDlg.close();
  gsap.to(pairDlg, { opacity: 0, scale: 0.97, duration: 0.2, ease: 'power2.in', onComplete: () => (pairDlg.close(), gsap.set(pairDlg, { clearProps: 'opacity,scale' })) });
}
$('#add-device').addEventListener('click', () => (openDialog('code'), beginPairing()));
pairDlg.addEventListener('cancel', (e) => (e.preventDefault(), closePairing())); // Esc
pairDlg.addEventListener('click', (e) => {
  if (e.target === pairDlg) return closePairing(); // backdrop
  const act = e.target.closest('[data-act]')?.dataset.act;
  if (act === 'cancel') closePairing();
  if (act === 'restart') beginPairing();
  if (act === 'copy') navigator.clipboard?.writeText($('#pair-hex').textContent.replace(/ /g, '')).then(() => ($('#pair-copy').textContent = 'Copied'));
  if (act === 'show-join') pairStep('join');
  if (act === 'paste') navigator.clipboard?.readText().then((t) => ($('#join-uri').value = t.trim()));
  if (act === 'join') {
    const uri = $('#join-uri').value.trim();
    if (!uri) return;
    stopPairClock();
    $('#join-wait').hidden = false;
    joinByUri(uri);
    // meshd reports an unreachable address only after the OS connect timeout; don't leave the dialog hanging that long.
    clearTimeout(joinTimer);
    joinTimer = setTimeout(() => pairDlg.open && !$('#join-wait').hidden && feed.dispatchEvent(new CustomEvent('pair', { detail: { phase: 'error', error: 'unreachable' } })), 15000);
  }
  if (act === 'ask-remove') askRemove(viewing);
  if (act === 'copy-id') {
    navigator.clipboard?.writeText(e.target.dataset.id);
    e.target.textContent = 'Copied';
  }
  if (act === 'revoke') {
    revoke(removing);
    closePairing();
  }
});
let joinTimer;
const FAIL = {
  expired: ['This code expired', "Codes last 5 minutes so an old one can't be reused. Get a new code and try again."],
  Expired: ['This code expired', "The device used the code after it ran out. Get a new code and try again."],
  NonceMismatch: ['That code didn’t match', 'A device presented a different code and was refused. Get a new code and scan it again.'],
  unreachable: ['Couldn’t reach that device', 'Both devices need to be on the same network, and some campus or public Wi-Fi blocks devices from talking to each other. Try a phone hotspot.'],
  'malformed uri': ['That isn’t a pairing link', 'Paste the whole link that starts with tcell://pair from the other device.'],
};
feed.addEventListener('pair', ({ detail }) => {
  if (!pairDlg.open || removing || viewing) return;
  stopPairClock();
  clearTimeout(joinTimer);
  if (detail.phase === 'paired') {
    $('#pair-done').textContent = `${detail.device.name} joined`;
    $('#pair-glyph').setAttribute('d', GLYPH[detail.device.kind]);
    return pairStep('paired');
  }
  const [title, body] = FAIL[detail.error ?? 'expired'] ?? ['Couldn’t pair', `${detail.error}. Get a new code and try again.`];
  $('#pair-fail-title').textContent = title;
  $('#pair-fail').textContent = body;
  pairStep('failed');
});
function askRemove(id) {
  const d = state.devices.find((x) => x.id === id);
  if (!d || (d.status !== 'clean' && d.status !== 'cured')) return; // not while it's mid-response
  removing = id;
  viewing = null;
  $('#rm-title').textContent = `Remove ${d.name}?`;
  if (pairDlg.open) pairStep('remove');
  else openDialog('remove');
}

// Device details: how it's doing in plain words, what it has done for the network, and its identity.
const DEV_SAY = {
  clean: 'Safe. It’s watching for threats and passes any cure it learns to your other devices.',
  watching: 'Something on it is acting suspiciously. T-Cell is keeping score and will freeze it if it crosses the line. No action needed.',
  isolated: 'It froze a threat before it could do damage and is building a cure. No action needed.',
  cured: 'It stopped a threat and shared the cure, so your other devices are protected too.',
};
function fillDevice() {
  const d = state.devices.find((x) => x.id === viewing);
  if (!d) return closePairing(); // removed while open
  const self = d.id === state.self;
  const inc = state.incident && !state.incident.done && state.incident.device === d.id ? state.incident : null;
  $('#dev-glyph').setAttribute('d', GLYPH[d.kind]);
  $('#dev-name').textContent = self ? `${d.name} (you)` : d.name;
  $('.dev-head').dataset.s = d.status; // colours the icon ring and the status line
  $('#dev-status b').textContent = LABEL[d.status];
  $('#dev-say').textContent = DEV_SAY[d.status];
  const row = (label, value) => `<div><dt>${label}</dt><dd>${value}</dd></div>`;
  $('#dev-facts').innerHTML = [
    inc && row('Current threat', esc(inc.threat)),
    row('Last heard from', self ? 'Now' : ago(d.heartbeat)),
    self && row('Cures it carries', fmt(state.genes.filter((g) => !g.suppressed).length)),
    row(self ? 'Cures it found' : 'Cures it shared', fmt(state.genes.filter((g) => g.from === d.id).length)),
    self && row('Blocks it wrote', fmt(state.contributions.length)),
    d.pubkey && row('Device ID', `<code title="${d.pubkey}">${short(d.pubkey.slice(8))}</code><button class="c-copy" data-act="copy-id" data-id="${d.pubkey}">Copy</button>`),
  ]
    .filter(Boolean)
    .join('');
  const rm = $('#dev-remove');
  rm.hidden = self; // this device can't leave its own network
  rm.disabled = d.status === 'watching' || d.status === 'isolated';
  rm.title = rm.disabled ? 'Wait until it has finished dealing with the threat' : '';
}
function showDevice(id) {
  viewing = id;
  fillDevice();
  if (pairDlg.open) pairStep('device');
  else openDialog('device');
}

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
  glow: 0.35,
  edgeScroll: true,
  visible: 14,
  onSelect: (h) => openGenome(state.genes[h.index]),
  onHover(h) {
    probe.classList.toggle('on', !!h);
    if (!h) return (probeI = -1);
    // Narrow column: keep the card inside the box instead of clipping off the right edge.
    probe.style.transform = `translate(${Math.min(h.x, probe.parentElement.clientWidth - probe.offsetWidth - 28)}px, ${h.y}px)`;
    if (h.index === probeI) return;
    probeI = h.index;
    const g = state.genes[h.index];
    $('strong', probe).textContent = g.name;
    $('span', probe).textContent = `${g.from === state.self ? 'Found by this device' : g.from === 'network' ? 'Learned from the network' : `Shared by ${nameOf(g.from)}`}, ${ago(g.time)}`;
  },
});
// With a cure, the genome window scrolls to it and opens its details.
function openGenome(g) {
  const pick = g && { gene: g.gene, name: g.name, threat: g.threat, time: g.time, bytes: g.bytes };
  if (window.tcell) window.tcell.openGenome(pick);
  else open(`genome.html${pick ? `#${encodeURIComponent(JSON.stringify(pick))}` : ''}`, 'genome', 'width=1100,height=760');
}
$('#open-genome').addEventListener('click', () => openGenome());

// ---------- Contributions ----------
function renderContrib() {
  const list = state.contributions;
  const cures = list.filter((b) => b.kind === 'commit_gene').length;
  $('#contrib-sub').textContent = list.length
    ? `This device has written ${list.length} ${list.length === 1 ? 'block' : 'blocks'} to the shared chain${cures ? `, including ${cures} ${cures === 1 ? 'cure' : 'cures'} other people now use` : ''}.`
    : '';
  const opened = new Set([...$('#contrib-list').querySelectorAll('details[open]')].map((d) => d.dataset.sig)); // a re-render must not snap an open row shut
  $('#contrib-list').innerHTML = list.length
    ? list
        .map(
          (b) => `<li class="${{ commit_gene: 'is-cure', suppress_gene: 'is-off' }[b.kind] ?? 'is-report'}"><details data-sig="${b.sig}"${opened.has(b.sig) ? ' open' : ''}>
            <summary>
              <span class="c-icon" aria-hidden="true"></span>
              <div><strong>${{ commit_gene: 'Shared a cure', suppress_gene: 'Turned off a cure' }[b.kind] ?? 'Reported a new threat'}</strong>
              <span>${esc(b.name ?? 'Unknown threat')}</span></div>
              <div class="c-meta"><span>Block ${fmt(b.slot)}</span><time data-t="${b.time}">${ago(b.time)}</time></div>
              <svg class="c-chev" viewBox="0 0 20 20" aria-hidden="true"><path d="M6 8l4 4 4-4" /></svg>
            </summary>
            ${contribBody(b)}
          </details></li>`,
        )
        .join('')
    : `<li class="empty">Nothing yet. When this device is the first to catch a threat, the cure it writes to the chain shows up here.</li>`;
}

// Expanded row: what the block did in plain words, then the receipts to prove it.
function contribBody(b) {
  const name = esc(b.name ?? 'this threat');
  const say = {
    commit_gene: `This device caught ${name} first, built a cure, and wrote it to the shared chain. Every T-Cell device can now use it without ever meeting the threat.`,
    suppress_gene: `This device helped turn off the cure for ${name}. Devices stop using it as soon as they see this block.`,
  }[b.kind] ?? `This device reported ${name} to the shared chain. Each independent report makes the network more confident the threat is real.`;
  const acts = THREATS.find((t) => t.name === b.name)?.actions; // live blocks may carry a name the sim catalogue doesn't know; then there's nothing honest to list
  const id = (label, v) => (v ? `<div><dt>${label}</dt><dd><code title="${v}">${v.slice(0, 8)}…${v.slice(-6)}</code><button class="c-copy" data-copy="${v}">Copy</button></dd></div>` : '');
  return `<div class="c-body">
    <p>${say}</p>
    ${acts && b.kind !== 'suppress_gene' ? `<ul class="c-acts" aria-label="${b.kind === 'commit_gene' ? 'What the cure stops' : 'What it was seen doing'}">${acts.map((a) => `<li><span>${ACT_LABEL[a]}</span><code>${ATTACK[a]}</code></li>`).join('')}</ul>` : ''}
    ${b.signers ? `<div class="d-proof c-proof"><span>${Array.from({ length: 5 }, (_, i) => `<i class="${i < b.signers ? 'on' : ''}"></i>`).join('')}</span><p>${b.signers} of 5 nodes re-ran it and signed</p></div>` : ''}
    <dl class="c-ids">
      <div><dt>Written</dt><dd>${new Date(b.time).toLocaleString('en-US', { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' })}, block ${fmt(b.slot)}</dd></div>
      ${id('Receipt', b.sig)}${id('Threat ID', b.threat)}${id('Cure', b.gene)}
    </dl>
    ${b.kind === 'commit_gene' ? `<button class="btn-quiet c-open" data-act="genome" data-sig="${b.sig}">Show in the global genome</button>` : ''}
  </div>`;
}
$('#contrib-list').addEventListener('click', (e) => {
  const copy = e.target.closest('[data-copy]');
  if (copy) {
    navigator.clipboard?.writeText(copy.dataset.copy);
    copy.textContent = 'Copied';
    setTimeout(() => (copy.textContent = 'Copy'), 1400);
  }
  const go = e.target.closest('[data-act="genome"]');
  if (go) openGenome(state.contributions.find((b) => b.sig === go.dataset.sig));
});

// ---------- Terminal ----------
const term = $('#term');
const SRC = ['tes', 'scout', 'soldier', 'ledger', 'mesh', 'advisor'];
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
  followBtn.textContent = `Tracking: ${on ? 'ON' : 'OFF'}`;
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
  $('#k-rej').textContent = fmt(s.rejected);
  $('#k-src').textContent = s.source;
  $('#k-gap').textContent = fmt(s.gaps);
  spark('#sp-cpu', state.history.cpu, 100);
  spark('#sp-mem', state.history.mem, 100);
  spark('#sp-eps', state.history.eps);

  $('#peers').innerHTML = state.devices
    .map((d) => `<tr><td>${esc(d.name)}${d.id === state.self ? ' <em>self</em>' : ''}</td><td><code>${short(d.pubkey)}</code></td><td><span class="st" data-s="${d.status}">${d.status}</span></td><td>${d.id === state.self ? 'now' : `${((Date.now() - d.heartbeat) / 1000).toFixed(1)}s ago`}</td></tr>`)
    .join('');
}

function renderLedger() {
  $('#ledger').innerHTML = state.blocks
    .slice(-14)
    .reverse()
    .map((b) => `<tr class="${b.mine ? 'mine' : ''}"><td>${b.slot ? fmt(b.slot) : '—'}</td><td><span class="ix ix-${b.kind}">${b.kind}</span></td><td><code>${short(b.threat)}</code></td><td><code>${short(b.gene)}</code></td><td><code>${short(b.sig)}</code></td></tr>`)
    .join('');
}

// ---------- Threat response: time to immunity, lineage tree, allele search, suppress ----------
const STEPS = [['detect', 'Frozen'], ['gene', 'Cure evolved'], ['regress', 'Apps checked'], ['commit', 'On chain'], ['immune', 'Home immune']];
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
  // NOT `!inc.done`: under a live eslogger Scout, ordinary background macOS
  // activity (e.g. Spotlight/Biome agents) routinely trips a partial,
  // never-convicted Stage-1 score, which claims state.incident (liveIncidentFor,
  // data.js) and then never reaches `done` -- that permanently disabled this
  // button. Only a real conviction (marks.detect, set solely on an actual
  // Detection/SIGSTOP+wake, both here and in the simulated path) that hasn't
  // yet finished should block starting a new test.
  const finished = !!inc && (inc.done || !!inc.marks.immune);
  const busy = !!inc && !!inc.marks.detect && !finished;
  const injectBtn = $('#inject');
  injectBtn.disabled = busy;
  // A second test on top of an already-finished one was never a planned
  // flow (nothing here resets a finished incident's own search/marks state
  // for reuse) -- once done, the button becomes an explicit dismiss instead
  // of silently starting another run over it.
  injectBtn.textContent = finished ? 'Clear test' : 'Run test threat';
  if (!inc) {
    // clearIncident() nulls state.incident, but this branch used to only ever
    // touch #inc-body -- #watch (timer), #tti (the step bar), and .inc's
    // data-live (bar color) live OUTSIDE inc-body and were left showing the
    // just-finished incident's stale values forever. Also cancel any pending
    // watchRaf: a not-yet-`immune` incident (e.g. the `suppressed`/refused
    // path, which sets `done` without ever setting `marks.immune`) leaves
    // tick() still scheduled, and the next frame would read state.incident
    // (now null) and throw.
    cancelAnimationFrame(watchRaf);
    delete $('.inc').dataset.live;
    $('#watch').textContent = '00:00.00';
    $('#tti').innerHTML = STEPS.map(([, label]) => `<li><span>${label}</span><b>—</b></li>`).join('');
    $('#inc-body').innerHTML = '<p class="empty">No threats yet. Scout is watching every process on this network. Run a test threat to see the full response.</p>';
    if (inspecting) closeInspect(); // the inspect popout shows a node from the now-cleared incident's tree
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
  if (inc.inheritedGene) {
    search = `<p class="al-sum">This cure was already known network-wide -- inherited gene <code>${short(inc.gene)}</code>, no local search needed.</p>`;
  } else if (S) {
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
$('#inject').addEventListener('click', () => {
  const inc = state.incident;
  if (inc && (inc.done || inc.marks.immune)) clearIncident();
  else inject();
});
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

// Advanced-view-only visibility into background Scout activity: lineages
// currently accumulating a partial (never-convicted) score, distinct from
// the single Threat response panel above (which only ever shows one
// incident, and no longer even has to be hijacked by background noise to
// display it -- see data.js's liveIncidentFor/scheduleWatchingRevert notes).
// Membership is time-based (a lineage drops off once it's gone quiet), so
// this needs its own periodic re-render, not just an event-driven one.
// Human-in-the-loop: each row expands to what Scout actually saw, and lets
// the person Pause (SIGSTOP) -> Build a cure (real wake to Soldier) or
// Resume / Looks fine. Re-rendered only when the rows change, so an open row
// and a focused button survive the 2s membership tick.
const watchOpen = new Set();
const watchNote = new Map(); // key -> last pause/resume outcome, shown in the row
let watchSig = '';
function watchRow(r) {
  const tag = r.escalated ? '<em class="w-tag w-cure">Cure requested</em>' : r.paused ? '<em class="w-tag w-paused">Paused</em>' : '';
  const acts = r.acts.map((a) => `<li><span>${esc(ACT_LABEL[a.action] ?? a.action)}</span><b>+${a.weight}</b><code>${esc(a.attack)}</code><details><summary>Raw event</summary><pre>${esc(JSON.stringify(a.tes, null, 2))}</pre></details></li>`).join('');
  const cureHint = r.escalated ? 'Soldier is on it; follow along in Threat response.' : r.paused ? 'Build a cure sends this to Soldier as if Scout had convicted it, and publishes the cure to the network.' : 'Pause it first. Frozen processes can be resumed.';
  return `<li data-key="${esc(r.key)}"><details${watchOpen.has(r.key) ? ' open' : ''}>
    <summary><span class="w-name">${esc(base(r.exe))}</span>${tag}<i class="w-bar" style="--s:${Math.min(r.score, 100)}%"></i><b>${r.score}/100</b></summary>
    <div class="w-body">
      <p class="w-path">${esc(r.exe)} <span>pid ${r.pids.join(', ') || 'unknown'}, last activity <time data-t="${r.lastSeen}">${ago(r.lastSeen)}</time></span></p>
      <ul class="w-acts">${acts}</ul>
      <div class="w-do">
        ${r.paused ? '<button class="btn btn-sm btn-line" data-w="resume">Resume</button>' : '<button class="btn btn-sm btn-line" data-w="pause">Pause</button>'}
        <button class="btn btn-sm" data-w="cure"${r.paused && !r.escalated ? '' : ' disabled'}>Build a cure</button>
        ${r.paused ? '' : '<button class="btn-quiet" data-w="dismiss">Looks fine</button>'}
      </div>
      <p class="w-note">${esc(watchNote.get(r.key) ?? cureHint)}</p>
    </div></details></li>`;
}
function renderWatchlist() {
  const list = $('#watchlist');
  if (!list) return;
  const rows = watchingLineages();
  const sig = JSON.stringify(rows.map((r) => [r.key, r.score, r.acts.length, r.paused, r.escalated, watchNote.get(r.key)]));
  if (sig === watchSig) return;
  watchSig = sig;
  list.innerHTML = rows.length ? rows.map(watchRow).join('') : '<li class="empty">Nothing partially scoring right now.</li>';
}
$('#watchlist')?.addEventListener('toggle', (e) => {
  const key = e.target.closest('li[data-key]')?.dataset.key;
  if (!key || e.target.parentElement.dataset.key !== key) return; // ignore the nested "Raw event" toggles
  e.target.open ? watchOpen.add(key) : watchOpen.delete(key);
}, true);
$('#watchlist')?.addEventListener('click', async (e) => {
  const btn = e.target.closest('[data-w]');
  if (!btn) return;
  const key = btn.closest('li[data-key]').dataset.key;
  btn.disabled = true;
  const act = btn.dataset.w;
  try {
    if (act === 'dismiss') return dismissLineage(key);
    if (act === 'cure') return await escalateLineage(key);
    const results = await (act === 'pause' ? pauseLineage(key) : resumeLineage(key));
    const bad = results.filter((r) => !r.ok);
    if (bad.length) watchNote.set(key, `${act === 'pause' ? "Couldn't pause" : "Couldn't resume"} ${bad.map((r) => `pid ${r.pid} (${r.reason})`).join(', ')}.`);
    else watchNote.delete(key);
  } catch (err) {
    watchNote.set(key, `That didn't go through: ${err.message}`);
  } finally {
    watchSig = '';
    renderWatchlist();
  }
});

// ---------- Wiring ----------
feed.addEventListener('devices', () => {
  mesh.update(state.devices);
  renderHealth();
  if (viewing) fillDevice();
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
feed.addEventListener('genome-clear', () => {
  helix.clear();
  renderHealth();
});
$('#clear-genome').addEventListener('click', clearLocalGenome);
feed.addEventListener('block', ({ detail }) => {
  if (detail.mine) renderContrib();
  renderLedger();
renderIncident();
});
feed.addEventListener('stats', renderStats);
feed.addEventListener('threat', () => {
  renderIncident();
  renderHealth();
  renderWatchlist();
});
setInterval(() => document.querySelectorAll('time[data-t]').forEach((t) => (t.textContent = ago(+t.dataset.t))), 5000);
setInterval(renderWatchlist, 2000); // membership is time-based (quiet lineages drop off on their own), so this can't rely on events alone

renderHealth();
renderContrib();
renderStats();
renderLedger();
renderWatchlist();
renderIncident();
loadReview();
