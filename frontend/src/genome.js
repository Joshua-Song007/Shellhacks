import gsap from 'gsap';
import { feed, state, THREATS, ALLELES, WEIGHT, ATTACK, ACT_LABEL, evaluate } from './data.js';
import { createHelix } from './helix.js';
import { createAdvisorAvatar } from './advisor.js';

const $ = (s, r = document) => r.querySelector(s);
const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;
const fmt = (n) => n.toLocaleString('en-US');
const hex = (n) => Array.from(crypto.getRandomValues(new Uint8Array(n)), (b) => b.toString(16).padStart(2, '0')).join('');
const HOUR = 3_600_000;

// Same exhaustive 32-mask search the Soldier runs (allele_search.rs), so the panel shows the cure that would win.
function bestMask(actions) {
  let best = 0;
  for (let m = 1; m < 1 << ALLELES.length; m++) {
    const e = evaluate(m, actions);
    const b = evaluate(best, actions);
    if (e.fitness > b.fitness || (e.fitness === b.fitness && e.size < b.size)) best = m;
  }
  return best;
}

// Most recent global cures, oldest first. Seeded here; new ones arrive as commit_gene blocks.
const cure = (g) => {
  const t = THREATS.find((x) => x.name === g.name) ?? THREATS[0];
  return { threat: hex(32), time: Date.now(), bytes: 380 + ((Math.random() * 420) | 0), devices: 40 + ((Math.random() * 9000) | 0), actions: t.actions, mask: bestMask(t.actions), ...Object.fromEntries(Object.entries(g).filter(([, v]) => v !== undefined)) }; // a missing field (live genes have no bytes until the feed reports them) keeps its default
};
const genes = Array.from({ length: 56 }, (_, i) =>
  cure({
    gene: hex(32),
    name: THREATS[i % THREATS.length].name,
    slot: state.stats.slot - (56 - i) * 900,
    signers: 3 + (i % 3),
    time: Date.now() - (56 - i) * 2.7 * HOUR,
  }),
);
// This device's own immune memory is part of the global genome too, in time order, so clicking one in the main window finds it here.
const slotAt = (t) => state.stats.slot - Math.round(((Date.now() - t) / HOUR) * 333);
for (const g of state.genes) genes.push(cure({ gene: g.gene, name: g.name, threat: g.threat, time: g.time, bytes: g.bytes, slot: slotAt(g.time), signers: 4, devices: 1 }));
genes.sort((a, b) => a.time - b.time);

function ago(ms) {
  const m = Math.round((Date.now() - ms) / 60000);
  if (m < 1) return 'just now';
  if (m < 60) return `${m} min ago`;
  if (m < 1440) return `${Math.round(m / 60)} h ago`;
  const d = Math.round(m / 1440);
  return d === 1 ? 'yesterday' : `${d} days ago`;
}

const probe = $('#probe');
let probeI = -1;
const helix = createHelix($('#global-gl'), {
  hashes: genes.map((g) => g.gene),
  capacity: 120,
  length: 2.4,
  tilt: 0.38,
  bg: 0x02040b,
  particles: 1100,
  reduced,
  edgeScroll: true,
  visible: 56,
  edgeTop: 44, // macOS traffic lights (hiddenInset title bar) sit over the canvas; hovering them must not scroll
  onEdge: (e) => {
    $('.edge-cue.top').classList.toggle('on', e > 0);
    $('.edge-cue.bottom').classList.toggle('on', e < 0);
  },
  onSelect: (h) => select(h),
  onHover(h) {
    if (open >= 0) h = null; // the panel already says what this is; a second card over it names a neighbour
    probe.classList.toggle('on', !!h);
    if (!h) return (probeI = -1);
    probe.style.transform = `translate(${h.x}px, ${h.y}px)`;
    if (h.index === probeI) return;
    probeI = h.index;
    const g = genes[h.index];
    const [title, a, b] = probe.children;
    title.textContent = g.name;
    a.textContent = `gene 0x${g.gene.slice(0, 12)}, block ${fmt(g.slot)}`;
    b.textContent = 'Click for details';
  },
});

// ---------- Block details: the clicked block flies out to the side and opens into a panel ----------
const panel = $('#detail');
let open = -1;

function fill(g, color) {
  panel.style.setProperty('--k', color);
  $('#d-name').textContent = g.name;
  $('#d-when').textContent = `Committed ${ago(g.time)} in block ${fmt(g.slot)}`;
  $('#d-stops').innerHTML = g.actions.map((a) => `<li><span>${ACT_LABEL[a]}</span><code>${ATTACK[a]}</code><b>+${WEIGHT[a]}</b></li>`).join('');
  const e = evaluate(g.mask, g.actions);
  $('#d-cure').innerHTML = ALLELES.map((a, i) => `<li class="${g.mask & (1 << i) ? 'on' : ''}">${a.label}</li>`).join('');
  $('#d-fit').textContent = `Stops ${e.containment} of ${g.actions.reduce((n, a) => n + WEIGHT[a], 0)} threat points.`;
  $('#d-proof').innerHTML = Array.from({ length: 5 }, (_, i) => `<i class="${i < g.signers ? 'on' : ''}"></i>`).join('');
  $('#d-proof-t').textContent = `${g.signers} of 5 nodes re-ran the cure and signed it`;
  $('#d-devices').textContent = fmt(g.devices);
  $('#d-bytes').textContent = `${g.bytes} B`;
  $('#d-threat').textContent = `${g.threat.slice(0, 10)}…${g.threat.slice(-6)}`;
  $('#d-threat').title = g.threat;
  $('#d-gene').textContent = `${g.gene.slice(0, 10)}…${g.gene.slice(-6)}`;
  $('#d-gene').title = g.gene;
  tell(g);
}

// ---------- The advisor reads the open block out in plain words ----------
// Gemma writes it (advisor-service /v1/explain, cached per gene by backend.cjs). This template is the fallback when the
// advisor is off or unreachable, and the simulated/browser path, so the d20 always has something true to say.
const DID = {
  ExecFromTempOrCache: 'ran from a downloads folder',
  RapidFileModBurst: 'scrambled your files so they couldn’t be opened',
  RecoverySnapshotTamper: 'deleted your backups',
};
const FIX = {
  QuarantineDroppedFiles: 'locks away anything it dropped',
  BlockSockets: 'cuts it off the internet',
  SigStop: 'freezes it',
  RevertTouchedFiles: 'puts your files back',
  KillChildTree: 'shuts it down with everything it started',
};
const list = (xs) => (xs.length < 2 ? xs.join('') : `${xs.slice(0, -1).join(', ')}${xs.length > 2 ? ',' : ''} and ${xs.at(-1)}`);
function summary(g) {
  const fixes = ALLELES.filter((_, i) => g.mask & (1 << i)).map((a) => FIX[a.name]);
  return [
    `This block is a cure for ${g.name.toLowerCase()}: a program that ${list(g.actions.map((a) => DID[a]))}.`,
    fixes.length ? `The cure ${list(fixes)}.` : 'No cure was needed to stop it; the network just remembers it.',
    `${g.signers} of 5 checking computers tested it before it went live. ${fmt(g.devices)} ${g.devices === 1 ? 'device has' : 'devices have'} it now, and yours gets it automatically.`,
  ].join(' ');
}
const avatar = createAdvisorAvatar($('#d-avatar-gl'), { reduced });
const bubble = $('#d-say');
let told = null;
// Only derived, public-on-chain fields go to the model: names, ATT&CK ids, cure steps, counts.
async function explain(g) {
  if (g.explained) return g.explained;
  const cure = ALLELES.filter((_, i) => g.mask & (1 << i)).map((a) => a.name);
  const r = await window.tcell?.explainBlock?.({ gene: g.gene, name: g.name, actions: g.actions, attack_ids: g.actions.map((a) => ATTACK[a]), cure, signers: g.signers, devices: g.devices }).catch(() => null);
  return r?.summary ? (g.explained = r.summary) : summary(g); // fallback isn't cached, so the next open retries the model
}
async function tell(g, delay = 0.45) {
  told = g;
  // Short windows push it below the fold; bring it up as it starts talking (its first line names the threat, so the header can scroll away).
  const toSummary = () => panel.scrollTo({ top: panel.scrollHeight, behavior: reduced ? 'auto' : 'smooth' });
  if (!g.explained) {
    bubble.textContent = 'Reading this block…';
    bubble.classList.add('thinking');
  }
  queueMicrotask(toSummary); // after select() unhides the panel
  const text = await explain(g);
  if (told !== g) return; // another block was opened while the model was answering
  bubble.classList.remove('thinking');
  // One span per word so the words can come in like speech; the text itself is whole from the start for screen readers.
  bubble.innerHTML = text.split(' ').map((w) => `<span>${w.replace(/[&<>]/g, (c) => `&#${c.charCodeAt(0)};`)}</span>`).join(' ');
  if (reduced) return toSummary();
  gsap.fromTo(bubble.children, { opacity: 0 }, { opacity: 1, duration: 0.25, stagger: 0.022, delay, ease: 'none', overwrite: true });
  gsap.delayedCall(delay, () => (toSummary(), avatar.nudge()));
}
$('#d-avatar').addEventListener('click', () => avatar.takeClick() && told && (avatar.hop(), tell(told, 0.2)));

// A glowing square standing in for the 3D block while it travels.
function ghost(x, y, color) {
  const d = document.createElement('div');
  d.className = 'ghost';
  d.style.setProperty('--k', color);
  document.body.append(d);
  gsap.set(d, { left: x, top: y, xPercent: -50, yPercent: -50, rotation: 45 });
  return d;
}

function select({ index, x, y, color }) {
  if (index === open) return close();
  const g = genes[index];
  const wasOpen = open >= 0;
  open = index;
  helix.pin(index);
  probe.classList.remove('on');
  document.body.classList.add('has-detail');
  fill(g, color);
  const body = panel.querySelectorAll('.d-in');
  if (reduced) return (panel.hidden = false);

  const gh = ghost(x, y, color);
  const tl = gsap.timeline({ onComplete: () => gh.remove() }).timeScale(1.6); // snappier: the panel is what the click was for
  if (wasOpen) {
    // Already open: the new block flies into the panel's colour chip and the contents re-stagger.
    const r = $('#d-chip').getBoundingClientRect();
    tl.to(body, { opacity: 0, y: -6, duration: 0.2, stagger: 0.02 }, 0)
      .to(gh, { left: r.left + r.width / 2, duration: 0.6, ease: 'power3.inOut' }, 0)
      .to(gh, { top: r.top + r.height / 2, duration: 0.6, ease: 'back.in(1.2)' }, 0)
      .to(gh, { scale: 0.6, rotation: 225, duration: 0.6, ease: 'power2.in' }, 0)
      .fromTo(body, { opacity: 0, y: 10 }, { opacity: 1, y: 0, duration: 0.45, ease: 'power3.out', stagger: 0.04 }, 0.5);
    return;
  }
  panel.hidden = false;
  const r = panel.getBoundingClientRect();
  gsap.set(panel, { opacity: 0 });
  gsap.set(body, { opacity: 0, y: 12 });
  // 1) stretch straight out to the side as a bar at the block's own height, 2) grow vertically into the panel, 3) contents stagger in.
  const yb = Math.min(Math.max(y, r.top + 11), r.bottom - 11);
  tl.to(gh, { left: r.left, top: yb - 11, xPercent: 0, yPercent: 0, width: r.width, height: 22, rotation: 0, borderRadius: 11, duration: 0.3, ease: 'power3.out' }, 0)
    .to(gh, { top: r.top, height: r.height, borderRadius: 18, duration: 0.34, ease: 'expo.out' }, 0.24)
    .to(gh, { backgroundColor: 'rgba(6, 10, 22, 0.9)', duration: 0.3, ease: 'power2.inOut' }, 0.2)
    .set(panel, { opacity: 1 }, 0.5)
    .to(gh, { opacity: 0, duration: 0.12 }, 0.5)
    .to(body, { opacity: 1, y: 0, duration: 0.3, ease: 'power3.out', stagger: 0.03 }, 0.44);
}

function close() {
  if (open < 0) return;
  const i = open;
  open = -1;
  document.body.classList.remove('has-detail');
  if (reduced) return (helix.pin(-1), (panel.hidden = true));
  const r = panel.getBoundingClientRect();
  const to = helix.pin(i); // still pinned, so this is where the popped block sits now
  const k = panel.style.getPropertyValue('--k');
  const gh = ghost(0, 0, k);
  gsap.set(gh, { left: r.left, top: r.top, xPercent: 0, yPercent: 0, rotation: 0, width: r.width, height: r.height, borderRadius: 18, backgroundColor: 'rgba(6, 10, 22, 0.9)' });
  gsap
    .timeline({ onComplete: () => (gh.remove(), open < 0 && helix.pin(-1)) })
    .timeScale(1.6) // same pace as opening
    .to(panel.querySelectorAll('.d-in'), { opacity: 0, duration: 0.12 })
    .call(() => (panel.hidden = open < 0))
    // Same path in reverse: collapse to a bar at the block's height, then retract sideways into it.
    .to(gh, { top: to.y - 11, height: 22, borderRadius: 11, backgroundColor: k, duration: 0.26, ease: 'expo.in' })
    .to(gh, { left: to.x - 11, width: 22, rotation: 45, borderRadius: 3, duration: 0.26, ease: 'power3.in' })
    .to(gh, { scale: 0.4, opacity: 0, duration: 0.1 });
}

$('#d-close').addEventListener('click', close);
addEventListener('keydown', (e) => e.key === 'Escape' && close());

function renderStats() {
  $('#gs-genes').textContent = fmt(genes.length); // exactly the cures drawn in the helix (demo history + real chain cures), per user decision
  $('#gs-devices').textContent = fmt(state.stats.globalDevices);
  $('#gs-slot').textContent = fmt(state.stats.slot);
}

feed.addEventListener('stats', renderStats);
feed.addEventListener('block', ({ detail: b }) => {
  renderStats();
  if (b.kind !== 'commit_gene' || genes.some((g) => g.gene === b.gene)) return;
  genes.push(cure({ gene: b.gene, name: b.name ?? THREATS[(Math.random() * THREATS.length) | 0].name, slot: b.slot, signers: b.signers, threat: b.threat, time: b.time, devices: 1 }));
  helix.add(b.gene);
  renderStats();
  const toast = $('#toast');
  toast.textContent = `New cure committed at block ${fmt(b.slot)}`;
  gsap.fromTo(toast, { opacity: 0, y: 8 }, { opacity: 1, y: 0, duration: reduced ? 0 : 0.5, ease: 'power3.out', overwrite: true });
  gsap.to(toast, { opacity: 0, delay: 3, duration: 0.6 });
});
// Genes already on chain (live: the ledger feed's first poll) arrive as 'genes', not blocks; no toast, they aren't new.
feed.addEventListener('genes', () => {
  const g = state.genes.at(-1);
  if (genes.some((x) => x.gene === g.gene)) return;
  genes.push(cure({ gene: g.gene, name: g.name, threat: g.threat, time: g.time, bytes: g.bytes, slot: state.stats.slot, signers: 3, devices: 1 }));
  helix.add(g.gene);
  renderStats();
});

// Opened from a block in the main window: scroll to that cure and open it as if clicked here.
async function showGene(g) {
  let i = genes.findIndex((x) => x.gene === g.gene);
  if (i < 0) {
    genes.push(cure({ ...g, slot: g.time ? slotAt(g.time) : state.stats.slot, signers: 3, devices: 1 }));
    i = genes.length - 1;
    helix.add(g.gene);
    renderStats();
  }
  const at = await helix.reveal(i);
  if (open !== i) select(at);
}
window.tcell?.onGenomeSelect?.(showGene);
// Plain-browser dev path: the main window passes the cure in the URL hash.
const fromHash = () => {
  try {
    if (location.hash.length > 1) showGene(JSON.parse(decodeURIComponent(location.hash.slice(1))));
  } catch {}
};
addEventListener('hashchange', fromHash);
fromHash();
renderStats();
