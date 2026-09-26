import gsap from 'gsap';
import { feed, state, THREATS, ALLELES, WEIGHT, ATTACK, ACT_LABEL, evaluate } from './data.js';
import { createHelix } from './helix.js';

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
  return { threat: hex(32), time: Date.now(), bytes: 380 + ((Math.random() * 420) | 0), devices: 40 + ((Math.random() * 9000) | 0), actions: t.actions, mask: bestMask(t.actions), ...g };
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
  onEdge: (e) => {
    $('.edge-cue.top').classList.toggle('on', e > 0);
    $('.edge-cue.bottom').classList.toggle('on', e < 0);
  },
  onSelect: (h) => select(h),
  onHover(h) {
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
  $('#d-fit').textContent = `Stops ${e.containment} of ${g.actions.reduce((n, a) => n + WEIGHT[a], 0)} threat points at a cost of ${e.cost}.`;
  $('#d-proof').innerHTML = Array.from({ length: 5 }, (_, i) => `<i class="${i < g.signers ? 'on' : ''}"></i>`).join('');
  $('#d-proof-t').textContent = `${g.signers} of 5 nodes re-ran the cure and signed it`;
  $('#d-devices').textContent = fmt(g.devices);
  $('#d-bytes').textContent = `${g.bytes} B`;
  $('#d-threat').textContent = `${g.threat.slice(0, 10)}…${g.threat.slice(-6)}`;
  $('#d-threat').title = g.threat;
  $('#d-gene').textContent = `${g.gene.slice(0, 10)}…${g.gene.slice(-6)}`;
  $('#d-gene').title = g.gene;
}

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
  const tl = gsap.timeline({ onComplete: () => gh.remove() });
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
  // 1) arc out to the side (x and y on different eases), 2) unfold into the panel's rectangle, 3) contents stagger in.
  tl.to(gh, { left: r.left + 34, duration: 0.7, ease: 'power3.inOut' }, 0)
    .to(gh, { top: r.top + 44, duration: 0.7, ease: 'power2.out' }, 0)
    .to(gh, { rotation: 0, scale: 1.4, duration: 0.7, ease: 'power2.inOut' }, 0)
    .to(gh, { left: r.left, top: r.top, xPercent: 0, yPercent: 0, scale: 1, width: r.width, height: r.height, borderRadius: 18, duration: 0.55, ease: 'expo.inOut' }, 0.62)
    .to(gh, { backgroundColor: 'rgba(6, 10, 22, 0.9)', duration: 0.45, ease: 'power2.inOut' }, 0.72)
    .set(panel, { opacity: 1 })
    .to(gh, { opacity: 0, duration: 0.2 })
    .to(body, { opacity: 1, y: 0, duration: 0.5, ease: 'power3.out', stagger: 0.05 }, '<');
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
    .to(panel.querySelectorAll('.d-in'), { opacity: 0, y: -8, duration: 0.2, stagger: 0.02 })
    .call(() => (panel.hidden = open < 0))
    .to(gh, { width: 22, height: 22, borderRadius: 3, left: r.left + 34, top: r.top + 44, xPercent: -50, yPercent: -50, backgroundColor: k, duration: 0.45, ease: 'expo.inOut' })
    .to(gh, { left: to.x, top: to.y, rotation: 45, duration: 0.55, ease: 'power3.inOut' })
    .to(gh, { scale: 0.4, opacity: 0, duration: 0.2 }, '-=0.12');
}

$('#d-close').addEventListener('click', close);
addEventListener('keydown', (e) => e.key === 'Escape' && close());

function renderStats() {
  $('#gs-genes').textContent = fmt(state.stats.globalGenes);
  $('#gs-devices').textContent = fmt(state.stats.globalDevices);
  $('#gs-slot').textContent = fmt(state.stats.slot);
}

feed.addEventListener('block', ({ detail: b }) => {
  renderStats();
  if (b.kind !== 'commit_gene') return;
  genes.push(cure({ gene: b.gene, name: b.name ?? THREATS[(Math.random() * THREATS.length) | 0].name, slot: b.slot, signers: b.signers, threat: b.threat, time: b.time, devices: 1 }));
  helix.add(b.gene);
  const toast = $('#toast');
  toast.textContent = `New cure committed at block ${fmt(b.slot)}`;
  gsap.fromTo(toast, { opacity: 0, y: 8 }, { opacity: 1, y: 0, duration: reduced ? 0 : 0.5, ease: 'power3.out', overwrite: true });
  gsap.to(toast, { opacity: 0, delay: 3, duration: 0.6 });
});
renderStats();
