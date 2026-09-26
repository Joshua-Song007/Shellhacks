import gsap from 'gsap';
import { feed, state, THREATS } from './data.js';
import { createHelix } from './helix.js';

const $ = (s, r = document) => r.querySelector(s);
const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;
const fmt = (n) => n.toLocaleString('en-US');
const hex = (n) => Array.from(crypto.getRandomValues(new Uint8Array(n)), (b) => b.toString(16).padStart(2, '0')).join('');

// Most recent global cures, oldest first. Seeded here; new ones arrive as commit_gene blocks.
const genes = Array.from({ length: 56 }, (_, i) => ({
  gene: hex(32),
  name: THREATS[i % THREATS.length].name,
  slot: state.stats.slot - (56 - i) * 900,
  signers: 3 + (i % 3),
}));

const probe = $('#probe');
let probeI = -1;
const helix = createHelix($('#global-gl'), {
  hashes: genes.map((g) => g.gene),
  capacity: 120,
  length: 1.35,
  tilt: 0.38,
  bg: 0x02040b,
  particles: 1100,
  reduced,
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
    b.textContent = `${g.signers} of 5 nodes proved it`;
  },
});

function renderStats() {
  $('#gs-genes').textContent = fmt(state.stats.globalGenes);
  $('#gs-devices').textContent = fmt(state.stats.globalDevices);
  $('#gs-slot').textContent = fmt(state.stats.slot);
}

feed.addEventListener('block', ({ detail: b }) => {
  renderStats();
  if (b.kind !== 'commit_gene') return;
  genes.push({ gene: b.gene, name: b.name ?? THREATS[(Math.random() * THREATS.length) | 0].name, slot: b.slot, signers: b.signers });
  helix.add(b.gene);
  const toast = $('#toast');
  toast.textContent = `New cure committed at block ${fmt(b.slot)}`;
  gsap.fromTo(toast, { opacity: 0, y: 8 }, { opacity: 1, y: 0, duration: reduced ? 0 : 0.5, ease: 'power3.out', overwrite: true });
  gsap.to(toast, { opacity: 0, delay: 3, duration: 0.6 });
});
renderStats();
