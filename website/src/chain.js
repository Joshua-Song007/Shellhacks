// Set to the deployed Anchor program id to stream real devnet activity
// (submit_threat / commit_gene / suppress_gene). Empty = simulated feed.
export const PROGRAM_ID = '';
const RPC_WS = 'wss://api.devnet.solana.com';

const KINDS = {
  submit_threat: { label: 'Threat reported', cls: 'k-threat' },
  commit_gene: { label: 'Cure committed', cls: 'k-cure' },
  suppress_gene: { label: 'Cure switched off', cls: 'k-suppress' },
};
const IX = { SubmitThreat: 'submit_threat', CommitGene: 'commit_gene', SuppressGene: 'suppress_gene' };
const MAX_BLOCKS = 14;

const hex = (n) => Array.from(crypto.getRandomValues(new Uint8Array(n)), (b) => b.toString(16).padStart(2, '0')).join('');
const short = (h) => (h ? `${h.slice(0, 6)}…${h.slice(-4)}` : '—');
const fmt = (n) => n.toLocaleString('en-US');

function ago(ms) {
  const s = Math.max(0, Math.round((Date.now() - ms) / 1000));
  if (s < 3) return 'just now';
  if (s < 60) return `${s}s ago`;
  return `${Math.floor(s / 60)}m ago`;
}

function simulate(emit) {
  let slot = 318_442_000 + ((Math.random() * 9000) | 0);
  const open = []; // threats awaiting a cure: { id, confidence }
  const cured = [];

  function next() {
    slot += 18 + ((Math.random() * 70) | 0);
    const r = Math.random();
    if (!open.length || r < 0.48) {
      // New threat, or another device independently reporting a known one
      const known = open.length && Math.random() < 0.4 ? open[(Math.random() * open.length) | 0] : null;
      const t = known || { id: hex(32), confidence: 0 };
      t.confidence++;
      if (!known) open.push(t);
      return { slot, kind: 'submit_threat', threat: t.id, confidence: t.confidence, sig: hex(32) };
    }
    if (r < 0.93 || !cured.length) {
      const t = open.shift();
      const g = { threat: t.id, gene: hex(32) };
      cured.push(g);
      return { slot, kind: 'commit_gene', threat: t.id, gene: g.gene, signers: 3 + ((Math.random() * 3) | 0), sig: hex(32) };
    }
    const g = cured.splice((Math.random() * cured.length) | 0, 1)[0];
    return { slot, kind: 'suppress_gene', threat: g.threat, gene: g.gene, sig: hex(32) };
  }

  for (let i = 0; i < 9; i++) emit({ ...next(), time: Date.now() - (9 - i) * 4000 }, true);
  (function loop() {
    setTimeout(() => {
      emit({ ...next(), time: Date.now() });
      loop();
    }, 1800 + Math.random() * 2400);
  })();
}

function live(emit, onFail) {
  const ws = new WebSocket(RPC_WS);
  ws.onopen = () =>
    ws.send(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'logsSubscribe', params: [{ mentions: [PROGRAM_ID] }, { commitment: 'confirmed' }] }));
  ws.onmessage = (e) => {
    const res = JSON.parse(e.data).params?.result;
    const v = res?.value;
    if (!v || v.err) return;
    const m = v.logs.join('\n').match(/Instruction: (SubmitThreat|CommitGene|SuppressGene)/);
    if (m) emit({ slot: res.context.slot, kind: IX[m[1]], sig: v.signature, time: Date.now() });
  };
  ws.onerror = onFail;
}

export function mountChain({ track, stats, source, onBlock = () => {}, animate }) {
  const totals = { threats: 0, cures: 0, devices: 2_300 + ((Math.random() * 900) | 0) };
  let simulated = true;

  function render(b, initial) {
    const k = KINDS[b.kind];
    const li = document.createElement('li');
    li.className = `block ${k.cls}`;
    li.innerHTML = `
      <div class="block-head"><span class="block-kind">${k.label}</span><span class="block-slot">Slot ${fmt(b.slot)}</span></div>
      <dl>
        <div><dt>Threat</dt><dd>${short(b.threat)}</dd></div>
        ${b.gene ? `<div><dt>Gene</dt><dd>${short(b.gene)}</dd></div>` : ''}
        ${b.signers ? `<div><dt>Proof</dt><dd>${b.signers} of 5 signed</dd></div>` : ''}
        ${b.confidence ? `<div><dt>Reports</dt><dd>${b.confidence} ${b.confidence === 1 ? 'device' : 'devices'}</dd></div>` : ''}
        <div><dt>Tx</dt><dd>${short(b.sig)}</dd></div>
      </dl>
      <time data-t="${b.time}">${ago(b.time)}</time>`;
    track.prepend(li);
    while (track.children.length > MAX_BLOCKS) track.lastElementChild.remove();
    if (!initial) animate(li);

    if (b.kind === 'submit_threat' && (b.confidence ?? 1) === 1) totals.threats++;
    if (b.kind === 'commit_gene') {
      totals.cures++;
      if (simulated) totals.devices += 40 + ((Math.random() * 160) | 0);
    }
    stats.height.textContent = fmt(b.slot);
    stats.threats.textContent = fmt(totals.threats);
    stats.cures.textContent = fmt(totals.cures);
    stats.devices.textContent = simulated ? fmt(totals.devices) : '—';
    if (!initial) onBlock(b);
  }

  setInterval(() => track.querySelectorAll('time').forEach((t) => (t.textContent = ago(+t.dataset.t))), 1000);

  if (PROGRAM_ID) {
    simulated = false;
    source.textContent = 'Solana devnet, live';
    source.parentElement.classList.add('is-live');
    live(render, () => {
      simulated = true;
      source.textContent = 'Devnet unreachable, showing simulated feed';
      simulate(render);
    });
  } else {
    source.textContent = 'Simulated feed';
    simulate(render);
  }
}
