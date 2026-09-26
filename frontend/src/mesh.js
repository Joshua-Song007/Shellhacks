import gsap from 'gsap';

const NS = 'http://www.w3.org/2000/svg';
const GLYPH = {
  laptop: 'M6 7h12v8H6z M3.5 18h17',
  desktop: 'M4 5h16v10H4z M9 20h6 M12 15v5',
  mini: 'M4 10h16v5H4z M7.5 12.5h1.5',
};
export const LABEL = { clean: 'Safe', watching: 'Checking something', isolated: 'Threat paused', cured: 'Fixed' };

const el = (tag, attrs = {}, parent) => {
  const n = document.createElementNS(NS, tag);
  for (const k in attrs) n.setAttribute(k, attrs[k]);
  parent?.append(n);
  return n;
};

// Full-mesh graph of lymph nodes. The local device sits in the middle.
export function createMesh(svg, devices, selfId, { reduced }) {
  const W = 600;
  const H = 360;
  const others = devices.filter((d) => d.id !== selfId);
  const pos = { [selfId]: [W / 2, H / 2 - 6] };
  others.forEach((d, i) => {
    const a = -Math.PI / 2 + ((i + 0.5) / others.length) * Math.PI * 2;
    pos[d.id] = [W / 2 + Math.cos(a) * 225, H / 2 - 6 + Math.sin(a) * 118];
  });

  const gLinks = el('g', { class: 'links' }, svg);
  const gPulses = el('g', {}, svg);
  const gNodes = el('g', {}, svg);

  for (let i = 0; i < devices.length; i++)
    for (let j = i + 1; j < devices.length; j++) {
      const [x1, y1] = pos[devices[i].id];
      const [x2, y2] = pos[devices[j].id];
      el('line', { x1, y1, x2, y2 }, gLinks);
    }

  const nodes = {};
  for (const d of devices) {
    const [x, y] = pos[d.id];
    const g = el('g', { class: 'node', transform: `translate(${x} ${y})`, 'data-s': d.status }, gNodes);
    el('circle', { class: 'halo', r: 34 }, g);
    el('circle', { class: 'disc', r: 27 }, g);
    el('path', { class: 'glyph', d: GLYPH[d.kind], transform: 'translate(-15 -15) scale(1.25)' }, g);
    const name = el('text', { class: 'name', y: 50 }, g);
    name.textContent = d.id === selfId ? `${d.name} (you)` : d.name;
    const st = el('text', { class: 'state', y: 67 }, g);
    nodes[d.id] = { g, st };
  }

  function update(list) {
    for (const d of list) {
      const n = nodes[d.id];
      if (n.g.dataset.s === d.status) continue;
      n.g.dataset.s = d.status;
      n.st.textContent = LABEL[d.status];
      if (!reduced && d.status !== 'clean') gsap.fromTo(n.g.querySelector('.halo'), { attr: { r: 30 }, opacity: 1 }, { attr: { r: 52 }, opacity: 0, duration: 1.2, ease: 'expo.out', repeat: d.status === 'isolated' ? 2 : 0 });
    }
  }
  for (const d of devices) nodes[d.id].st.textContent = LABEL[d.status];

  // A cure travelling from one device to the rest.
  function propagate(from, to) {
    const [x1, y1] = pos[from];
    to.forEach((id, i) => {
      const [x2, y2] = pos[id];
      const dot = el('circle', { class: 'pulse', r: 5, cx: x1, cy: y1 }, gPulses);
      gsap.to(dot, {
        attr: { cx: x2, cy: y2 },
        duration: reduced ? 0.01 : 1.1,
        delay: reduced ? 0 : i * 0.12,
        ease: 'power2.inOut',
        onComplete() {
          dot.remove();
          if (!reduced) gsap.fromTo(nodes[id].g.querySelector('.disc'), { attr: { r: 33 } }, { attr: { r: 27 }, duration: 0.6, ease: 'elastic.out(1, 0.5)' });
        },
      });
    });
  }

  return { update, propagate };
}
