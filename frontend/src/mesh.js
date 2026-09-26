import gsap from 'gsap';

const NS = 'http://www.w3.org/2000/svg';
export const GLYPH = {
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
  const pos = {}; // id -> { x, y }, tweened when a device joins
  const gLinks = el('g', { class: 'links' }, svg);
  const gPulses = el('g', {}, svg);
  const gNodes = el('g', {}, svg);
  const nodes = {};
  let ids = [];

  // Where every device should sit for the current roster.
  function targets() {
    const others = ids.filter((id) => id !== selfId);
    const t = { [selfId]: [W / 2, H / 2 - 6] };
    others.forEach((id, i) => {
      const a = -Math.PI / 2 + ((i + 0.5) / others.length) * Math.PI * 2;
      t[id] = [W / 2 + Math.cos(a) * 225, H / 2 - 6 + Math.sin(a) * 118];
    });
    return t;
  }

  function draw() {
    for (const id of ids) nodes[id].g.setAttribute('transform', `translate(${pos[id].x} ${pos[id].y})`);
    for (const l of gLinks.children) {
      const [a, b] = [pos[l.dataset.a], pos[l.dataset.b]];
      l.setAttribute('x1', a.x), l.setAttribute('y1', a.y), l.setAttribute('x2', b.x), l.setAttribute('y2', b.y);
    }
  }

  function addNode(d) {
    const g = el('g', { class: 'node', 'data-s': d.status }, gNodes);
    el('circle', { class: 'halo', r: 34 }, g);
    el('circle', { class: 'disc', r: 27 }, g);
    el('path', { class: 'glyph', d: GLYPH[d.kind], transform: 'translate(-15 -15) scale(1.25)' }, g);
    const name = el('text', { class: 'name', y: 50 }, g);
    name.textContent = d.id === selfId ? `${d.name} (you)` : d.name;
    const st = el('text', { class: 'state', y: 67 }, g);
    st.textContent = LABEL[d.status];
    for (const other of ids) el('line', { 'data-a': other, 'data-b': d.id }, gLinks);
    ids.push(d.id);
    nodes[d.id] = { g, st };
    return g;
  }

  for (const d of devices) addNode(d);
  for (const [id, [x, y]] of Object.entries(targets())) pos[id] = { x, y };
  draw();

  // A device joined: it grows in from the centre while the others slide round to make room.
  function join(d) {
    const g = addNode(d);
    pos[d.id] = { ...pos[selfId] };
    const t = targets();
    const tl = gsap.timeline({ onUpdate: draw, defaults: { duration: reduced ? 0 : 1, ease: 'expo.inOut' } });
    for (const id of ids) tl.to(pos[id], { x: t[id][0], y: t[id][1] }, 0);
    if (reduced) return draw();
    tl.fromTo(g, { opacity: 0 }, { opacity: 1, duration: 0.6, ease: 'power2.out' }, 0.2);
    tl.fromTo(gLinks.querySelectorAll(`[data-b="${d.id}"]`), { opacity: 0 }, { opacity: 1, duration: 0.8 }, 0.5);
    tl.fromTo(g.querySelector('.halo'), { attr: { r: 30 }, opacity: 1 }, { attr: { r: 60 }, opacity: 0, duration: 1.4, ease: 'expo.out' }, 0.9);
  }

  function update(list) {
    for (const d of list) {
      if (!nodes[d.id]) join(d);
      const n = nodes[d.id];
      if (n.g.dataset.s === d.status) continue;
      n.g.dataset.s = d.status;
      n.st.textContent = LABEL[d.status];
      if (!reduced && d.status !== 'clean') gsap.fromTo(n.g.querySelector('.halo'), { attr: { r: 30 }, opacity: 1 }, { attr: { r: 52 }, opacity: 0, duration: 1.2, ease: 'expo.out', repeat: d.status === 'isolated' ? 2 : 0 });
    }
  }

  // A cure travelling from one device to the rest.
  function propagate(from, to) {
    const { x: x1, y: y1 } = pos[from];
    to.forEach((id, i) => {
      const dot = el('circle', { class: 'pulse', r: 5, cx: x1, cy: y1 }, gPulses);
      gsap.to(dot, {
        // function values: read the target when the tween starts, so a node still sliding into place is hit where it lands
        attr: { cx: () => pos[id].x, cy: () => pos[id].y },
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
