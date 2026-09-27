import * as THREE from 'three';
import { EffectComposer } from 'three/examples/jsm/postprocessing/EffectComposer.js';
import { RenderPass } from 'three/examples/jsm/postprocessing/RenderPass.js';
import { UnrealBloomPass } from 'three/examples/jsm/postprocessing/UnrealBloomPass.js';
import { OutputPass } from 'three/examples/jsm/postprocessing/OutputPass.js';

// Trimmed from website/src/helix.js: no scroll/chain choreography, sized to its container,
// and the pair count can grow (one pair per cure).
const BASE = { A: '#4ff5d2', T: '#8f7bff', G: '#4ba3ff', C: '#f77fd1' };
const PAIR = { A: 'T', T: 'A', G: 'C', C: 'G' };

const clamp01 = (v) => Math.min(1, Math.max(0, v));
const ease = (t) => t * t * (3 - 2 * t);
const baseOf = (hash) => 'ATGC'[parseInt(hash.slice(0, 2), 16) % 4];

// bg = null renders transparent so the panel shows through; `length` is how much of the box the strand spans (>1 runs off the edges).
// edgeScroll: hovering the top/bottom band of the box scrolls along the strand (and so does the wheel); onSelect(hit) fires on a block click.
// edgeTop: px at the top that never scroll (window chrome overlaid on the canvas).
// visible: the strand stops shrinking past this many blocks; the rest scroll (needs edgeScroll). It opens on the newest, and returns there when a cure is added.
export function createHelix(canvas, { hashes, capacity = 160, tilt = 0, bg = null, length = 0.86, thickness = 0.55, particles = 300, reduced = false, glow = 1, edgeScroll = false, edgeTop = 0, visible = Infinity, onHover = () => {}, onSelect = null, onEdge = () => {} }) {
  const SP = 0.34;
  const R = 0.62;
  const TWIST = 0.36;
  const CUBE = 0.23;
  const N = capacity;
  const box = canvas.parentElement;

  const renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: bg === null });
  renderer.setPixelRatio(Math.min(devicePixelRatio, 2));
  const scene = new THREE.Scene();
  if (bg !== null) {
    scene.background = new THREE.Color(bg);
    scene.fog = new THREE.FogExp2(bg, 0.045);
  }
  const camera = new THREE.PerspectiveCamera(40, 1, 0.1, 100);
  camera.position.set(0, 0, 11);

  const root = new THREE.Group();
  root.rotation.z = tilt;
  scene.add(root);

  const seq = [];
  const colA = [];
  const colB = [];
  const colBlock = [];
  const born = new Float32Array(N).fill(-1); // time each pair appeared, for the grow-in
  let count = 0;

  const nodes = new THREE.InstancedMesh(new THREE.SphereGeometry(0.062, 14, 10), new THREE.MeshBasicMaterial({ toneMapped: false }), N * 2);
  const rungs = new THREE.InstancedMesh(
    new THREE.CylinderGeometry(0.011, 0.011, 1, 6),
    new THREE.MeshBasicMaterial({ toneMapped: false, transparent: true, opacity: 0.55, blending: THREE.AdditiveBlending, depthWrite: false }),
    N,
  );
  const blocks = new THREE.InstancedMesh(
    new THREE.BoxGeometry(1, 1, 1),
    new THREE.ShaderMaterial({
      transparent: true,
      depthWrite: false,
      blending: THREE.AdditiveBlending,
      vertexShader: /* glsl */ `
        varying vec2 vUv; varying vec3 vColor;
        void main() { vUv = uv; vColor = instanceColor; gl_Position = projectionMatrix * modelViewMatrix * instanceMatrix * vec4(position, 1.0); }`,
      fragmentShader: /* glsl */ `
        varying vec2 vUv; varying vec3 vColor;
        void main() {
          float d = min(min(vUv.x, 1.0 - vUv.x), min(vUv.y, 1.0 - vUv.y));
          float edge = 1.0 - smoothstep(0.0, 0.07, d);
          float rows = step(0.86, fract(vUv.y * 4.0)) * step(0.18, vUv.x) * step(vUv.x, 0.82);
          gl_FragColor = vec4(vColor * (edge * 1.5 + rows * 0.35 + 0.07), 1.0);
        }`,
    }),
    N,
  );
  const zero = new THREE.Matrix4().makeScale(0, 0, 0);
  for (let i = 0; i < N; i++) {
    nodes.setMatrixAt(i * 2, zero);
    nodes.setMatrixAt(i * 2 + 1, zero);
    rungs.setMatrixAt(i, zero);
    blocks.setMatrixAt(i, zero);
    nodes.setColorAt(i * 2, new THREE.Color());
    nodes.setColorAt(i * 2 + 1, new THREE.Color());
    rungs.setColorAt(i, new THREE.Color());
    blocks.setColorAt(i, new THREE.Color());
  }
  root.add(nodes, rungs, blocks);

  if (particles) {
    const pPos = new Float32Array(particles * 3);
    for (let i = 0; i < particles * 3; i += 3) {
      pPos[i] = (Math.random() - 0.5) * 30;
      pPos[i + 1] = (Math.random() - 0.5) * 18;
      pPos[i + 2] = (Math.random() - 0.5) * 14 - 3;
    }
    const pGeo = new THREE.BufferGeometry();
    pGeo.setAttribute('position', new THREE.BufferAttribute(pPos, 3));
    scene.add(new THREE.Points(pGeo, new THREE.PointsMaterial({ color: 0x7fb6ff, size: 0.035, transparent: true, opacity: 0.5, blending: THREE.AdditiveBlending, depthWrite: false })));
  }

  const composer = new EffectComposer(renderer);
  composer.addPass(new RenderPass(scene, camera));
  const bloom = new UnrealBloomPass(new THREE.Vector2(1, 1), 0.8 * glow, 0.55 * Math.sqrt(glow), 0.12) // glow < 1 for a small panel: less dark margin to bleed into;
  composer.addPass(bloom);
  composer.addPass(new OutputPass());

  function add(hash) {
    if (count >= N) return; // ponytail: capped at capacity; shift the oldest out if a view ever needs more
    const i = count++;
    const b = baseOf(hash);
    seq[i] = b;
    colA[i] = new THREE.Color(BASE[b]);
    colB[i] = new THREE.Color(BASE[PAIR[b]]);
    colBlock[i] = colA[i].clone().lerp(colB[i], 0.5);
    nodes.setColorAt(i * 2, colA[i]);
    nodes.setColorAt(i * 2 + 1, colB[i]);
    rungs.setColorAt(i, colBlock[i]);
    nodes.instanceColor.needsUpdate = rungs.instanceColor.needsUpdate = true;
    born[i] = clock.elapsedTime;
    return i;
  }

  const mix = new Float32Array(N);
  const flash = new Float32Array(N);
  const centers = Array.from({ length: N }, () => new THREE.Vector3());
  const pointer = { x: 0, y: 0, nx: 0, ny: 0, active: false };
  let hover = -1;
  let pinned = -1; // selected block, held popped out while its details are open
  let scroll = 0; // strand-local offset along the axis
  let wheel = 0;
  let follow = true; // glide to the newest end until the viewer scrolls; add() re-arms it
  let seek = null; // { i, done } from reveal(): glide to block i, resolve once it has settled there
  let edge = 0; // -1 bottom band, 1 top band, 0 neither
  let phase = 0;
  let w = 1;
  let h = 1;
  let fit = 1;

  const m4 = new THREE.Matrix4();
  const q = new THREE.Quaternion();
  const s = new THREE.Vector3();
  const pA = new THREE.Vector3();
  const pB = new THREE.Vector3();
  const tmp = new THREE.Vector3();
  const up = new THREE.Vector3(0, 1, 0);
  const col = new THREE.Color();
  const euler = new THREE.Euler();

  new ResizeObserver(() => {
    if (!box.clientWidth || !box.clientHeight) return; // hidden view: a 0 size would NaN the camera for good
    w = box.clientWidth;
    h = box.clientHeight;
    renderer.setSize(w, h, false);
    composer.setSize(w, h);
    camera.aspect = w / h;
    camera.updateProjectionMatrix();
  }).observe(box);

  canvas.addEventListener('pointermove', (e) => {
    const r = canvas.getBoundingClientRect();
    pointer.x = e.clientX - r.left;
    pointer.y = e.clientY - r.top;
    pointer.nx = pointer.x / r.width - 0.5;
    pointer.ny = pointer.y / r.height - 0.5;
    pointer.active = true;
  });
  canvas.addEventListener('pointerleave', () => (pointer.active = false));
  // Native window controls overlay the page without a pointerleave; drop the stale position when the cursor leaves the page or the window blurs.
  document.addEventListener('mouseleave', () => (pointer.active = false));
  addEventListener('blur', () => (pointer.active = false));
  if (edgeScroll) canvas.addEventListener('wheel', (e) => (wheel -= e.deltaY * 0.004), { passive: true });
  if (onSelect)
    canvas.addEventListener('click', () => {
      if (hover < 0) return;
      const [x, y] = screenOf(tmp.copy(centers[hover]).applyMatrix4(root.matrixWorld));
      onSelect({ index: hover, x, y, color: `#${colBlock[hover].getHexString()}` });
    });

  function screenOf(v) {
    tmp.copy(v).project(camera);
    return [(tmp.x * 0.5 + 0.5) * w, (-tmp.y * 0.5 + 0.5) * h];
  }

  const clock = new THREE.Clock();
  for (const hsh of hashes) add(hsh);
  born.fill(-10); // initial pairs skip the grow-in sequence below…
  // …and build in from one end instead
  const intro = { t: 0 };

  function frame() {
    const dt = Math.min(clock.getDelta(), 0.05);
    const t = clock.elapsedTime;
    intro.t = Math.min(1, intro.t + dt / (reduced ? 0.2 : 2));
    phase += dt * 0.3 * (reduced ? 0.2 : 1);

    // Fit the strand's length to the box (along whichever axis it runs)
    const vh = 2 * camera.position.z * Math.tan(THREE.MathUtils.degToRad(camera.fov / 2));
    const along = Math.abs(Math.cos(tilt)) * vh + Math.abs(Math.sin(tilt)) * vh * camera.aspect;
    const across = Math.abs(Math.sin(tilt)) * vh + Math.abs(Math.cos(tilt)) * vh * camera.aspect;
    fit += (Math.min((across * thickness) / (R * 2), (along * length) / Math.max(1, Math.min(count, visible) * SP)) - fit) * Math.min(1, dt * 3);
    root.scale.setScalar(fit);

    if (edgeScroll) {
      // Depth into the top/bottom 16% band sets the speed; clamp so the strand's ends stop at the box edge.
      const band = 0.16 * h;
      const top = pointer.y - edgeTop;
      let depth = !pointer.active || top < 0 ? 0 : top < band ? 1 - top / band : pointer.y > h - band ? -(1 - (h - pointer.y) / band) : 0;
      // End padding = the band's depth, so the first/last block rests just inside it, not under it.
      const max = Math.max(0, ((count - 1) / 2) * SP + SP + (0.16 * along) / fit - along / 2 / fit);
      if ((depth > 0 && scroll >= max) || (depth < 0 && scroll <= -max)) depth = 0; // at the end: the band goes inert so its blocks can be hovered and clicked
      const e = Math.sign(depth);
      if (e !== edge) onEdge((edge = e));
      scroll += ease(Math.abs(depth)) * Math.sign(depth) * dt * 4.5 + wheel;
      if (depth || wheel) follow = false;
      if (seek) {
        follow = false;
        const want = Math.min(max, Math.max(-max, (seek.i - (count - 1) / 2) * SP));
        intro.t = 1; // arriving from a click elsewhere: skip the build-in, the viewer is waiting on one block
        scroll += (want - scroll) * Math.min(1, dt * 10);
        if (Math.abs(want - scroll) < 0.08) {
          scroll = want;
          const { i, done } = seek;
          seek = null;
          requestAnimationFrame(() => {
            const [x, y] = screenOf(tmp.copy(centers[i]).applyMatrix4(root.matrixWorld));
            done({ index: i, x, y, color: `#${colBlock[i].getHexString()}` });
          });
        }
      } else if (follow && pinned < 0 && visible < Infinity) scroll += (max - scroll) * Math.min(1, dt * 2);
      wheel = 0;
      scroll = Math.min(max, Math.max(-max, scroll));
    }

    camera.position.x += ((pointer.active ? pointer.nx : 0) * 0.5 - camera.position.x) * 0.04;
    camera.position.y += ((pointer.active ? -pointer.ny : 0) * 0.35 - camera.position.y) * 0.04;
    camera.lookAt(0, 0, 0);
    camera.updateMatrixWorld();
    root.updateMatrixWorld();

    let best = -1;
    let hoverD = Infinity;
    let bestD = 60;
    if (pointer.active && intro.t >= 1) {
      for (let i = 0; i < count; i++) {
        // Hit-test the un-popped axis point: a popped block slides toward the camera, which would move its target under the cursor.
        const [sx, sy] = screenOf(tmp.set(0, centers[i].y, 0).applyMatrix4(root.matrixWorld));
        const d = Math.hypot(sx - pointer.x, sy - pointer.y);
        if (i === hover) hoverD = d;
        if (d < bestD) {
          bestD = d;
          best = i;
        }
      }
    }
    if (best !== -1 && hoverD - bestD < 4) best = hover; // a few px of hysteresis, so every neighbour stays reachable
    if (edge) best = -1; // scrolling, not pointing
    hover = best;

    const half = (count - 1) / 2;
    for (let i = 0; i < count; i++) {
      const build = born[i] < 0 ? ease(clamp01((intro.t * (count + 8) - i) / 8)) : ease(clamp01((t - born[i]) / 1.2));
      const focus = pinned >= 0 ? pinned : hover;
      const hv = focus >= 0 ? clamp01(1 - (Math.abs(i - focus) - 1) / 3) : 0;
      mix[i] += (hv - mix[i]) * Math.min(1, dt * (reduced ? 12 : 6));
      flash[i] *= 1 - Math.min(1, dt * 1.2);
      const e = ease(mix[i]);

      const ay = (i - half) * SP - scroll;
      const a = i * TWIST + phase;
      const pop = e * 0.35;
      pA.set(Math.cos(a) * R, ay, Math.sin(a) * R).lerp(tmp.set(-CUBE * 0.5 - 0.02, ay, pop), e);
      pB.set(-Math.cos(a) * R, ay, -Math.sin(a) * R).lerp(tmp.set(CUBE * 0.5 + 0.02, ay, pop), e);
      centers[i].set(0, ay, pop);

      const nScale = build * (1 - 0.55 * e) * (1 + flash[i] * 0.8);
      m4.compose(pA, q.identity(), s.setScalar(nScale));
      nodes.setMatrixAt(i * 2, m4);
      m4.compose(pB, q, s);
      nodes.setMatrixAt(i * 2 + 1, m4);

      tmp.subVectors(pB, pA);
      const len = tmp.length();
      q.setFromUnitVectors(up, tmp.normalize());
      m4.compose(tmp.addVectors(pA, pB).multiplyScalar(0.5), q, s.set(build * (1 - e), len, build * (1 - e)));
      rungs.setMatrixAt(i, m4);

      const bs = CUBE * Math.max(e, flash[i]) * build * (1 + (i === hover || i === pinned ? 0.25 : 0));
      q.setFromEuler(euler.set(0, a * (1 - e), 0));
      m4.compose(tmp.set(0, ay, pop), q, s.setScalar(bs));
      blocks.setMatrixAt(i, m4);
      col.copy(colBlock[i]).multiplyScalar(1 + (i === hover || i === pinned ? 1.2 : 0) + flash[i] * 2.5);
      blocks.setColorAt(i, col);
    }
    nodes.instanceMatrix.needsUpdate = rungs.instanceMatrix.needsUpdate = blocks.instanceMatrix.needsUpdate = true;
    blocks.instanceColor.needsUpdate = true;

    canvas.style.cursor = onSelect && hover >= 0 ? 'pointer' : edge ? (edge > 0 ? 'n-resize' : 's-resize') : '';
    if (hover >= 0 && hover !== pinned && mix[hover] > 0.6) {
      const [sx, sy] = screenOf(tmp.copy(centers[hover]).applyMatrix4(root.matrixWorld));
      onHover({ index: hover, x: sx, y: sy, base: seq[hover] + PAIR[seq[hover]] });
    } else onHover(null);

    composer.render();
    requestAnimationFrame(frame);
  }
  requestAnimationFrame(frame);

  return {
    // Append a pair (a newly learned cure) and light it up.
    add(hash) {
      const i = add(hash);
      if (i !== undefined) flash[i] = 1;
      follow = true;
    },
    // Scroll block i into view (edgeScroll only); resolves with the same hit shape onSelect gets, once it's there.
    reveal(i) {
      if (!edgeScroll) return Promise.resolve(null);
      return new Promise((done) => (seek = { i, done }));
    },
    pulse(i = (Math.random() * count) | 0) {
      flash[i] = 1;
    },
    // Hold block i popped out (-1 releases). Returns its current screen position.
    pin(i) {
      pinned = i;
      if (i < 0) return null;
      const [x, y] = screenOf(tmp.copy(centers[i]).applyMatrix4(root.matrixWorld));
      return { x, y };
    },
    // Empty the strand back to nothing. frame() only ever writes matrices for i < count,
    // so shrinking count alone would leave the last-rendered instances frozen visible;
    // zero them out here the same way the initial N-capacity setup above does.
    clear() {
      for (let i = 0; i < count; i++) {
        nodes.setMatrixAt(i * 2, zero);
        nodes.setMatrixAt(i * 2 + 1, zero);
        rungs.setMatrixAt(i, zero);
        blocks.setMatrixAt(i, zero);
      }
      nodes.instanceMatrix.needsUpdate = rungs.instanceMatrix.needsUpdate = blocks.instanceMatrix.needsUpdate = true;
      count = 0;
      seq.length = 0;
      colA.length = 0;
      colB.length = 0;
      colBlock.length = 0;
      born.fill(-1);
      hover = -1;
      pinned = -1;
      follow = true;
    },
  };
}
