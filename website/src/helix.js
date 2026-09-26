import * as THREE from 'three';
import { EffectComposer } from 'three/examples/jsm/postprocessing/EffectComposer.js';
import { RenderPass } from 'three/examples/jsm/postprocessing/RenderPass.js';
import { UnrealBloomPass } from 'three/examples/jsm/postprocessing/UnrealBloomPass.js';
import { OutputPass } from 'three/examples/jsm/postprocessing/OutputPass.js';

// Nucleotide colours; the two strands always carry complementary bases.
const BASE = { A: '#4ff5d2', T: '#8f7bff', G: '#4ba3ff', C: '#f77fd1' };
const PAIR = { A: 'T', T: 'A', G: 'C', C: 'G' };
const BG = 0x02040b;

const clamp01 = (v) => Math.min(1, Math.max(0, v));
const ease = (t) => t * t * (3 - 2 * t);

// Deterministic per-block "hash" so the same block always reads the same.
export function blockHash(i, len = 8) {
  let h = 2166136261 ^ (i * 16777619);
  let out = '';
  while (out.length < len) {
    h = Math.imul(h ^ (h >>> 15), 2246822507);
    h = Math.imul(h ^ (h >>> 13), 3266489909);
    out += ((h ^= h >>> 16) >>> 0).toString(16).padStart(8, '0');
  }
  return out.slice(0, len);
}

export function createHelix(canvas, { reduced = false, onHover = () => {} } = {}) {
  const mobile = matchMedia('(max-width: 720px)').matches;
  const N = mobile ? 60 : 84;
  const SP = 0.34; // distance between base pairs along the axis
  const R = 0.62; // helix radius
  const TWIST = 0.36; // radians per base pair
  const CUBE = 0.23; // block edge length once unzipped

  const renderer = new THREE.WebGLRenderer({ canvas, antialias: true, powerPreference: 'high-performance' });
  renderer.setPixelRatio(Math.min(devicePixelRatio, mobile ? 1.5 : 2));

  const scene = new THREE.Scene();
  scene.background = new THREE.Color(BG); // colour-managed, unlike setClearColor through the composer
  scene.fog = new THREE.FogExp2(BG, 0.05);
  const camera = new THREE.PerspectiveCamera(40, 1, 0.1, 100);
  camera.position.set(0, 0, 11);

  // Everything scroll-driven lives in `state`; GSAP tweens these numbers.
  const state = { build: 0, chain: 0, x: 0, y: 0, tilt: 0, scale: 1, follow: 0 };
  let anchor = null;

  const root = new THREE.Group();
  scene.add(root);

  // Pair sequence
  const seq = Array.from({ length: N }, () => 'ATGC'[(Math.random() * 4) | 0]);
  const colA = seq.map((b) => new THREE.Color(BASE[b]));
  const colB = seq.map((b) => new THREE.Color(BASE[PAIR[b]]));
  const colBlock = seq.map((_, i) => colA[i].clone().lerp(colB[i], 0.5));

  // Backbone nodes
  const nodes = new THREE.InstancedMesh(
    new THREE.SphereGeometry(0.062, 14, 10),
    new THREE.MeshBasicMaterial({ toneMapped: false }),
    N * 2,
  );
  for (let i = 0; i < N; i++) {
    nodes.setColorAt(i * 2, colA[i]);
    nodes.setColorAt(i * 2 + 1, colB[i]);
  }
  root.add(nodes);

  // Rungs (hydrogen bonds)
  const rungGeo = new THREE.CylinderGeometry(0.011, 0.011, 1, 6);
  const rungs = new THREE.InstancedMesh(
    rungGeo,
    new THREE.MeshBasicMaterial({ toneMapped: false, transparent: true, opacity: 0.55, blending: THREE.AdditiveBlending, depthWrite: false }),
    N,
  );
  for (let i = 0; i < N; i++) rungs.setColorAt(i, colBlock[i]);
  root.add(rungs);

  // Blocks: glowing edges + faint ledger rows, drawn from box UVs.
  const blocks = new THREE.InstancedMesh(
    new THREE.BoxGeometry(1, 1, 1),
    new THREE.ShaderMaterial({
      transparent: true,
      depthWrite: false,
      blending: THREE.AdditiveBlending,
      vertexShader: /* glsl */ `
        varying vec2 vUv;
        varying vec3 vColor;
        void main() {
          vUv = uv;
          vColor = instanceColor;
          gl_Position = projectionMatrix * modelViewMatrix * instanceMatrix * vec4(position, 1.0);
        }`,
      fragmentShader: /* glsl */ `
        varying vec2 vUv;
        varying vec3 vColor;
        void main() {
          float d = min(min(vUv.x, 1.0 - vUv.x), min(vUv.y, 1.0 - vUv.y));
          float edge = 1.0 - smoothstep(0.0, 0.07, d);
          float rows = step(0.86, fract(vUv.y * 4.0)) * step(0.18, vUv.x) * step(vUv.x, 0.82);
          gl_FragColor = vec4(vColor * (edge * 1.5 + rows * 0.35 + 0.07), 1.0);
        }`,
    }),
    N,
  );
  root.add(blocks);

  // Chain links between neighbouring blocks
  const linkPos = new Float32Array((N - 1) * 6);
  const linkCol = new Float32Array((N - 1) * 6);
  const linkGeo = new THREE.BufferGeometry();
  linkGeo.setAttribute('position', new THREE.BufferAttribute(linkPos, 3));
  linkGeo.setAttribute('color', new THREE.BufferAttribute(linkCol, 3));
  const links = new THREE.LineSegments(
    linkGeo,
    new THREE.LineBasicMaterial({ vertexColors: true, transparent: true, blending: THREE.AdditiveBlending, depthWrite: false }),
  );
  links.frustumCulled = false;
  root.add(links);

  // Drifting particles: free antigens / antibodies in the field
  const P = mobile ? 600 : 1400;
  const pPos = new Float32Array(P * 3);
  for (let i = 0; i < P; i++) {
    pPos[i * 3] = (Math.random() - 0.5) * 34;
    pPos[i * 3 + 1] = (Math.random() - 0.5) * 22;
    pPos[i * 3 + 2] = (Math.random() - 0.5) * 18 - 3;
  }
  const pGeo = new THREE.BufferGeometry();
  pGeo.setAttribute('position', new THREE.BufferAttribute(pPos, 3));
  const particles = new THREE.Points(
    pGeo,
    new THREE.PointsMaterial({ color: 0x7fb6ff, size: 0.035, transparent: true, opacity: 0.55, blending: THREE.AdditiveBlending, depthWrite: false }),
  );
  scene.add(particles);

  // Post
  const composer = new EffectComposer(renderer);
  composer.addPass(new RenderPass(scene, camera));
  const bloom = new UnrealBloomPass(new THREE.Vector2(1, 1), 0.85, 0.55, 0.12);
  composer.addPass(bloom);
  composer.addPass(new OutputPass());

  // Per-pair animated values
  const mix = new Float32Array(N); // 0 = helix, 1 = block
  const flash = new Float32Array(N);
  const centers = Array.from({ length: N }, () => new THREE.Vector3());

  const pointer = { x: -1e4, y: -1e4, nx: 0, ny: 0, active: false };
  let hover = -1;
  let phase = 0;
  let flow = 0;

  const m4 = new THREE.Matrix4();
  const q = new THREE.Quaternion();
  const s = new THREE.Vector3();
  const pA = new THREE.Vector3();
  const pB = new THREE.Vector3();
  const tmp = new THREE.Vector3();
  const up = new THREE.Vector3(0, 1, 0);
  const col = new THREE.Color();
  const euler = new THREE.Euler();

  function resize() {
    const w = innerWidth;
    const h = innerHeight;
    renderer.setSize(w, h, false);
    composer.setSize(w, h);
    bloom.setSize(w, h);
    camera.aspect = w / h;
    camera.updateProjectionMatrix();
  }
  resize();
  addEventListener('resize', resize);

  addEventListener('pointermove', (e) => {
    pointer.x = e.clientX;
    pointer.y = e.clientY;
    pointer.nx = e.clientX / innerWidth - 0.5;
    pointer.ny = e.clientY / innerHeight - 0.5;
    pointer.active = true;
  });
  document.addEventListener('pointerleave', () => (pointer.active = false));

  const visibleHeight = () => 2 * camera.position.z * Math.tan(THREE.MathUtils.degToRad(camera.fov / 2));

  function screenOf(v) {
    tmp.copy(v).project(camera);
    return [(tmp.x * 0.5 + 0.5) * innerWidth, (-tmp.y * 0.5 + 0.5) * innerHeight, tmp.z];
  }

  const clock = new THREE.Clock();

  function frame() {
    const dt = Math.min(clock.getDelta(), 0.05);
    const t = clock.elapsedTime;
    const speed = reduced ? 0.2 : 1;

    phase += dt * 0.35 * speed * (1 - state.chain * 0.85);
    flow += dt * 0.55 * speed * state.chain;

    // Group placement. In chain mode the axis locks to a DOM anchor.
    let y = state.y;
    if (anchor && state.follow > 0) {
      const r = anchor.getBoundingClientRect();
      const ay = (0.5 - (r.top + r.height / 2) / innerHeight) * visibleHeight();
      y = THREE.MathUtils.lerp(state.y, ay, state.follow);
    }
    root.position.set(state.x, y, 0);
    root.rotation.z = state.tilt;
    root.scale.setScalar(state.scale);

    // Camera parallax
    camera.position.x += (pointer.nx * 0.6 - camera.position.x) * 0.04;
    camera.position.y += (-pointer.ny * 0.4 - camera.position.y) * 0.04;
    camera.lookAt(0, 0, 0);
    camera.updateMatrixWorld();
    root.updateMatrixWorld();

    // Hover pick: nearest pair centre on screen
    let best = -1;
    let bestD = mobile ? 70 : 95;
    if (pointer.active && state.build > 0.95) {
      for (let i = 0; i < N; i++) {
        const [sx, sy] = screenOf(tmp.copy(centers[i]).applyMatrix4(root.matrixWorld));
        const d = Math.hypot(sx - pointer.x, sy - pointer.y);
        if (d < bestD) {
          bestD = d;
          best = i;
        }
      }
    }
    // Stickiness avoids flicker between neighbours
    if (best !== -1 && hover !== -1 && Math.abs(best - hover) <= 1) best = hover;
    if (best !== hover) hover = best;

    const half = (N - 1) / 2;
    for (let i = 0; i < N; i++) {
      const build = ease(clamp01((state.build * (N + 12) - i) / 12));
      const hv = hover >= 0 ? clamp01(1 - (Math.abs(i - hover) - 2) / 4) : 0;
      const target = Math.max(hv, state.chain);
      mix[i] += (target - mix[i]) * Math.min(1, dt * (reduced ? 12 : 5));
      flash[i] *= 1 - Math.min(1, dt * 1.6);
      const e = ease(mix[i]);

      // Slot along the axis; in chain mode pairs conveyor forward and wrap off-screen.
      const slot = (((i + flow) % N) + N) % N;
      const ay = (slot - half) * SP;
      const a = i * TWIST + phase;
      const pop = e * 0.35 * (1 - state.chain);

      pA.set(Math.cos(a) * R, ay, Math.sin(a) * R).lerp(tmp.set(-CUBE * 0.5 - 0.02, ay, pop), e);
      pB.set(-Math.cos(a) * R, ay, -Math.sin(a) * R).lerp(tmp.set(CUBE * 0.5 + 0.02, ay, pop), e);
      centers[i].set(0, ay, pop);

      const nScale = build * (1 - 0.55 * e);
      m4.compose(pA, q.identity(), s.setScalar(nScale));
      nodes.setMatrixAt(i * 2, m4);
      m4.compose(pB, q, s);
      nodes.setMatrixAt(i * 2 + 1, m4);

      // Rung between the two nodes, fading as it becomes a block
      tmp.subVectors(pB, pA);
      const len = tmp.length();
      q.setFromUnitVectors(up, tmp.normalize());
      m4.compose(tmp.addVectors(pA, pB).multiplyScalar(0.5), q, s.set(build * (1 - e), len, build * (1 - e)));
      rungs.setMatrixAt(i, m4);

      // Block untwists into alignment as it forms
      const bs = CUBE * e * build * (1 + (i === hover ? 0.25 : 0) + flash[i] * 0.5);
      q.setFromEuler(euler.set(0, a * (1 - e), 0));
      m4.compose(tmp.set(0, ay, pop), q, s.setScalar(bs));
      blocks.setMatrixAt(i, m4);
      col.copy(colBlock[i]).multiplyScalar(1 + (i === hover ? 1.2 : 0) + flash[i] * 2.5);
      blocks.setColorAt(i, col);

      // Link to next pair (skipped across the wrap seam)
      if (i < N - 1) {
        const nextSlot = (((i + 1 + flow) % N) + N) % N;
        const ok = nextSlot > slot;
        const k = ok ? Math.min(e, ease(mix[i + 1])) * build : 0;
        const o = i * 6;
        linkPos[o] = 0; linkPos[o + 1] = ay + bs * 0.5; linkPos[o + 2] = pop;
        linkPos[o + 3] = 0; linkPos[o + 4] = ay + SP - bs * 0.5; linkPos[o + 5] = pop;
        col.copy(colBlock[i]).multiplyScalar(k * 0.9);
        linkCol[o] = linkCol[o + 3] = col.r;
        linkCol[o + 1] = linkCol[o + 4] = col.g;
        linkCol[o + 2] = linkCol[o + 5] = col.b;
      }
    }
    nodes.instanceMatrix.needsUpdate = true;
    rungs.instanceMatrix.needsUpdate = true;
    blocks.instanceMatrix.needsUpdate = true;
    blocks.instanceColor.needsUpdate = true;
    linkGeo.attributes.position.needsUpdate = true;
    linkGeo.attributes.color.needsUpdate = true;

    particles.rotation.y = t * 0.012;
    particles.position.y = Math.sin(t * 0.2) * 0.2;

    // Report hover to the DOM probe
    if (hover >= 0 && mix[hover] > 0.6) {
      const [sx, sy] = screenOf(tmp.copy(centers[hover]).applyMatrix4(root.matrixWorld));
      onHover({ index: hover, x: sx, y: sy, base: seq[hover] + PAIR[seq[hover]] });
    } else onHover(null);

    composer.render();
    requestAnimationFrame(frame);
  }
  requestAnimationFrame(frame);

  return {
    state,
    setAnchor: (el) => (anchor = el),
    // Brighten a random on-screen block (used when a new block lands).
    pulse() {
      const visible = [];
      for (let i = 0; i < N; i++) {
        const [sx, sy] = screenOf(tmp.copy(centers[i]).applyMatrix4(root.matrixWorld));
        if (sx > 0 && sx < innerWidth && sy > 0 && sy < innerHeight) visible.push(i);
      }
      if (visible.length) flash[visible[(Math.random() * visible.length) | 0]] = 1;
    },
  };
}
