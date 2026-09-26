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
  const state = { build: 0, chain: 0, x: 0, y: 0, tilt: 0, scale: 1, follow: 0, mesh: 0, meshX: 0, meshY: 0, meshScale: 1 };
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

  // Enterprise mesh: blocks regroup into sites (a relay plus its devices) wired into one network.
  const SITES = mobile ? 5 : 6;
  const site = Array.from({ length: N }, (_, i) => i % SITES); // block i < SITES is its site's relay
  const meshBase = Array.from({ length: N }, () => new THREE.Vector3());
  // Laid flat like a network map: relays on a ring, each site's devices evenly spaced round their relay.
  const PER = Math.ceil((N - SITES) / SITES);
  const RING = 3.4;
  const LOCAL = 1.05;
  for (let c = 0; c < SITES; c++) {
    const th = (c / SITES) * Math.PI * 2;
    meshBase[c].set(Math.cos(th) * RING, 0, Math.sin(th) * RING);
  }
  for (let i = SITES; i < N; i++) {
    const k = Math.floor((i - SITES) / SITES); // i-th device of its site
    const th = (k / PER) * Math.PI * 2 + site[i] * 0.4;
    meshBase[i].set(Math.cos(th) * LOCAL, 0, Math.sin(th) * LOCAL).add(meshBase[site[i]]);
  }
  // Relays wired round the ring and across the middle; each device to its relay and its neighbours on the site ring.
  const edges = [];
  const seen = new Set();
  const link = (a, b) => {
    const k = Math.min(a, b) * N + Math.max(a, b);
    if (!seen.has(k)) seen.add(k), edges.push(a, b);
  };
  for (let c = 0; c < SITES; c++) link(c, (c + 1) % SITES), link(c, (c + SITES / 2) % SITES | 0);
  for (let i = SITES; i < N; i++) {
    link(i, site[i]);
    const next = i + SITES < N ? i + SITES : SITES + site[i]; // next device on the same ring, wrapping to the first
    if (next !== i) link(i, next);
  }
  const E = edges.length / 2;
  const mPos = new Float32Array(E * 6);
  const mCol = new Float32Array(E * 6);
  const meshGeo = new THREE.BufferGeometry();
  meshGeo.setAttribute('position', new THREE.BufferAttribute(mPos, 3));
  meshGeo.setAttribute('color', new THREE.BufferAttribute(mCol, 3));
  const meshLinks = new THREE.LineSegments(
    meshGeo,
    new THREE.LineBasicMaterial({ vertexColors: true, transparent: true, blending: THREE.AdditiveBlending, depthWrite: false }),
  );
  meshLinks.frustumCulled = false;
  root.add(meshLinks);
  const waves = []; // [time, block] flashes queued by wave()
  const WAVE = 0.4; // gentler than a single pulse: the whole mesh lights at once, and bloom sums it

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

  // Viruses: a hexagon with a spike at each corner, drawn once to a texture. Each one drifts,
  // turns green as the immune system kills it, pops out, and respawns somewhere else.
  const vCanvas = document.createElement('canvas');
  vCanvas.width = vCanvas.height = 128;
  const vx = vCanvas.getContext('2d');
  vx.translate(64, 64);
  vx.strokeStyle = vx.fillStyle = '#fff';
  vx.lineCap = vx.lineJoin = 'round';
  vx.lineWidth = 8;
  const corner = (k, r) => [Math.cos((k / 6) * Math.PI * 2) * r, Math.sin((k / 6) * Math.PI * 2) * r];
  vx.beginPath();
  for (let k = 0; k < 6; k++) vx.lineTo(...corner(k, 30));
  vx.closePath();
  vx.stroke();
  for (let k = 0; k < 6; k++) {
    vx.beginPath();
    vx.moveTo(...corner(k, 30));
    vx.lineTo(...corner(k, 48));
    vx.stroke();
    vx.beginPath();
    vx.arc(...corner(k, 52), 7, 0, Math.PI * 2);
    vx.fill();
  }

  const V = mobile ? 8 : 18;
  const VIRUS_LIFE = [7, 13]; // seconds from appearing to death
  const VIRUS_SLEEP = [3, 10]; // seconds hidden before the next one appears
  const vPos = new Float32Array(V * 3);
  const vSeed = new Float32Array(V * 2); // [spin phase, spin speed]
  const vSize = new Float32Array(V);
  const vKill = new Float32Array(V); // 0 = red/alive, 1 = green/killed
  const vAlpha = new Float32Array(V);
  const vGrow = new Float32Array(V);
  const vVel = new Float32Array(V * 3);
  const vAge = new Float32Array(V);
  const vLife = new Float32Array(V);
  function spawnVirus(i, age = 0) {
    vPos[i * 3] = (Math.random() - 0.5) * 34;
    vPos[i * 3 + 1] = (Math.random() - 0.5) * 22;
    vPos[i * 3 + 2] = (Math.random() - 0.5) * 18 - 3;
    const a = Math.random() * Math.PI * 2;
    const sp = 0.35 + Math.random() * 0.45; // world units / s
    vVel[i * 3] = Math.cos(a) * sp;
    vVel[i * 3 + 1] = Math.sin(a) * sp;
    vVel[i * 3 + 2] = (Math.random() - 0.5) * 0.3;
    vSeed[i * 2] = Math.random() * Math.PI * 2;
    vSeed[i * 2 + 1] = (Math.random() < 0.5 ? -1 : 1) * (0.3 + Math.random() * 0.6);
    vSize[i] = 0.26 + Math.random() * 0.2;
    vLife[i] = VIRUS_LIFE[0] + Math.random() * (VIRUS_LIFE[1] - VIRUS_LIFE[0]);
    vAge[i] = age;
  }
  const sleep = () => -(VIRUS_SLEEP[0] + Math.random() * (VIRUS_SLEEP[1] - VIRUS_SLEEP[0])); // negative age = not yet visible
  for (let i = 0; i < V; i++) spawnVirus(i, VIRUS_LIFE[0] * (Math.random() * 1.6 - 0.6)); // staggered so they don't die in sync
  const vGeo = new THREE.BufferGeometry();
  vGeo.setAttribute('position', new THREE.BufferAttribute(vPos, 3));
  vGeo.setAttribute('aSeed', new THREE.BufferAttribute(vSeed, 2));
  vGeo.setAttribute('aSize', new THREE.BufferAttribute(vSize, 1));
  vGeo.setAttribute('aKill', new THREE.BufferAttribute(vKill, 1));
  vGeo.setAttribute('aAlpha', new THREE.BufferAttribute(vAlpha, 1));
  vGeo.setAttribute('aGrow', new THREE.BufferAttribute(vGrow, 1));
  const vUniforms = {
    uMap: { value: new THREE.CanvasTexture(vCanvas) },
    uColor: { value: new THREE.Color('#b0263f') },
    uKilled: { value: new THREE.Color('#47ff9a') },
    uTime: { value: 0 },
    uScale: { value: 1 }, // pixels per world unit at distance 1; set in resize()
  };
  const viruses = new THREE.Points(
    vGeo,
    new THREE.ShaderMaterial({
      uniforms: vUniforms,
      transparent: true,
      depthWrite: false,
      blending: THREE.AdditiveBlending,
      vertexShader: /* glsl */ `
        attribute vec2 aSeed;
        attribute float aSize;
        attribute float aKill;
        attribute float aAlpha;
        attribute float aGrow;
        uniform float uTime;
        uniform float uScale;
        varying float vAngle;
        varying float vFade;
        varying float vKill;
        void main() {
          vec4 mv = modelViewMatrix * vec4(position, 1.0);
          float dist = -mv.z;
          vAngle = aSeed.x + uTime * aSeed.y;
          vKill = aKill;
          vFade = aAlpha * smoothstep(0.6, 2.5, dist) * (1.0 - smoothstep(10.0, 24.0, dist)); // hide when clipping the lens or lost in fog
          gl_PointSize = min(aSize * aGrow * uScale / dist, 160.0);
          gl_Position = projectionMatrix * mv;
        }`,
      fragmentShader: /* glsl */ `
        uniform sampler2D uMap;
        uniform vec3 uColor;
        uniform vec3 uKilled;
        varying float vAngle;
        varying float vFade;
        varying float vKill;
        void main() {
          vec2 p = gl_PointCoord - 0.5;
          float c = cos(vAngle), s = sin(vAngle);
          float a = texture2D(uMap, vec2(c * p.x - s * p.y, s * p.x + c * p.y) + 0.5).a;
          gl_FragColor = vec4(mix(uColor, uKilled, vKill) * a * (0.85 + vKill * 0.4) * vFade, 1.0);
        }`,
    }),
  );
  viruses.frustumCulled = false;
  scene.add(viruses);

  // Burst: a killed virus scatters into dots that match the background field.
  const BURST = 16;
  const bPos = new Float32Array(V * BURST * 3);
  const bVel = new Float32Array(V * BURST * 3);
  const bAge = new Float32Array(V * BURST).fill(99);
  const bLife = new Float32Array(V * BURST).fill(1);
  const bAlpha = new Float32Array(V * BURST);
  const bGeo = new THREE.BufferGeometry();
  bGeo.setAttribute('position', new THREE.BufferAttribute(bPos, 3));
  bGeo.setAttribute('aAlpha', new THREE.BufferAttribute(bAlpha, 1));
  const bursts = new THREE.Points(
    bGeo,
    new THREE.ShaderMaterial({
      uniforms: { uColor: { value: new THREE.Color(0x7fb6ff) }, uScale: vUniforms.uScale },
      transparent: true,
      depthWrite: false,
      blending: THREE.AdditiveBlending,
      vertexShader: /* glsl */ `
        attribute float aAlpha;
        uniform float uScale;
        varying float vAlpha;
        void main() {
          vec4 mv = modelViewMatrix * vec4(position, 1.0);
          vAlpha = aAlpha;
          gl_PointSize = max(0.05 * uScale / -mv.z, 1.5);
          gl_Position = projectionMatrix * mv;
        }`,
      fragmentShader: /* glsl */ `
        uniform vec3 uColor;
        varying float vAlpha;
        void main() {
          float a = 1.0 - smoothstep(0.25, 0.5, length(gl_PointCoord - 0.5));
          gl_FragColor = vec4(uColor * a * vAlpha, 1.0);
        }`,
    }),
  );
  bursts.frustumCulled = false;
  scene.add(bursts);

  function burst(i) {
    for (let j = 0; j < BURST; j++) {
      const n = i * BURST + j;
      // random direction on a sphere
      const u = Math.random() * 2 - 1;
      const th = Math.random() * Math.PI * 2;
      const r = Math.sqrt(1 - u * u);
      const sp = 0.8 + Math.random() * 1.6;
      for (let k = 0; k < 3; k++) bPos[n * 3 + k] = vPos[i * 3 + k];
      bVel[n * 3] = r * Math.cos(th) * sp;
      bVel[n * 3 + 1] = r * Math.sin(th) * sp;
      bVel[n * 3 + 2] = u * sp;
      bAge[n] = 0;
      bLife[n] = 1.4 + Math.random() * 1.4;
    }
  }

  // Per-frame virus lifecycle: fade in, drift, turn green, pop, respawn.
  function stepViruses(dt) {
    for (let i = 0; i < V; i++) {
      const before = vLife[i] - vAge[i];
      vAge[i] += dt;
      const left = vLife[i] - vAge[i];
      if (left <= 0) {
        spawnVirus(i, sleep());
        vAlpha[i] = 0;
        continue;
      }
      if (before > 0.25 && left <= 0.25) burst(i);
      for (let k = 0; k < 3; k++) vPos[i * 3 + k] += vVel[i * 3 + k] * dt * (left < 2.2 ? 0.25 : 1); // slows as it's caught
      const kill = clamp01((2.2 - left) / 0.5); // turns green over 0.5s, holds green…
      const pop = clamp01((0.25 - left) / 0.25); // …then shrinks away as it bursts
      vKill[i] = kill;
      vAlpha[i] = clamp01(vAge[i] / 0.8) * (1 - pop);
      vGrow[i] = 1 - pop * 0.6;
    }
    for (const n of ['position', 'aKill', 'aAlpha', 'aGrow']) vGeo.attributes[n].needsUpdate = true;

    const drag = Math.exp(-dt * 2.2); // shards coast to a stop like the drifting field
    for (let n = 0; n < V * BURST; n++) {
      if (bAge[n] >= bLife[n]) {
        bAlpha[n] = 0;
        continue;
      }
      bAge[n] += dt;
      for (let k = 0; k < 3; k++) {
        bPos[n * 3 + k] += bVel[n * 3 + k] * dt;
        bVel[n * 3 + k] *= drag;
      }
      const p = bAge[n] / bLife[n];
      bAlpha[n] = 0.75 * Math.min(1, p * 12) * (1 - p * p);
    }
    bGeo.attributes.position.needsUpdate = bGeo.attributes.aAlpha.needsUpdate = true;
  }

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
  const bp = new THREE.Vector3();
  const mp = new THREE.Vector3();
  const meshRot = new THREE.Matrix4();
  const lerp = THREE.MathUtils.lerp;

  const tmp2 = new THREE.Vector2();
  function resize() {
    const w = innerWidth;
    const h = innerHeight;
    renderer.setSize(w, h, false);
    composer.setSize(w, h);
    bloom.setSize(w, h);
    camera.aspect = w / h;
    camera.updateProjectionMatrix();
    vUniforms.uScale.value = renderer.getDrawingBufferSize(tmp2).y / (2 * Math.tan(THREE.MathUtils.degToRad(camera.fov / 2)));
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

  // A cure spreading: one device learns it, its relay passes it on, every other site inherits it.
  function wave(from = SITES + ((Math.random() * (N - SITES)) | 0)) {
    const t0 = clock.elapsedTime;
    const home = site[from];
    waves.push([t0, from], [t0 + 0.25, home]);
    for (let c = 0; c < SITES; c++) if (c !== home) waves.push([t0 + 0.55, c]);
    for (let i = SITES; i < N; i++) if (i !== from) waves.push([t0 + (site[i] === home ? 0.4 : 0.8) + Math.random() * 0.25, i]);
  }

  function frame() {
    const dt = Math.min(clock.getDelta(), 0.05);
    const t = clock.elapsedTime;
    const speed = reduced ? 0.2 : 1;

    phase += dt * 0.35 * speed * (1 - state.chain * 0.85);
    flow += dt * 0.55 * speed * state.chain * (1 - clamp01(state.mesh));

    // Group placement. In chain mode the axis locks to a DOM anchor.
    let y = state.y;
    if (anchor && state.follow > 0) {
      const r = anchor.getBoundingClientRect();
      // Clamped: on a fast scroll the band can be screens away while follow is still mid-scrub
      const vh = visibleHeight();
      const ay = THREE.MathUtils.clamp((0.5 - (r.top + r.height / 2) / innerHeight) * vh, -vh * 0.6, vh * 0.6);
      y = THREE.MathUtils.lerp(state.y, ay, state.follow);
    }
    // Mesh stage blends the whole group toward its own resting place, so the scroll timeline never has to own two poses.
    const M = ease(clamp01(state.mesh));
    root.position.set(lerp(state.x, state.meshX, M), lerp(y, state.meshY, M), -6 * M); // sits well back behind the copy; distance also flattens the perspective
    root.rotation.z = state.tilt * (1 - M);
    root.scale.setScalar(lerp(state.scale, state.meshScale, M));
    meshRot.makeRotationFromEuler(euler.set(0.62, t * 0.05 * speed, 0)); // spin in-plane, then tip the map toward the camera
    for (let k = waves.length - 1; k >= 0; k--) if (waves[k][0] <= t) (flash[waves[k][1]] = Math.max(flash[waves[k][1]], WAVE)), waves.splice(k, 1);

    // Camera parallax
    camera.position.x += (pointer.nx * 0.6 - camera.position.x) * 0.04;
    camera.position.y += (-pointer.ny * 0.4 - camera.position.y) * 0.04;
    camera.lookAt(0, 0, 0);
    camera.updateMatrixWorld();
    root.updateMatrixWorld();

    // Hover pick: nearest pair centre on screen
    let best = -1;
    let hoverD = Infinity;
    let bestD = mobile ? 70 : 95;
    if (pointer.active && state.build > 0.95 && state.mesh < 0.5) { // the mesh is a backdrop: no probe over the copy
      for (let i = 0; i < N; i++) {
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
    // Stickiness avoids flicker between neighbours
    if (best !== -1 && hoverD - bestD < 4) best = hover; // a few px of hysteresis, so every neighbour stays reachable
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
      const a = slot * TWIST + phase; // twist by slot so the conveyor's wrap seam stays at the off-screen ends
      const pop = e * 0.35 * (1 - state.chain);
      // Sites gather one after another as the mesh forms.
      const em = ease(clamp01(state.mesh * 1.5 - (site[i] / SITES) * 0.5));
      mp.copy(meshBase[i]).applyMatrix4(meshRot);
      bp.set(0, ay, pop).lerp(mp, em);

      pA.set(Math.cos(a) * R, ay, Math.sin(a) * R).lerp(tmp.set(-CUBE * 0.5 - 0.02, ay, pop), e).lerp(bp, em);
      pB.set(-Math.cos(a) * R, ay, -Math.sin(a) * R).lerp(tmp.set(CUBE * 0.5 + 0.02, ay, pop), e).lerp(bp, em);
      centers[i].copy(bp);

      const nScale = build * (1 - 0.55 * e) * (1 - em);
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
      const bs = CUBE * e * build * (1 + (i === hover ? 0.25 : 0) + flash[i] * 0.5) * lerp(1, i < SITES ? 1.7 : 0.75, em);
      q.setFromEuler(euler.set(em * (t * 0.3 + i), a * (1 - e) + em * (t * 0.4 + i * 1.7), 0));
      m4.compose(bp, q, s.setScalar(bs));
      blocks.setMatrixAt(i, m4);
      col.copy(colBlock[i]).multiplyScalar((1 + (i === hover ? 1.2 : 0) + flash[i] * 2.5) * lerp(1, 0.45, em)); // mesh stays a backdrop
      blocks.setColorAt(i, col);

      // Link to next pair (skipped across the wrap seam)
      if (i < N - 1) {
        const nextSlot = (((i + 1 + flow) % N) + N) % N;
        const ok = nextSlot > slot;
        const k = ok ? Math.min(e, ease(mix[i + 1])) * build * clamp01(1 - state.mesh * 3) : 0;
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

    // Mesh wires appear once the nodes have mostly arrived; a wave lights them as it passes.
    const ML = clamp01(state.mesh * 2 - 1);
    meshLinks.visible = ML > 0;
    if (ML > 0) {
      for (let k = 0; k < E; k++) {
        const a = edges[k * 2];
        const b = edges[k * 2 + 1];
        centers[a].toArray(mPos, k * 6);
        centers[b].toArray(mPos, k * 6 + 3);
        col.copy(colBlock[a]).lerp(colBlock[b], 0.5).multiplyScalar(ML * (0.22 + (flash[a] + flash[b]) * 0.6));
        col.toArray(mCol, k * 6);
        col.toArray(mCol, k * 6 + 3);
      }
      meshGeo.attributes.position.needsUpdate = meshGeo.attributes.color.needsUpdate = true;
    }

    particles.rotation.y = t * 0.012;
    particles.position.y = Math.sin(t * 0.2) * 0.2;
    viruses.rotation.y = bursts.rotation.y = particles.rotation.y;
    viruses.position.y = bursts.position.y = particles.position.y;
    vUniforms.uTime.value = t;
    stepViruses(reduced ? dt * 0.3 : dt);

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
    wave,
    // Brighten a random on-screen block (used when a new block lands); in the mesh, send a cure wave instead.
    pulse() {
      if (state.mesh > 0.5) return wave();
      const visible = [];
      for (let i = 0; i < N; i++) {
        const [sx, sy] = screenOf(tmp.copy(centers[i]).applyMatrix4(root.matrixWorld));
        if (sx > 0 && sx < innerWidth && sy > 0 && sy < innerHeight) visible.push(i);
      }
      if (visible.length) flash[visible[(Math.random() * visible.length) | 0]] = 1;
    },
  };
}
