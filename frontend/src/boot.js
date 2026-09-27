import * as THREE from 'three';
import { EffectComposer } from 'three/examples/jsm/postprocessing/EffectComposer.js';
import { RenderPass } from 'three/examples/jsm/postprocessing/RenderPass.js';
import { UnrealBloomPass } from 'three/examples/jsm/postprocessing/UnrealBloomPass.js';
import { OutputPass } from 'three/examples/jsm/postprocessing/OutputPass.js';

const clamp01 = (v) => Math.min(1, Math.max(0, v));

// One-shot boot splash: a single hexagon "virus" (same shape/shader family as
// website/src/helix.js's ambient field, reduced to one actor and a fixed
// timeline instead of that file's continuously-respawning field) spins red,
// turns green as if just cured, holds, then bursts into scattering dots.
// Returns a `stop()` the caller can invoke to force an early finish (skip).
export function runBoot(canvas, onDone) {
  if (matchMedia('(prefers-reduced-motion: reduce)').matches) {
    onDone();
    return () => {};
  }

  const renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: true });
  renderer.setPixelRatio(Math.min(devicePixelRatio, 2));
  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(40, 1, 0.1, 50);
  camera.position.set(0, 0, 6);

  // Virus shape: hexagon outline + 6 corner spikes, drawn once to a texture
  // (identical construction to website/src/helix.js's own virus texture).
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

  const vGeo = new THREE.BufferGeometry();
  vGeo.setAttribute('position', new THREE.BufferAttribute(new Float32Array([0, 0, 0]), 3));
  const vUniforms = {
    uMap: { value: new THREE.CanvasTexture(vCanvas) },
    uColor: { value: new THREE.Color('#ff3b5c') }, // matches the app's own --threat token
    uKilled: { value: new THREE.Color('#4ff5d2') }, // matches the app's own --a (cured/clean) token
    uAngle: { value: 0 },
    uKill: { value: 0 }, // 0 red -> 1 green
    uGrow: { value: 1 }, // shrinks to 0 as it pops
    uSize: { value: 2.3 },
    uScale: { value: 1 },
  };
  const virus = new THREE.Points(
    vGeo,
    new THREE.ShaderMaterial({
      uniforms: vUniforms,
      transparent: true,
      depthWrite: false,
      blending: THREE.AdditiveBlending,
      vertexShader: /* glsl */ `
        uniform float uSize;
        uniform float uGrow;
        uniform float uScale;
        void main() {
          vec4 mv = modelViewMatrix * vec4(position, 1.0);
          gl_PointSize = min(uSize * uGrow * uScale / -mv.z, 420.0);
          gl_Position = projectionMatrix * mv;
        }`,
      fragmentShader: /* glsl */ `
        uniform sampler2D uMap;
        uniform vec3 uColor;
        uniform vec3 uKilled;
        uniform float uAngle;
        uniform float uKill;
        void main() {
          vec2 p = gl_PointCoord - 0.5;
          float c = cos(uAngle), s = sin(uAngle);
          float a = texture2D(uMap, vec2(c * p.x - s * p.y, s * p.x + c * p.y) + 0.5).a;
          gl_FragColor = vec4(mix(uColor, uKilled, uKill) * a * (0.85 + uKill * 0.4), a);
        }`,
    }),
  );
  scene.add(virus);

  // Burst dots: scatter outward from the origin once the virus pops (mirrors
  // website/src/helix.js's burst(), centered here since there's only one actor).
  const BURST = 56;
  const bPos = new Float32Array(BURST * 3);
  const bVel = new Float32Array(BURST * 3);
  const bAge = new Float32Array(BURST).fill(99);
  const bAlpha = new Float32Array(BURST);
  const bGeo = new THREE.BufferGeometry();
  bGeo.setAttribute('position', new THREE.BufferAttribute(bPos, 3));
  bGeo.setAttribute('aAlpha', new THREE.BufferAttribute(bAlpha, 1));
  const bUniforms = { uColor: { value: new THREE.Color('#4ff5d2') }, uScale: vUniforms.uScale };
  const bursts = new THREE.Points(
    bGeo,
    new THREE.ShaderMaterial({
      uniforms: bUniforms,
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
          gl_PointSize = max(0.09 * uScale / -mv.z, 1.5);
          gl_Position = projectionMatrix * mv;
        }`,
      fragmentShader: /* glsl */ `
        uniform vec3 uColor;
        varying float vAlpha;
        void main() {
          float a = 1.0 - smoothstep(0.25, 0.5, length(gl_PointCoord - 0.5));
          gl_FragColor = vec4(uColor * a * vAlpha, a * vAlpha);
        }`,
    }),
  );
  scene.add(bursts);

  function burstNow() {
    for (let j = 0; j < BURST; j++) {
      const u = Math.random() * 2 - 1;
      const th = Math.random() * Math.PI * 2;
      const r = Math.sqrt(1 - u * u);
      const sp = 2.2 + Math.random() * 3.2;
      bVel[j * 3] = r * Math.cos(th) * sp;
      bVel[j * 3 + 1] = r * Math.sin(th) * sp;
      bVel[j * 3 + 2] = u * sp;
      bPos[j * 3] = bPos[j * 3 + 1] = bPos[j * 3 + 2] = 0;
      bAge[j] = 0;
    }
  }

  const composer = new EffectComposer(renderer);
  composer.addPass(new RenderPass(scene, camera));
  const bloom = new UnrealBloomPass(new THREE.Vector2(1, 1), 1.1, 0.6, 0.15);
  composer.addPass(bloom);
  composer.addPass(new OutputPass());

  const tmp2 = new THREE.Vector2();
  function resize() {
    const w = canvas.clientWidth || 1;
    const h = canvas.clientHeight || 1;
    renderer.setSize(w, h, false);
    composer.setSize(w, h);
    bloom.setSize(w, h);
    camera.aspect = w / h;
    camera.updateProjectionMatrix();
    vUniforms.uScale.value = renderer.getDrawingBufferSize(tmp2).y / (2 * Math.tan(THREE.MathUtils.degToRad(camera.fov / 2)));
  }
  const ro = new ResizeObserver(resize);
  ro.observe(canvas);
  resize();

  // One-shot timeline, seconds from start.
  const T_KILL_START = 1.0; // spins red until here
  const T_KILL_END = 1.6; // turns green over this window
  const T_HOLD_END = 2.0; // holds green, then starts popping
  const T_POP_END = 2.25; // fully popped (burst fires at T_HOLD_END)
  const T_BURST_LIFE = 1.6; // how long the scattered dots take to fade
  const T_DONE = T_POP_END + T_BURST_LIFE;

  let raf = 0;
  let last = 0;
  let start = 0;
  let burstFired = false;
  let stopped = false;

  function frame(now) {
    if (stopped) return;
    if (!start) start = now;
    const t = (now - start) / 1000;
    const dt = Math.min(0.05, last ? (now - last) / 1000 : 0);
    last = now;

    vUniforms.uAngle.value = t * 1.6;
    vUniforms.uKill.value = clamp01((t - T_KILL_START) / (T_KILL_END - T_KILL_START));
    vUniforms.uGrow.value = 1 - clamp01((t - T_HOLD_END) / (T_POP_END - T_HOLD_END));

    if (t >= T_HOLD_END && !burstFired) {
      burstFired = true;
      burstNow();
    }

    const drag = Math.exp(-dt * 1.4);
    for (let j = 0; j < BURST; j++) {
      if (bAge[j] >= T_BURST_LIFE) {
        bAlpha[j] = 0;
        continue;
      }
      bAge[j] += dt;
      for (let k = 0; k < 3; k++) {
        bPos[j * 3 + k] += bVel[j * 3 + k] * dt;
        bVel[j * 3 + k] *= drag;
      }
      const p = bAge[j] / T_BURST_LIFE;
      bAlpha[j] = Math.min(1, p * 10) * (1 - p * p);
    }
    bGeo.attributes.position.needsUpdate = bGeo.attributes.aAlpha.needsUpdate = true;

    composer.render();

    if (t >= T_DONE) {
      finish();
      return;
    }
    raf = requestAnimationFrame(frame);
  }
  raf = requestAnimationFrame(frame);

  function finish() {
    if (stopped) return;
    stopped = true;
    cancelAnimationFrame(raf);
    ro.disconnect();
    composer.dispose();
    renderer.dispose();
    vGeo.dispose();
    bGeo.dispose();
    virus.material.dispose();
    bursts.material.dispose();
    vUniforms.uMap.value.dispose();
    onDone();
  }

  return finish; // caller can force an early finish (skip)
}
