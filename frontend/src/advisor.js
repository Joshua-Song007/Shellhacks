import * as THREE from 'three';
import gsap from 'gsap';

// The advisor's avatar: a flat-shaded d20 (yellow cap, orange base) with a face.
// Idles with a float + sway and an occasional full spin, leans toward the
// pointer, hops on click, and can be dragged around freely (springs back to
// face you). `setMood(phase)` follows the health phase; `nudge()` is the
// "I have something to tell you" bounce.
const GOLD = new THREE.Color('#f2c84b');
const PALE = new THREE.Color('#fdf28a');
const BRIGHT = new THREE.Color('#fff35c');
const ORANGE = new THREE.Color('#ec7236');
const INK = '#0b0d16';
const TAU = Math.PI * 2;

function roundRect(w, h, r) {
  const s = new THREE.Shape();
  s.moveTo(-w / 2 + r, -h / 2);
  s.lineTo(w / 2 - r, -h / 2);
  s.quadraticCurveTo(w / 2, -h / 2, w / 2, -h / 2 + r);
  s.lineTo(w / 2, h / 2 - r);
  s.quadraticCurveTo(w / 2, h / 2, w / 2 - r, h / 2);
  s.lineTo(-w / 2 + r, h / 2);
  s.quadraticCurveTo(-w / 2, h / 2, -w / 2, h / 2 - r);
  s.lineTo(-w / 2, -h / 2 + r);
  s.quadraticCurveTo(-w / 2, -h / 2, -w / 2 + r, -h / 2);
  return new THREE.ShapeGeometry(s, 6);
}

function d20() {
  const g = new THREE.IcosahedronGeometry(1, 0);
  // Stand it on a vertex, like the sketch: (0, 1, φ) is a vertex of three's icosahedron.
  g.applyQuaternion(new THREE.Quaternion().setFromUnitVectors(new THREE.Vector3(0, 1, (1 + Math.sqrt(5)) / 2).normalize(), new THREE.Vector3(0, 1, 0)));
  const pos = g.attributes.position;
  const faces = [];
  for (let i = 0; i < pos.count; i += 3) {
    const c = new THREE.Vector3().fromBufferAttribute(pos, i).add(new THREE.Vector3().fromBufferAttribute(pos, i + 1)).add(new THREE.Vector3().fromBufferAttribute(pos, i + 2)).divideScalar(3);
    faces.push(c);
  }
  // Turn the downward-pointing band face with the highest centroid toward the camera: that's the face's "nose" triangle.
  const front = faces.filter((c) => c.y > 0.05 && c.y < 0.3)[0];
  g.rotateY(-Math.atan2(front.x, front.z));
  const colors = [];
  for (let i = 0; i < pos.count; i += 3) {
    const c = new THREE.Vector3().fromBufferAttribute(pos, i).add(new THREE.Vector3().fromBufferAttribute(pos, i + 1)).add(new THREE.Vector3().fromBufferAttribute(pos, i + 2)).divideScalar(3);
    const col = c.y > 0.5 ? GOLD : c.y < -0.5 ? ORANGE : c.y > 0 ? PALE : Math.abs(c.x) > 0.5 ? BRIGHT : GOLD;
    for (let k = 0; k < 3; k++) colors.push(col.r, col.g, col.b);
  }
  g.setAttribute('color', new THREE.Float32BufferAttribute(colors, 3));
  return g;
}

function groundShadow() {
  const c = document.createElement('canvas');
  c.width = c.height = 64;
  const x = c.getContext('2d');
  const grad = x.createRadialGradient(32, 32, 0, 32, 32, 32);
  grad.addColorStop(0, 'rgba(0,0,0,0.55)');
  grad.addColorStop(1, 'rgba(0,0,0,0)');
  x.fillStyle = grad;
  x.fillRect(0, 0, 64, 64);
  const m = new THREE.Mesh(new THREE.PlaneGeometry(1.6, 0.5), new THREE.MeshBasicMaterial({ map: new THREE.CanvasTexture(c), transparent: true, depthWrite: false }));
  m.position.y = -1.45;
  return m;
}

const FOV = 32; // vertical fov across the button's own height

export function createAdvisorAvatar(canvas, { reduced = false } = {}) {
  const box = canvas.parentElement; // the hit area; the canvas overhangs it so hops aren't clipped
  const renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: true });
  renderer.setPixelRatio(Math.min(devicePixelRatio, 2));
  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(FOV, 1, 0.1, 50);
  camera.position.set(0, 0.05, 4.7);

  scene.add(new THREE.HemisphereLight('#fff8e0', '#ffb070', 2.4));
  const key = new THREE.DirectionalLight('#ffffff', 1.4);
  key.position.set(-2, 3, 4);
  scene.add(key);
  const rim = new THREE.DirectionalLight('#4ff5d2', 1.1); // the app's teal, catching the back edges
  rim.position.set(3, 1, -3);
  scene.add(rim);

  const shadow = groundShadow();
  scene.add(shadow);
  const float = new THREE.Group(); // bob + squash
  const body = new THREE.Group(); // spin/drag rotation
  float.add(body);
  scene.add(float);
  body.add(new THREE.Mesh(d20(), new THREE.MeshStandardMaterial({ vertexColors: true, flatShading: true, roughness: 0.85, metalness: 0, emissive: '#5a3000', emissiveIntensity: 0.4 })));

  // Lit edges, the same glowing-wireframe language as the helix blocks.
  body.add(new THREE.LineSegments(new THREE.EdgesGeometry(body.children[0].geometry), new THREE.LineBasicMaterial({ color: '#7afbe2', transparent: true, opacity: 0.55 })));

  // Face decals: stuck onto whatever facet a ray toward the centre hits, so they sit flush on the flat faces.
  const mesh = body.children[0];
  const ray = new THREE.Raycaster();
  const ink = new THREE.MeshBasicMaterial({ color: INK, side: THREE.DoubleSide });
  function stick(geo, dir) {
    dir.normalize();
    ray.set(dir.clone().multiplyScalar(3), dir.clone().negate()); // from outside in: front faces only
    const hit = ray.intersectObject(mesh)[0];
    const m = new THREE.Mesh(geo, ink);
    m.position.copy(hit.point).addScaledVector(hit.face.normal, 0.012);
    m.lookAt(m.position.clone().add(hit.face.normal));
    body.add(m);
    return m;
  }
  const eyes = [stick(roundRect(0.19, 0.3, 0.07), new THREE.Vector3(-0.5, 0.2, 1)), stick(roundRect(0.19, 0.3, 0.07), new THREE.Vector3(0.5, 0.2, 1))];
  const mouth = stick(roundRect(0.22, 0.06, 0.025), new THREE.Vector3(0.02, 0.12, 1));

  // --- motion state ---
  const m = { spin: 0, hop: 0, sx: 1, sy: 1, eye: 1, lookX: 0, lookY: 0, shake: 0 };
  let mood = 'clean';
  let drag = null; // { x, y, moved }
  let rotX = 0;
  let rotY = 0;
  let velX = 0;
  let velY = 0;
  let free = false; // true after a drag until it has settled back facing front
  let suppressClick = false;

  // Every spin lands on a whole turn, so the face always ends up in front. overwrite
  // kills a spin already in flight, which would otherwise make this one stop part-way round.
  const spinTo = (turns, vars) => ({ spin: (Math.round(m.spin / TAU) + turns) * TAU, overwrite: 'auto', ...vars });

  function blink() {
    if (!reduced) gsap.to(m, { eye: 0.1, duration: 0.07, yoyo: true, repeat: 1, ease: 'power1.in', onComplete: () => gsap.delayedCall(2.5 + Math.random() * 3.5, blink) });
  }
  function idleSpin() {
    if (reduced) return;
    gsap.delayedCall(8 + Math.random() * 6, () => {
      if (!drag && !free) gsap.to(m, spinTo(1, { duration: 1.6, ease: 'power3.inOut' }));
      idleSpin();
    });
  }
  blink();
  idleSpin();

  function hop() {
    if (reduced) return;
    gsap.timeline()
      .to(m, { sx: 1.18, sy: 0.8, duration: 0.1, ease: 'power2.out' })
      .to(m, { sx: 0.9, sy: 1.14, hop: 0.55, duration: 0.28, ease: 'power2.out' })
      .to(m, spinTo(1, { duration: 0.6, ease: 'power2.inOut' }), '<')
      .to(m, { hop: 0, sx: 1, sy: 1, duration: 0.5, ease: 'bounce.out' });
  }

  function nudge() {
    if (reduced) return;
    gsap.timeline().to(m, { hop: 0.22, sy: 1.08, sx: 0.95, duration: 0.18, ease: 'power2.out', yoyo: true, repeat: 3 }).to(m, { hop: 0, sx: 1, sy: 1, duration: 0.2 });
  }

  function setMood(next) {
    if (next === mood) return;
    mood = next;
    gsap.to(m, { shake: next === 'isolated' ? 1 : 0, duration: 0.4 });
    if (next === 'cured') hop();
  }

  // --- pointer: lean toward the cursor, drag to spin it ---
  addEventListener('pointermove', (e) => {
    const r = canvas.getBoundingClientRect();
    if (!r.width) return;
    const nx = (e.clientX - (r.left + r.width / 2)) / innerWidth;
    const ny = (e.clientY - (r.top + r.height / 2)) / innerHeight;
    m.lookX = THREE.MathUtils.clamp(nx * 1.4, -0.45, 0.45);
    m.lookY = THREE.MathUtils.clamp(ny * 1.2, -0.3, 0.3);
    if (!drag) return;
    const dx = e.clientX - drag.x;
    const dy = e.clientY - drag.y;
    if (!drag.moved && Math.hypot(dx, dy) < 4) return;
    if (!free) {
      // Take over any spin in flight: the drag owns rotation until it settles back home.
      gsap.killTweensOf(m, 'spin');
      rotY += m.spin;
      m.spin = 0;
    }
    drag.moved = true;
    free = true;
    velY = dx * 0.012;
    velX = dy * 0.012;
    rotY += velY;
    rotX += velX;
    drag.x = e.clientX;
    drag.y = e.clientY;
  });
  box.addEventListener('pointerdown', (e) => {
    drag = { x: e.clientX, y: e.clientY, moved: false };
    box.setPointerCapture(e.pointerId);
    gsap.to(m, { eye: 0.25, sx: 1.06, sy: 0.94, duration: 0.15 }); // squeezed
  });
  const release = () => {
    if (!drag) return;
    suppressClick = drag.moved;
    drag = null;
    gsap.to(m, { eye: 1, sx: 1, sy: 1, duration: 0.35, ease: 'back.out(3)' });
  };
  box.addEventListener('pointerup', release);
  box.addEventListener('pointercancel', release);

  const size = () => {
    const w = canvas.clientWidth;
    const h = canvas.clientHeight;
    if (!w || !h || !box.clientHeight) return;
    renderer.setSize(w, h, false);
    // Widen the view by the overhang so the avatar keeps the size it has in the box.
    camera.fov = THREE.MathUtils.radToDeg(2 * Math.atan(Math.tan(THREE.MathUtils.degToRad(FOV / 2)) * (h / box.clientHeight)));
    camera.aspect = w / h;
    camera.updateProjectionMatrix();
  };
  new ResizeObserver(size).observe(box);
  size();

  renderer.setAnimationLoop(() => {
    if (!canvas.offsetParent || document.hidden) return; // standard view hidden: skip the frame
    const t = performance.now() / 1000;
    const still = reduced ? 0 : 1;

    if (!drag && free) {
      // Inertia, then spring back to the nearest front-facing turn.
      rotY += velY;
      rotX += velX;
      velY *= 0.94;
      velX *= 0.94;
      if (Math.abs(velY) + Math.abs(velX) < 0.004) {
        const home = Math.round(rotY / TAU) * TAU;
        const homeX = Math.round(rotX / TAU) * TAU; // nearest upright, not a full unwind
        rotY += (home - rotY) * 0.08;
        rotX += (homeX - rotX) * 0.08;
        if (Math.abs(home - rotY) + Math.abs(homeX - rotX) < 0.002) {
          gsap.killTweensOf(m, 'spin'); // a hop clicked mid-settle: keep its whole turns, drop the partial one
          m.spin = Math.round(m.spin / TAU) * TAU + home; // fold the leftover into spin so nothing snaps
          rotY = rotX = 0;
          free = false;
        }
      }
    }

    const scan = mood === 'watching' ? Math.sin(t * 1.8) * 0.28 : 0; // looking around while it watches something
    const sway = Math.sin(t * 0.7) * 0.18 * still;
    const tremble = m.shake * Math.sin(t * 60) * 0.025;
    body.rotation.set(rotX + (free ? 0 : m.lookY * 0.6 * still), m.spin + rotY + sway + scan * still + (free ? 0 : m.lookX * still), Math.sin(t * 0.9) * 0.06 * still);
    float.position.set(tremble, Math.sin(t * 1.3) * 0.09 * still + m.hop, 0);
    float.scale.set(m.sx, m.sy, m.sx);
    const lift = float.position.y;
    shadow.scale.setScalar(1 - lift * 0.35);
    shadow.material.opacity = 1 - lift * 0.6;
    const wide = 1 + m.shake * 0.25;
    for (const e of eyes) e.scale.set(wide, m.eye * wide, 1);
    mouth.scale.set(mood === 'cured' ? 1.3 : mood === 'isolated' ? 0.6 : 1, 1, 1);
    renderer.render(scene, camera);
  });

  return {
    hop,
    nudge,
    setMood,
    // A drag ends in a click event on the wrapping button; swallow that one.
    takeClick() {
      const s = suppressClick;
      suppressClick = false;
      return !s;
    },
  };
}
