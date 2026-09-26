import gsap from 'gsap';
import { ScrollTrigger } from 'gsap/ScrollTrigger';
import { ScrollToPlugin } from 'gsap/ScrollToPlugin';
import { createHelix, blockHash } from './helix.js';
import { mountChain } from './chain.js';

gsap.registerPlugin(ScrollTrigger, ScrollToPlugin);

// Always start at the top on reload; the loader and scroll choreography assume scrollY = 0.
history.scrollRestoration = 'manual';
scrollTo(0, 0);
addEventListener('pagehide', () => scrollTo(0, 0)); // some browsers restore anyway; leave at the top

// ponytail: placeholder until the Tauri .dmg is published; swap for the release URL.
const DOWNLOAD_URL = 'https://github.com/REPLACE_ME/t-cell/releases/latest';

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;
const mobile = matchMedia('(max-width: 720px)').matches;
const touch = matchMedia('(hover: none)').matches;

$$('[data-download]').forEach((a) => (a.href = DOWNLOAD_URL));
if (touch) $('.hint-text').textContent = 'Drag across the strand to read its blocks';

// ---------- Probe label that follows the hovered block ----------
const probe = $('#probe');
let probeIndex = -1;
function onHover(h) {
  if (!h) {
    probe.classList.remove('on');
    probeIndex = -1;
    return;
  }
  probe.classList.add('on');
  probe.style.transform = `translate(${h.x}px, ${h.y}px)`;
  if (h.index !== probeIndex) {
    probeIndex = h.index;
    $('#probe-title').textContent = `Block ${(18_400 + h.index).toLocaleString('en-US')}`;
    $('#probe-hash').textContent = `gene 0x${blockHash(h.index, 12)}`;
    $('#probe-pair').textContent = `base pair ${h.base[0]}–${h.base[1]}`;
  }
}

const helix = createHelix($('#gl'), { reduced, onHover });
helix.setAnchor($('#band'));
const layout = mobile ? { x: 1.7, tilt: 0.3, scale: 0.8 } : { x: 2.7, tilt: 0.42, scale: 1 };
Object.assign(helix.state, layout);

// ---------- Headline split ----------
$$('[data-split]').forEach((line) => {
  const text = line.textContent;
  line.textContent = '';
  line.setAttribute('aria-hidden', 'true');
  text.split(' ').forEach((word, i) => {
    if (i) line.append(' ');
    const w = document.createElement('span');
    w.className = 'word';
    for (const ch of word) {
      const s = document.createElement('span');
      s.className = 'ch';
      s.textContent = ch;
      w.append(s);
    }
    line.append(w);
  });
});

// ---------- Loader: sequence the strand, then divide ----------
const COMP = { A: 'T', T: 'A', G: 'C', C: 'G' };
const letters = Array.from({ length: mobile ? 18 : 34 }, () => 'ATGC'[(Math.random() * 4) | 0]);
$('.seq-a').innerHTML = letters.map((b) => `<span data-b="${b}">${b}</span>`).join('');
$('.seq-b').innerHTML = letters.map((b) => `<span data-b="${COMP[b]}">${COMP[b]}</span>`).join('');
const pairSpans = $$('.seq-b span');
const pct = $('#pct');

const progress = { p: 0 };
const loading = gsap.to(progress, {
  p: 1,
  duration: reduced ? 0.4 : 2.4,
  ease: 'power1.inOut',
  onUpdate() {
    pct.textContent = Math.round(progress.p * 100);
    const n = Math.floor(progress.p * pairSpans.length);
    pairSpans.forEach((s, i) => s.classList.toggle('on', i < n));
  },
});

Promise.all([loading.then(), document.fonts.ready]).then(() => {
  const d = reduced ? 0.01 : 1;
  const tl = gsap.timeline({
    onComplete() {
      $('#loader').remove();
      document.body.classList.remove('is-loading');
      setupScroll();
    },
  });
  tl.to('.seq-a', { y: -40, opacity: 0, duration: 0.6 * d, ease: 'power2.in' })
    .to('.seq-b', { y: 40, opacity: 0, duration: 0.6 * d, ease: 'power2.in' }, '<')
    .to(['.loader-count', '.loader-note'], { opacity: 0, scale: 0.96, duration: 0.5 * d }, '<')
    .to('.loader-top', { yPercent: -100, duration: 1.3 * d, ease: 'expo.inOut' }, '-=0.1')
    .to('.loader-bottom', { yPercent: 100, duration: 1.3 * d, ease: 'expo.inOut' }, '<')
    .to(helix.state, { build: 1, duration: 2.6 * d, ease: 'power2.out' }, '<0.25')
    .from('.hero-title .ch', { '--w': 50, opacity: 0, yPercent: 60, duration: 1.1 * d, ease: 'expo.out', stagger: 0.022 * d }, '<0.35')
    .from('.reveal', { opacity: 0, y: 18, duration: 0.9 * d, ease: 'power3.out', stagger: 0.1 * d }, '<0.5')
    .from('.nav', { opacity: 0, y: -12, duration: 0.8 * d }, '<');
});

// ---------- Scroll choreography ----------
function setupScroll() {
  // One scrubbed timeline owns the helix, so fast scrolls can't leave two tweens fighting over tilt/x.
  gsap
    .timeline({
      defaults: { ease: 'none' },
      scrollTrigger: { trigger: '#how', start: 'top bottom', endTrigger: '#chain', end: 'top 15%', scrub: 0.6 },
    })
    // Hero -> steps: helix swings the other way and drifts right
    .to(helix.state, { tilt: mobile ? -0.2 : -0.28, x: mobile ? 1.8 : 3.0, duration: 1 })
    // Steps -> chain: helix unzips into a horizontal chain locked to #band
    .to(helix.state, { tilt: -Math.PI / 2, x: 0, chain: 1, follow: 1, scale: 1, duration: 1.4 });

  // Step progress rail and active step
  gsap.to('.step-list', {
    '--p': 1,
    ease: 'none',
    scrollTrigger: { trigger: '.step-list', start: 'top 70%', end: 'bottom 45%', scrub: 0.5 },
  });
  $$('.step').forEach((el) =>
    ScrollTrigger.create({ trigger: el, start: 'top 72%', end: 'bottom 40%', toggleClass: 'is-on' }),
  );

  // Active tab
  ScrollTrigger.create({
    trigger: '#chain',
    start: 'top 55%',
    onEnter: () => setTab('chain'),
    onLeaveBack: () => setTab('top'),
  });
}

// ---------- Tabs ----------
const pill = $('.tab-pill');
function setTab(name) {
  $$('.tabs a').forEach((a) => a.classList.toggle('is-active', a.dataset.tab === name));
  const a = $(`.tabs a[data-tab="${name}"]`);
  gsap.to(pill, { x: a.offsetLeft - 4, width: a.offsetWidth, duration: reduced ? 0 : 0.5, ease: 'expo.out' });
}
gsap.set(pill, { width: $('.tabs a').offsetWidth });
document.fonts.ready.then(() => setTab($('.tabs a.is-active').dataset.tab));
addEventListener('resize', () => setTab($('.tabs a.is-active').dataset.tab));

$$('[data-scroll]').forEach((a) =>
  a.addEventListener('click', (e) => {
    e.preventDefault();
    const id = a.getAttribute('href');
    gsap.to(window, {
      scrollTo: { y: id === '#top' ? 0 : id, offsetY: 72, autoKill: true },
      duration: reduced ? 0 : 1.6,
      ease: 'power3.inOut',
    });
  }),
);

// ---------- Live chain ----------
mountChain({
  track: $('#track'),
  source: $('#source'),
  stats: { height: $('#s-height'), threats: $('#s-threats'), cures: $('#s-cures'), devices: $('#s-devices') },
  onBlock: () => helix.pulse(),
  animate(li) {
    if (reduced) return;
    gsap.fromTo([...li.parentElement.children].slice(1), { x: -272 }, { x: 0, duration: 0.8, ease: 'expo.out' });
    gsap.from(li, { opacity: 0, scale: 0.88, x: -24, duration: 0.8, ease: 'expo.out' });
  },
});
