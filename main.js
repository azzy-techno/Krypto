/* ═══════════════════════════════════════════════════════════
   KRYPTO — main.js
═══════════════════════════════════════════════════════════ */

// ── Navbar scroll ────────────────────────────────────────
const navbar = document.getElementById('navbar');
const onScroll = () => navbar.classList.toggle('scrolled', window.scrollY > 30);
window.addEventListener('scroll', onScroll, { passive: true });
onScroll(); // init

// ── Mobile nav toggle ─────────────────────────────────────
const navToggle = document.getElementById('navToggle');
const navMenu   = document.getElementById('navMenu');
if (navToggle && navMenu) {
    navToggle.addEventListener('click', () => {
        const open = navMenu.classList.toggle('open');
        navToggle.classList.toggle('open', open);
        navToggle.setAttribute('aria-expanded', open);
        document.body.style.overflow = open ? 'hidden' : '';
    });
    navMenu.querySelectorAll('.nav-link').forEach(link => {
        link.addEventListener('click', () => {
            navMenu.classList.remove('open');
            navToggle.classList.remove('open');
            document.body.style.overflow = '';
        });
    });
    // Close on outside click
    document.addEventListener('click', (e) => {
        if (!navbar.contains(e.target) && navMenu.classList.contains('open')) {
            navMenu.classList.remove('open');
            navToggle.classList.remove('open');
            document.body.style.overflow = '';
        }
    });
}

// ── Scroll Reveal ─────────────────────────────────────────
const revealObs = new IntersectionObserver(entries => {
    entries.forEach(e => { if (e.isIntersecting) e.target.classList.add('visible'); });
}, { threshold: 0.1, rootMargin: '0px 0px -40px 0px' });

document.querySelectorAll('.reveal').forEach(el => revealObs.observe(el));

// ── Counter animation ─────────────────────────────────────
function runCounter(el) {
    const target = parseInt(el.getAttribute('data-target'), 10);
    if (isNaN(target)) return;
    const duration = 1800;
    const start = performance.now();
    const tick = now => {
        const p = Math.min((now - start) / duration, 1);
        const eased = 1 - Math.pow(1 - p, 3);
        el.textContent = Math.round(eased * target);
        if (p < 1) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
}
const counterObs = new IntersectionObserver(entries => {
    entries.forEach(e => {
        if (e.isIntersecting) { runCounter(e.target); counterObs.unobserve(e.target); }
    });
}, { threshold: 0.5 });

document.querySelectorAll('.stat-num[data-target]').forEach(el => counterObs.observe(el));

// ── Smooth anchor links ────────────────────────────────────
document.querySelectorAll('a[href^="#"]').forEach(a => {
    a.addEventListener('click', e => {
        const target = document.querySelector(a.getAttribute('href'));
        if (target) {
            e.preventDefault();
            target.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
    });
});

/* ── Reviews Slideshow ───────────────────────────────────── */
(function () {
    const track    = document.getElementById('sliderTrack');
    const dots     = document.querySelectorAll('.dot');
    const prevBtn  = document.getElementById('sliderPrev');
    const nextBtn  = document.getElementById('sliderNext');
    const progress = document.getElementById('sliderProgress');

    if (!track) return;

    const TOTAL       = track.children.length;
    const AUTO_MS     = 5500;   // ms between auto-advances
    const PROGRESS_MS = AUTO_MS;

    let current   = 0;
    let autoTimer = null;
    let progTimer = null;
    let progStart = null;
    let isPaused  = false;

    /* Go to slide n */
    function goTo(n, resetAuto = true) {
        current = (n + TOTAL) % TOTAL;
        track.style.transform = `translateX(-${current * 100}%)`;

        // Update dots
        dots.forEach((d, i) => d.classList.toggle('active', i === current));

        if (resetAuto) restartAuto();
    }

    /* Progress bar animation */
    function startProgress() {
        if (progress) {
            progress.style.transition = 'none';
            progress.style.width = '0%';
            // Force reflow
            progress.offsetWidth;
            progress.style.transition = `width ${PROGRESS_MS}ms linear`;
            progress.style.width = '100%';
        }
    }

    function stopProgress() {
        if (progress) {
            progress.style.transition = 'none';
            progress.style.width = '0%';
        }
    }

    /* Auto-advance */
    function restartAuto() {
        clearInterval(autoTimer);
        stopProgress();
        if (!isPaused) {
            startProgress();
            autoTimer = setInterval(() => goTo(current + 1, false), AUTO_MS);
        }
    }

    /* Prev / Next buttons */
    if (prevBtn) prevBtn.addEventListener('click', () => goTo(current - 1));
    if (nextBtn) nextBtn.addEventListener('click', () => goTo(current + 1));

    /* Dot clicks */
    dots.forEach(d => {
        d.addEventListener('click', () => goTo(parseInt(d.dataset.index)));
    });

    /* Pause on hover */
    const wrap = document.querySelector('.slider-wrap');
    if (wrap) {
        wrap.addEventListener('mouseenter', () => {
            isPaused = true;
            clearInterval(autoTimer);
            stopProgress();
        });
        wrap.addEventListener('mouseleave', () => {
            isPaused = false;
            restartAuto();
        });
    }

    /* Touch / swipe support */
    let touchStartX = 0;
    track.addEventListener('touchstart', e => {
        touchStartX = e.touches[0].clientX;
    }, { passive: true });
    track.addEventListener('touchend', e => {
        const diff = touchStartX - e.changedTouches[0].clientX;
        if (Math.abs(diff) > 50) goTo(diff > 0 ? current + 1 : current - 1);
    }, { passive: true });

    /* Keyboard support */
    document.addEventListener('keydown', e => {
        if (e.key === 'ArrowLeft')  goTo(current - 1);
        if (e.key === 'ArrowRight') goTo(current + 1);
    });

    /* Init */
    goTo(0);
})();

/* ── FAQ Accordion ───────────────────────────────────────── */
document.querySelectorAll('.faq-q').forEach(btn => {
    btn.addEventListener('click', () => {
        const item = btn.closest('.faq-item');
        const isOpen = item.classList.contains('open');
        // Close all
        document.querySelectorAll('.faq-item.open').forEach(el => {
            el.classList.remove('open');
            el.querySelector('.faq-q').setAttribute('aria-expanded', 'false');
        });
        // Open clicked if it was closed
        if (!isOpen) {
            item.classList.add('open');
            btn.setAttribute('aria-expanded', 'true');
        }
    });
});