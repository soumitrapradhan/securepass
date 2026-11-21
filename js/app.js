/*
 * SecurePass - app.js
 * -------------------
 * Connects the HTML page to the checker and generator modules.
 * PRIVACY RULES followed in this file:
 *   - The password is only read from the input field and passed to PasswordChecker.analyze().
 *   - It is never logged, stored (no localStorage / sessionStorage / cookies) or sent over the network.
 *   - Password text is never written into the page with innerHTML (only textContent).
 */
(function () {
  'use strict';

  const $ = function (id) { return document.getElementById(id); };

  /* =====================================================
     Small UI helpers
     ===================================================== */
  let toastTimer = null;
  function showToast(message) {
    const el = $('toast');
    el.textContent = message;
    el.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { el.classList.remove('show'); }, 2200);
  }

  function setText(id, text) { $(id).textContent = text; }

  /* =====================================================
     Navigation: mobile menu + active link highlighting
     ===================================================== */
  function initNav() {
    const toggle = $('nav-toggle');
    const links = $('nav-links');

    function closeMenu() {
      links.classList.remove('open');
      toggle.setAttribute('aria-expanded', 'false');
    }
    toggle.addEventListener('click', function () {
      const open = links.classList.toggle('open');
      toggle.setAttribute('aria-expanded', String(open));
    });
    links.addEventListener('click', function (e) { if (e.target.closest('a')) closeMenu(); });
    document.addEventListener('keydown', function (e) { if (e.key === 'Escape') closeMenu(); });

    // Highlight the nav link of the section currently in view.
    const anchors = Array.from(links.querySelectorAll('a'));
    const sections = anchors.map(function (a) { return document.querySelector(a.getAttribute('href')); });

    function updateActive() {
      const marker = window.scrollY + window.innerHeight * 0.35;
      let current = 0;
      sections.forEach(function (s, i) { if (s && s.offsetTop <= marker) current = i; });
      if (window.innerHeight + window.scrollY >= document.body.scrollHeight - 4) current = sections.length - 1;
      anchors.forEach(function (a, i) { a.classList.toggle('is-active', i === current); });
    }
    window.addEventListener('scroll', updateActive, { passive: true });
    window.addEventListener('resize', updateActive);
    updateActive();
  }

  /* =====================================================
     Password checker UI
     ===================================================== */
  function initChecker() {
    const input = $('password-input');
    const checklist = $('checklist');
    const meter = $('meter');

    // Build the checklist once; only its state changes afterwards.
    const checkItems = {};
    PasswordChecker.analyze('').checks.forEach(function (c) {
      const li = document.createElement('li');
      li.dataset.state = 'idle';
      const icon = document.createElement('span');
      icon.className = 'check-icon';
      icon.setAttribute('aria-hidden', 'true');
      const label = document.createElement('span');
      label.textContent = c.label;
      li.append(icon, label);
      checklist.appendChild(li);
      checkItems[c.id] = { li: li, icon: icon };
    });

    function renderChecks(result) {
      result.checks.forEach(function (c) {
        const item = checkItems[c.id];
        let state = 'idle', symbol = '';
        if (!result.empty) {
          if (c.pass) { state = 'pass'; symbol = '✓'; }
          else if (c.severity === 'recommended') { state = 'warn'; symbol = '!'; }
          else { state = 'fail'; symbol = '✕'; }
        }
        item.li.dataset.state = state;
        item.icon.textContent = symbol;
      });
    }

    function renderList(listEl, items, build) {
      listEl.textContent = '';
      items.forEach(function (it) { listEl.appendChild(build(it)); });
    }

    function render() {
      const r = PasswordChecker.analyze(input.value);
      const levelKey = r.empty ? 'none' : r.level.key;
      meter.dataset.level = levelKey;

      $('meter-bar').style.width = r.score + '%';
      $('meter-track').setAttribute('aria-valuenow', String(r.score));

      setText('stat-level', r.empty ? '—' : r.level.label);
      $('stat-score').innerHTML = r.score + '<small>/100</small>';          // numbers only
      $('stat-entropy').innerHTML = Math.round(r.effectiveEntropy) + '<small> bits</small>'; // numbers only
      setText('stat-length', String(r.length));

      renderChecks(r);

      // Dashboard
      setText('dash-length', r.empty ? '—' : r.length + ' characters');
      setText('dash-variety', r.empty ? '—' : r.variety + ' of 4 types (pool ≈ ' + r.poolSize + ')');
      setText('dash-entropy', r.empty ? '—' : r.effectiveEntropy.toFixed(1) + ' bits (raw ' + r.rawEntropy.toFixed(1) + ')');
      setText('dash-level', r.empty ? '—' : r.level.label + ' (' + r.score + '/100)');
      setText('dash-crack', r.empty ? '—' : r.crackTime);

      // Explanation
      const why = $('why-box');
      why.textContent = '';
      if (r.empty) {
        const p = document.createElement('p');
        p.className = 'muted';
        p.textContent = 'Start typing a password to see a breakdown of how its score was calculated.';
        why.appendChild(p);
      } else {
        r.explanation.forEach(function (line) {
          const p = document.createElement('p');
          p.textContent = line;
          why.appendChild(p);
        });
      }

      renderList($('findings'), r.findings, function (f) {
        const li = document.createElement('li');
        li.dataset.type = f.type;
        li.textContent = f.text;
        return li;
      });

      // Recommendations
      const recs = r.empty
        ? [{ priority: 'info', text: 'Enter a password above and these recommendations will adapt to what is found.' }]
        : r.recommendations;
      renderList($('recs'), recs, function (rec) {
        const li = document.createElement('li');
        li.className = 'rec rec--' + rec.priority;
        const tag = document.createElement('span');
        tag.className = 'rec__tag';
        tag.textContent = rec.priority === 'high' ? 'Fix' : (rec.priority === 'medium' ? 'Improve' : 'Tip');
        const text = document.createElement('span');
        text.textContent = rec.text;
        li.append(tag, text);
        return li;
      });
    }

    function clearPassword() {
      input.value = '';
      render();
      input.focus();
    }

    input.addEventListener('input', render);
    $('clear-password').addEventListener('click', clearPassword);
    $('reset-btn').addEventListener('click', function () {
      input.value = '';
      input.type = 'password';
      updateVisibilityButton();
      render();
      showToast('Password cleared');
    });

    // Show / hide
    const visBtn = $('toggle-visibility');
    function updateVisibilityButton() {
      const visible = input.type === 'text';
      visBtn.setAttribute('aria-pressed', String(visible));
      visBtn.setAttribute('aria-label', visible ? 'Hide password' : 'Show password');
      visBtn.querySelector('.icon-eye').hidden = visible;
      visBtn.querySelector('.icon-eye-off').hidden = !visible;
    }
    visBtn.addEventListener('click', function () {
      input.type = input.type === 'password' ? 'text' : 'password';
      updateVisibilityButton();
      input.focus();
    });

    render();
    return { input: input, render: render };
  }

  /* =====================================================
     Password generator UI
     ===================================================== */
  function initGenerator(checker) {
    const out = $('generated-password');
    const slider = $('length-slider');
    const errorEl = $('gen-error');
    const genMeter = $('gen-meter');
    const optIds = { upper: 'opt-upper', lower: 'opt-lower', numbers: 'opt-numbers', special: 'opt-special' };

    function readOptions() {
      const o = { length: parseInt(slider.value, 10) };
      Object.keys(optIds).forEach(function (k) { o[k] = $(optIds[k]).checked; });
      return o;
    }

    function updateSlider() {
      const min = +slider.min, max = +slider.max, val = +slider.value;
      slider.style.setProperty('--fill', ((val - min) / (max - min)) * 100 + '%');
      setText('length-value', String(val));
    }

    function showStrength(pw) {
      const r = PasswordChecker.analyze(pw);
      genMeter.dataset.level = r.empty ? 'none' : r.level.key;
      $('gen-meter-bar').style.width = r.score + '%';
      setText('gen-strength', r.empty ? '—' : r.level.label + ' · ~' + Math.round(r.effectiveEntropy) + ' bits');
    }

    function generate() {
      try {
        const pw = PasswordGenerator.generate(readOptions());
        out.value = pw;
        errorEl.hidden = true;
        showStrength(pw);
        resetCopyButton();
      } catch (err) {
        out.value = '';
        showStrength('');
        errorEl.textContent = err.message;
        errorEl.hidden = false;
      }
    }

    // Copy (Clipboard API with a fallback for older browsers / file:// pages)
    const copyBtn = $('copy-btn');
    let copyTimer = null;
    function resetCopyButton() {
      clearTimeout(copyTimer);
      copyBtn.classList.remove('is-copied');
      setText('copy-label', 'Copy Password');
    }
    function copyFallback(text) {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.setAttribute('readonly', '');
      ta.style.cssText = 'position:fixed;left:-9999px;top:0;opacity:0';
      document.body.appendChild(ta);
      ta.select();
      let ok = false;
      try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
      document.body.removeChild(ta);
      return ok;
    }
    function copyPassword() {
      const text = out.value;
      if (!text) { showToast('Generate a password first'); return; }
      function done(ok) {
        if (!ok) { showToast('Copy failed - select the password and press Ctrl+C'); return; }
        copyBtn.classList.add('is-copied');
        setText('copy-label', 'Copied!');
        showToast('Password copied to clipboard');
        clearTimeout(copyTimer);
        copyTimer = setTimeout(resetCopyButton, 2000);
      }
      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(function () { done(true); }, function () { done(copyFallback(text)); });
      } else {
        done(copyFallback(text));
      }
    }

    $('generate-btn').addEventListener('click', generate);
    $('regenerate-btn').addEventListener('click', generate);
    copyBtn.addEventListener('click', copyPassword);
    $('copy-icon').addEventListener('click', copyPassword);
    slider.addEventListener('input', function () { updateSlider(); generate(); });
    Object.keys(optIds).forEach(function (k) { $(optIds[k]).addEventListener('change', generate); });

    $('analyze-btn').addEventListener('click', function () {
      if (!out.value) { showToast('Generate a password first'); return; }
      checker.input.value = out.value;
      checker.render();
      document.getElementById('checker').scrollIntoView({ behavior: 'smooth' });
    });

    updateSlider();
    generate();
  }

  /* =====================================================
     Background particles (subtle network effect)
     ===================================================== */
  function initParticles() {
    const canvas = $('bg-canvas');
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    let w = 0, h = 0, dpr = 1, particles = [], raf = null;

    function resize() {
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      w = window.innerWidth; h = window.innerHeight;
      canvas.width = w * dpr; canvas.height = h * dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      const count = Math.max(18, Math.min(60, Math.floor((w * h) / 28000)));
      particles = [];
      for (let i = 0; i < count; i++) {
        particles.push({ x: Math.random() * w, y: Math.random() * h,
          vx: (Math.random() - 0.5) * 0.25, vy: (Math.random() - 0.5) * 0.25, r: Math.random() * 1.4 + 0.6 });
      }
    }

    function frame() {
      ctx.clearRect(0, 0, w, h);
      for (let i = 0; i < particles.length; i++) {
        const p = particles[i];
        if (!reduce) {
          p.x += p.vx; p.y += p.vy;
          if (p.x < 0 || p.x > w) p.vx *= -1;
          if (p.y < 0 || p.y > h) p.vy *= -1;
        }
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
        ctx.fillStyle = 'rgba(0, 229, 255, 0.55)';
        ctx.fill();
        for (let j = i + 1; j < particles.length; j++) {
          const q = particles[j];
          const dx = p.x - q.x, dy = p.y - q.y, d = Math.sqrt(dx * dx + dy * dy);
          if (d < 130) {
            ctx.strokeStyle = 'rgba(0, 229, 255,' + (0.12 * (1 - d / 130)).toFixed(3) + ')';
            ctx.lineWidth = 1;
            ctx.beginPath(); ctx.moveTo(p.x, p.y); ctx.lineTo(q.x, q.y); ctx.stroke();
          }
        }
      }
      if (!reduce) raf = requestAnimationFrame(frame);
    }

    resize();
    frame();
    window.addEventListener('resize', function () { resize(); if (reduce) frame(); });
    document.addEventListener('visibilitychange', function () {
      if (reduce) return;
      if (document.hidden) cancelAnimationFrame(raf); else raf = requestAnimationFrame(frame);
    });
  }

  /* =====================================================
     Start
     ===================================================== */
  document.addEventListener('DOMContentLoaded', function () {
    $('year').textContent = new Date().getFullYear();
    initNav();
    const checker = initChecker();
    initGenerator(checker);
    initParticles();
  });
})();
