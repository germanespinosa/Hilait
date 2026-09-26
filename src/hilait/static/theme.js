(() => {
  'use strict';
  const key = 'hilait-theme';
  const media = matchMedia('(prefers-color-scheme: light)');
  const allowed = new Set(['light', 'dark']);
  let preference;
  try { preference = localStorage.getItem(key); } catch {}
  if (!allowed.has(preference)) {
    preference = media.matches ? 'light' : 'dark';
    try { localStorage.setItem(key, preference); } catch {}
  }

  function resolved() { return preference; }
  function apply() {
    const theme = resolved();
    document.documentElement.dataset.theme = theme;
    document.documentElement.dataset.themePreference = preference;
    document.querySelectorAll('[data-theme-toggle]').forEach(button => {
      const label = theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode';
      button.setAttribute('aria-label', label);
      button.title = label;
    });
    dispatchEvent(new CustomEvent('hilait-theme-change', {detail:{theme, preference}}));
  }
  function set(value) {
    if (!allowed.has(value)) return;
    preference = value;
    try { localStorage.setItem(key, value); } catch {}
    apply();
  }
  document.addEventListener('click', event => {
    if (event.target.closest('[data-theme-toggle]')) set(resolved() === 'dark' ? 'light' : 'dark');
  });
  document.addEventListener('DOMContentLoaded', apply);
  addEventListener('storage', event => {
    if (event.key === key) { preference = allowed.has(event.newValue) ? event.newValue : (media.matches ? 'light' : 'dark'); apply(); }
  });
  window.HilaitTheme = {get preference() { return preference; }, get resolved() { return resolved(); }, set};
  apply();
})();
