// Staff login page. Kept in its own file so the Content-Security-Policy can block inline scripts.
const demos = [['supervisor@facein.demo', 'Supervisor (Manager)'], ['hr@facein.demo', 'HR Clerk (view only)'], ['owner@facein.demo', 'Owner (view only)'], ['admin@facein.demo', 'Admin']];
// Demo accounts are listed only while the server runs in demo mode (DEMO_ACCOUNTS is not false).
fetch('/api/config').then(r => r.json()).then(cfg => {
  if (!cfg.demo) return;
  const demo = document.getElementById('demo');
  demos.forEach(([e, l]) => {
    const b = document.createElement('button'); b.type = 'button'; b.className = 'small';
    const strong = document.createElement('strong'); strong.textContent = l;
    const span = document.createElement('span'); span.className = 'muted'; span.textContent = e;
    b.append(strong, document.createElement('br'), span);
    b.onclick = () => { document.getElementById('email').value = e; document.getElementById('pw').value = 'Demo@123'; };
    demo.appendChild(b);
  });
  document.getElementById('demo-box').hidden = false;
}).catch(() => {});
fetch('/api/me').then(r => { if (r.ok) location.href = '/app'; });
document.getElementById('f').onsubmit = async ev => {
  ev.preventDefault();
  const r = await fetch('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: document.getElementById('email').value, password: document.getElementById('pw').value }) });
  const j = await r.json().catch(() => ({ error: 'Server error' }));
  if (r.ok) { location.href = '/app'; return; }
  const box = document.createElement('div'); box.className = 'msg err'; box.textContent = j.error || 'Login failed';
  document.getElementById('err').replaceChildren(box);
};
