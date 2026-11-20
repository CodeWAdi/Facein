// FaceIn API + static hosting. Business rules BR1-BR5 enforced here and in database triggers (db.js).
const { db, tx, init, seed, closeDays, NOTICE, ACTIVE_CONSENT_SQL, fmtDate, fmtTs, fmtHM, toMin, isSunday, addDays } = require('./db');
const express = require('express');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');

const PORT = process.env.PORT || 3000;
const SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const FACE_THRESHOLD = Number(process.env.FACE_THRESHOLD || 0.45); // BR4: strict (face-api default is 0.6)
const VIEW = ['supervisor', 'hr', 'owner'];

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '20kb' })); // small limit: images can never be uploaded
app.use((req, res, next) => { res.set('Permissions-Policy', 'camera=(self)'); res.set('X-Content-Type-Options', 'nosniff'); next(); });

class HttpError extends Error { constructor(status, msg) { super(msg); this.status = status; } }
const bad = msg => { throw new HttpError(400, msg); };

// ---------- auth (signed cookie) ----------
const sign = v => crypto.createHmac('sha256', SECRET).update(v).digest('base64url');
async function currentUser(req) {
  const m = /(?:^|;\s*)fi_session=([^;]+)/.exec(req.headers.cookie || '');
  if (!m) return null;
  const [uid, exp, sig] = m[1].split('.');
  if (!sig) return null;
  const a = Buffer.from(sign(`${uid}.${exp}`)), b = Buffer.from(sig);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b) || Date.now() > Number(exp)) return null;
  return await db.prepare('SELECT id, name, email, role FROM app_user WHERE id = ?').get(Number(uid)) || null;
}
const auth = (...roles) => async (req, res, next) => {
  const u = await currentUser(req);
  if (!u) return res.status(401).json({ error: 'Please log in' });
  if (roles.length && !roles.includes(u.role)) return res.status(403).json({ error: 'Your role is not allowed to do this' });
  req.user = u; next();
};

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body || {};
  const u = await db.prepare('SELECT * FROM app_user WHERE lower(email) = lower(?)').get(String(email || '').trim());
  if (!u || !bcrypt.compareSync(String(password || ''), u.password_hash)) return res.status(401).json({ error: 'Wrong email or password' });
  const exp = Date.now() + 12 * 3600 * 1000;
  const val = `${u.id}.${exp}`;
  res.set('Set-Cookie', `fi_session=${val}.${sign(val)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=43200${req.secure ? '; Secure' : ''}`);
  res.json({ id: u.id, name: u.name, email: u.email, role: u.role });
});
app.post('/api/logout', async (req, res) => { res.set('Set-Cookie', 'fi_session=; Path=/; Max-Age=0'); res.json({ ok: true }); });
app.get('/api/me', auth(), async (req, res) => res.json(req.user));
app.get('/api/notice', auth(), async (req, res) => res.json(NOTICE));
app.get('/healthz', async (req, res) => res.json({ ok: true }));

// ---------- shared helpers ----------
const logAttempt = async (workerId, kioskId, method, result) =>
  await db.prepare('INSERT INTO checkin_attempt (worker_id, kiosk_id, method, result, timestamp) VALUES (?,?,?,?,?)')
    .run(workerId ?? null, kioskId, method, result, fmtTs(new Date()));
const hasActiveConsent = async workerId =>
  (await db.prepare('SELECT decision FROM consent WHERE worker_id = ? ORDER BY id DESC LIMIT 1').get(workerId) || {}).decision === 'grant';
const validDescriptor = d => Array.isArray(d) && d.length === 128 && d.every(x => typeof x === 'number' && Number.isFinite(x) && Math.abs(x) < 10);
const validDate = d => /^\d{4}-\d{2}-\d{2}$/.test(d || '') && !isNaN(new Date(d + 'T00:00:00'));
const getKiosk = async id => await db.prepare('SELECT * FROM kiosk WHERE id = ?').get(Number(id)) || bad('Unknown kiosk');

// B07: a check-in is accepted only from 2 hours before shift start until shift end (handles shifts that cross midnight)
const EARLY_MIN = 120;
function inShiftWindow(shift, nowMin) {
  const from = (toMin(shift.start) - EARLY_MIN + 1440) % 1440, to = toMin(shift.end);
  return from <= to ? nowMin >= from && nowMin <= to : nowMin >= from || nowMin <= to;
}

// BR1 + BR2: one record per worker per date; late after start + grace
async function checkIn(w, kioskId, method) {
  const now = new Date(), date = fmtDate(now), hm = fmtHM(now);
  const existing = await db.prepare('SELECT status, check_in_time FROM daily_attendance WHERE worker_id = ? AND date = ?').get(w.id, date);
  if (existing) {
    await logAttempt(w.id, kioskId, method, 'already_marked');
    return { result: 'already_marked', name: w.name, status: existing.status, time: existing.check_in_time };
  }
  const shift = await db.prepare('SELECT * FROM shift WHERE id = ?').get(w.shift_id);
  if (!inShiftWindow(shift, now.getHours() * 60 + now.getMinutes())) {
    await logAttempt(w.id, kioskId, method, 'rejected_outside_shift');
    return { result: 'rejected', name: w.name, message: `Not your shift time. ${shift.name} shift check-in opens 2 hours before ${shift.start} and closes at ${shift.end}.` };
  }
  const status = now.getHours() * 60 + now.getMinutes() > toMin(shift.start) + shift.grace_minutes ? 'late' : 'present';
  try {
    await tx(async () => {
      await db.prepare('INSERT INTO daily_attendance (worker_id, date, status, check_in_time) VALUES (?,?,?,?)').run(w.id, date, status, hm);
      await logAttempt(w.id, kioskId, method, 'success');
    });
  } catch (e) {
    if (e.code === '23505' || /UNIQUE|duplicate key/i.test(e.message)) { await logAttempt(w.id, kioskId, method, 'already_marked'); return { result: 'already_marked', name: w.name }; }
    throw e;
  }
  return { result: 'success', name: w.name, status, time: hm };
}

// ---------- kiosk (public, no login) ----------
app.get('/api/kiosk/setup', async (req, res) => res.json({
  kiosks: await db.prepare('SELECT id, name, location FROM kiosk ORDER BY id').all(),
  threshold: FACE_THRESHOLD
}));
// BR4 (server side): the kiosk sends only the live face descriptor; the server does the matching itself.
// BR3: only templates of active workers with active consent are compared.
const MATCH_MARGIN = 0.05; // the next-closest worker must be at least this much further away
const euclid = (a, b) => { let s = 0; for (let i = 0; i < a.length; i++) { const d = a[i] - b[i]; s += d * d; } return Math.sqrt(s); };
app.post('/api/kiosk/face', async (req, res) => {
  const { kiosk_id, descriptor } = req.body || {};
  const k = await getKiosk(kiosk_id);
  if (!validDescriptor(descriptor)) bad('Face data is not valid. Capture again.');
  const rows = await db.prepare(`SELECT ft.worker_id, ft.descriptor FROM face_template ft JOIN worker w ON w.id = ft.worker_id
    WHERE w.active = 1 AND ${ACTIVE_CONSENT_SQL} = 'grant'`).all();
  const best = new Map(); // worker_id -> closest distance over that worker's templates
  for (const r of rows) {
    const d = euclid(descriptor, JSON.parse(r.descriptor));
    if (!best.has(r.worker_id) || d < best.get(r.worker_id)) best.set(r.worker_id, d);
  }
  const ranked = [...best].sort((a, b) => a[1] - b[1]);
  const [first, second] = ranked;
  if (!first || !(first[1] <= FACE_THRESHOLD) || (second && second[1] - first[1] < MATCH_MARGIN)) {
    await logAttempt(null, k.id, 'face', 'rejected_low_confidence');
    return res.json({ result: 'not_recognised' });
  }
  const w = await db.prepare('SELECT * FROM worker WHERE id = ?').get(first[0]);
  res.json(await checkIn(w, k.id, 'face'));
});
// B03: after 5 wrong PINs for a worker code within 15 minutes, lock PIN check-in for that code for 15 minutes.
// Counted from checkin_attempt, so it survives a page refresh or a server restart.
const PIN_MAX_WRONG = 5, PIN_WINDOW_MS = 15 * 60 * 1000;
const tsDate = ts => new Date(ts.replace(' ', 'T'));
async function pinLocked(workerId) {
  const wrong = (await db.prepare(`SELECT timestamp FROM checkin_attempt WHERE worker_id = ? AND method = 'pin' AND result = 'rejected_wrong_pin'
    ORDER BY id DESC LIMIT ${PIN_MAX_WRONG}`).all(workerId)).map(r => r.timestamp);
  if (wrong.length < PIN_MAX_WRONG) return false;
  const now = Date.now(), newest = wrong[0], oldest = wrong[PIN_MAX_WRONG - 1];
  // the 5 most recent wrong PINs fall within 15 minutes, and the lock (15 minutes from the 5th) has not run out
  return oldest >= fmtTs(new Date(+tsDate(newest) - PIN_WINDOW_MS)) && newest > fmtTs(new Date(now - PIN_WINDOW_MS));
}
app.post('/api/kiosk/pin', async (req, res) => {
  const { kiosk_id, employee_code, pin } = req.body || {};
  const k = await getKiosk(kiosk_id);
  const w = await db.prepare('SELECT * FROM worker WHERE employee_code = ?').get(String(employee_code || '').trim());
  if (!w) { await logAttempt(null, k.id, 'pin', 'rejected_unknown_code'); return res.json({ result: 'rejected', message: 'Worker code or PIN is wrong' }); }
  if (!w.active) { await logAttempt(w.id, k.id, 'pin', 'rejected_inactive'); return res.json({ result: 'rejected', message: 'Worker is not active. Please see your supervisor.' }); }
  if (await pinLocked(w.id)) { await logAttempt(w.id, k.id, 'pin', 'rejected_locked'); return res.json({ result: 'rejected', message: 'Too many wrong PINs. Please see your supervisor.' }); }
  if (!/^\d{4}$/.test(String(pin)) || !bcrypt.compareSync(String(pin), w.pin_hash)) {
    await logAttempt(w.id, k.id, 'pin', 'rejected_wrong_pin');
    return res.json({ result: 'rejected', message: 'Worker code or PIN is wrong' });
  }
  res.json(await checkIn(w, k.id, 'pin'));
});

// ---------- day view (home, daily report) ----------
async function dayView(date, shiftId) {
  await closeDays();
  const today = fmtDate(new Date()), now = new Date(), nowMin = now.getHours() * 60 + now.getMinutes();
  const sid = Number(shiftId) || 0;
  const rows = await db.prepare(`SELECT w.id worker_id, w.name, w.employee_code, w.shift_id, s.name shift_name, s.start, s.grace_minutes,
      a.id attendance_id, a.status, a.check_in_time,
      (SELECT method FROM checkin_attempt ca WHERE ca.worker_id = w.id AND ca.result = 'success' AND substr(ca.timestamp,1,10) = ? ORDER BY ca.id LIMIT 1) method,
      (SELECT COUNT(*) FROM override o WHERE o.attendance_id = a.id) overrides
    FROM worker w JOIN shift s ON s.id = w.shift_id
    LEFT JOIN daily_attendance a ON a.worker_id = w.id AND a.date = ?
    WHERE (w.active = 1 OR a.id IS NOT NULL) AND (? = 0 OR w.shift_id = ?) AND substr(w.created_at,1,10) <= ?
    ORDER BY s.start, w.name`).all(date, date, sid, sid, date);
  for (const r of rows) {
    if (r.status) continue;
    if (date > today) r.status = 'not_started';
    else if (date < today) r.status = isSunday(date) ? 'weekly_off' : 'absent';
    else r.status = nowMin > toMin(r.start) + r.grace_minutes ? 'absent' : 'not_started';
  }
  const counts = { present: 0, late: 0, absent: 0, not_started: 0, weekly_off: 0 };
  rows.forEach(r => counts[r.status]++);
  return { date, rows, counts };
}

app.get('/api/dashboard', auth(...VIEW), async (req, res) => {
  const date = validDate(req.query.date) ? req.query.date : fmtDate(new Date());
  const v = await dayView(date, req.query.shift_id);
  const sid = Number(req.query.shift_id) || 0;
  const rejected = await db.prepare(`SELECT ca.id, ca.timestamp, ca.method, ca.result, w.name, w.employee_code, k.name kiosk
    FROM checkin_attempt ca LEFT JOIN worker w ON w.id = ca.worker_id JOIN kiosk k ON k.id = ca.kiosk_id
    WHERE substr(ca.timestamp,1,10) = ? AND ca.result LIKE 'rejected%' AND (? = 0 OR w.shift_id = ? OR ca.worker_id IS NULL)
    ORDER BY ca.id DESC`).all(date, sid, sid);
  res.json({ ...v, exceptions: { pin: v.rows.filter(r => r.method === 'pin'), rejected, absent: v.rows.filter(r => r.status === 'absent') } });
});

// ---------- live log of kiosk attempts (face scans and PINs) ----------
// The page polls every few seconds with ?after=<last id seen>, so new attempts appear without a refresh.
// Only the attempt row is shown: time, kiosk, method, result and, when the worker is known, their name.
// A face that is not recognised has no worker, so it shows as Unknown. No face image or descriptor is ever kept.
app.get('/api/attempts/live', auth(...VIEW), async (req, res) => {
  const date = validDate(req.query.date) ? req.query.date : fmtDate(new Date());
  const after = Math.max(0, Number.parseInt(req.query.after, 10) || 0);
  const rows = await db.prepare(`SELECT ca.id, ca.timestamp, ca.method, ca.result, w.name, w.employee_code, k.name kiosk
    FROM checkin_attempt ca LEFT JOIN worker w ON w.id = ca.worker_id JOIN kiosk k ON k.id = ca.kiosk_id
    WHERE substr(ca.timestamp,1,10) = ? AND ca.id > ? ORDER BY ca.id DESC LIMIT 200`).all(date, after);
  const counts = await db.prepare(`SELECT
      COUNT(*) FILTER (WHERE method = 'face') AS face,
      COUNT(*) FILTER (WHERE method = 'face' AND worker_id IS NOT NULL) AS face_recognised,
      COUNT(*) FILTER (WHERE method = 'face' AND worker_id IS NULL) AS face_unknown,
      COUNT(*) FILTER (WHERE method = 'pin') AS pin
    FROM checkin_attempt WHERE substr(timestamp,1,10) = ?`).get(date);
  for (const k in counts) counts[k] = Number(counts[k]);
  res.json({ date, today: date === fmtDate(new Date()), rows, counts });
});

// ---------- workers ----------
app.get('/api/shifts', auth(), async (req, res) => res.json(await db.prepare('SELECT * FROM shift ORDER BY start').all()));

app.get('/api/workers', auth(...VIEW), async (req, res) => {
  res.json(await db.prepare(`SELECT w.id, w.name, w.employee_code, w.shift_id, w.active, s.name shift_name,
      ${ACTIVE_CONSENT_SQL} consent, EXISTS (SELECT 1 FROM face_template f WHERE f.worker_id = w.id) has_face
    FROM worker w JOIN shift s ON s.id = w.shift_id ORDER BY CAST(w.employee_code AS INTEGER), w.employee_code`).all());
});

app.get('/api/workers/:id', auth(...VIEW), async (req, res) => {
  await closeDays();
  const w = await db.prepare(`SELECT w.id, w.name, w.employee_code, w.shift_id, w.active, w.created_at, s.name shift_name, s.start, s."end", s.grace_minutes
    FROM worker w JOIN shift s ON s.id = w.shift_id WHERE w.id = ?`).get(Number(req.params.id));
  if (!w) throw new HttpError(404, 'Worker not found');
  const consents = await db.prepare('SELECT decision, notice_version, timestamp FROM consent WHERE worker_id = ? ORDER BY id DESC').all(w.id);
  const face = await db.prepare('SELECT created_at FROM face_template WHERE worker_id = ?').get(w.id) || null;
  const attendance = await db.prepare(`SELECT a.id, a.date, a.status, a.check_in_time, (SELECT COUNT(*) FROM override o WHERE o.attendance_id = a.id) overrides
    FROM daily_attendance a WHERE a.worker_id = ? ORDER BY a.date DESC LIMIT 14`).all(w.id);
  res.json({ worker: w, consent: consents[0] ? consents[0].decision : 'none', consents, face, attendance });
});

const validPin = p => /^\d{4}$/.test(String(p || '')) || bad('PIN must be exactly 4 digits');

app.post('/api/workers', auth('supervisor'), async (req, res) => {
  const { name, employee_code, shift_id, pin, consent, descriptor } = req.body || {};
  const nm = String(name || '').trim();
  if (nm.length < 2 || nm.length > 80) bad('Enter the worker name');
  const code = String(employee_code || '').trim();
  if (!/^\d{3,6}$/.test(code)) bad('Worker code must be 3 to 6 digits (it is typed on the kiosk keypad)');
  if (await db.prepare('SELECT 1 FROM worker WHERE employee_code = ?').get(code)) bad('This worker code is already used');
  if (!await db.prepare('SELECT 1 FROM shift WHERE id = ?').get(Number(shift_id))) bad('Choose a shift');
  validPin(pin);
  const accepted = !!(consent && consent.accepted);
  if (accepted && consent.notice_version !== NOTICE.version) bad('Consent notice version is out of date. Reload the page.');
  if (descriptor && !accepted) bad('BR3: face data needs consent');
  if (descriptor && !validDescriptor(descriptor)) bad('Face data is not valid. Capture again.');
  const id = await tx(async () => {
    const ts = fmtTs(new Date());
    const wid = Number((await db.prepare('INSERT INTO worker (name, employee_code, shift_id, active, pin_hash, created_at) VALUES (?,?,?,1,?,?)')
      .run(nm, code, Number(shift_id), bcrypt.hashSync(String(pin), 10), ts)).lastInsertRowid);
    if (accepted) await db.prepare('INSERT INTO consent (worker_id, decision, notice_version, timestamp) VALUES (?,?,?,?)').run(wid, 'grant', NOTICE.version, ts);
    if (descriptor) await db.prepare('INSERT INTO face_template (worker_id, descriptor, created_at) VALUES (?,?,?)').run(wid, JSON.stringify(descriptor.map(x => +x.toFixed(6))), ts);
    return wid;
  });
  res.json({ id });
});

// B06: Supervisor can fix a worker's name or shift, reset the PIN, and deactivate or reactivate the worker.
// Inactive workers cannot check in (face or PIN) and drop out of the Absent list.
app.put('/api/workers/:id', auth('supervisor'), async (req, res) => {
  const w = await db.prepare('SELECT * FROM worker WHERE id = ?').get(Number(req.params.id));
  if (!w) throw new HttpError(404, 'Worker not found');
  const { name, shift_id, pin, active } = req.body || {};
  const nm = String(name || '').trim();
  if (nm.length < 2 || nm.length > 80) bad('Enter the worker name');
  if (!await db.prepare('SELECT 1 FROM shift WHERE id = ?').get(Number(shift_id))) bad('Choose a shift');
  if (typeof active !== 'boolean') bad('Choose active or inactive');
  if (pin) validPin(pin);
  await db.prepare('UPDATE worker SET name = ?, shift_id = ?, active = ? WHERE id = ?').run(nm, Number(shift_id), active ? 1 : 0, w.id);
  if (pin) await db.prepare('UPDATE worker SET pin_hash = ? WHERE id = ?').run(bcrypt.hashSync(String(pin), 10), w.id);
  res.json({ ok: true });
});

app.post('/api/workers/:id/enrol-face', auth('supervisor'), async (req, res) => {
  const { accepted, notice_version, descriptor } = req.body || {};
  const w = await db.prepare('SELECT * FROM worker WHERE id = ?').get(Number(req.params.id));
  if (!w) throw new HttpError(404, 'Worker not found');
  if (!accepted) bad('BR3: the worker must accept the notice before face capture');
  if (notice_version !== NOTICE.version) bad('Consent notice version is out of date. Reload the page.');
  if (!validDescriptor(descriptor)) bad('Face data is not valid. Capture again.');
  await tx(async () => {
    const ts = fmtTs(new Date());
    await db.prepare('INSERT INTO consent (worker_id, decision, notice_version, timestamp) VALUES (?,?,?,?)').run(w.id, 'grant', NOTICE.version, ts);
    await db.prepare('DELETE FROM face_template WHERE worker_id = ?').run(w.id);
    await db.prepare('INSERT INTO face_template (worker_id, descriptor, created_at) VALUES (?,?,?)').run(w.id, JSON.stringify(descriptor.map(x => +x.toFixed(6))), ts);
  });
  res.json({ ok: true });
});

// BR3: withdrawal records consent 'withdraw' and deletes the template immediately (also enforced by trigger)
app.post('/api/workers/:id/delete-face', auth('supervisor'), async (req, res) => {
  const w = await db.prepare('SELECT * FROM worker WHERE id = ?').get(Number(req.params.id));
  if (!w) throw new HttpError(404, 'Worker not found');
  const hasTpl = await db.prepare('SELECT 1 FROM face_template WHERE worker_id = ?').get(w.id);
  if (!hasTpl && !await hasActiveConsent(w.id)) bad('This worker has no face data and no active consent');
  await tx(async () => {
    await db.prepare('INSERT INTO consent (worker_id, decision, notice_version, timestamp) VALUES (?,?,?,?)').run(w.id, 'withdraw', NOTICE.version, fmtTs(new Date()));
    await db.prepare('DELETE FROM face_template WHERE worker_id = ?').run(w.id);
  });
  res.json({ ok: true });
});

// ---------- records & overrides ----------
app.get('/api/record', auth(...VIEW), async (req, res) => {
  await closeDays();
  let rec;
  if (req.query.id) {
    rec = await db.prepare('SELECT * FROM daily_attendance WHERE id = ?').get(Number(req.query.id));
    if (!rec) throw new HttpError(404, 'Record not found');
  } else {
    if (!validDate(req.query.date)) bad('Bad date');
    rec = await db.prepare('SELECT * FROM daily_attendance WHERE worker_id = ? AND date = ?').get(Number(req.query.worker_id), req.query.date)
      || { id: null, worker_id: Number(req.query.worker_id), date: req.query.date, status: 'absent', check_in_time: null };
  }
  const worker = await db.prepare('SELECT w.id, w.name, w.employee_code, s.name shift_name, s.start, s.grace_minutes FROM worker w JOIN shift s ON s.id = w.shift_id WHERE w.id = ?').get(rec.worker_id);
  if (!worker) throw new HttpError(404, 'Worker not found');
  const overrides = rec.id ? await db.prepare(`SELECT o.*, u.name supervisor FROM override o JOIN app_user u ON u.id = o.supervisor_id
    WHERE o.attendance_id = ? ORDER BY o.id DESC`).all(rec.id) : [];
  const attempts = await db.prepare(`SELECT ca.timestamp, ca.method, ca.result, k.name kiosk FROM checkin_attempt ca JOIN kiosk k ON k.id = ca.kiosk_id
    WHERE ca.worker_id = ? AND substr(ca.timestamp,1,10) = ? ORDER BY ca.id`).all(rec.worker_id, rec.date);
  res.json({ record: rec, worker, overrides, attempts });
});

// BR5: only Supervisor; reason required; old/new status, supervisor and time saved; never deleted
app.post('/api/override', auth('supervisor'), async (req, res) => {
  const { attendance_id, worker_id, date, new_status, reason } = req.body || {};
  const why = String(reason || '').trim();
  if (why.length < 5) bad('A written reason is required (at least 5 characters)');
  if (!['present', 'late', 'absent'].includes(new_status)) bad('Choose the new status');
  const result = await tx(async () => {
    let rec;
    if (attendance_id) rec = await db.prepare('SELECT * FROM daily_attendance WHERE id = ?').get(Number(attendance_id));
    else {
      if (!validDate(date) || date > fmtDate(new Date())) bad('Bad date');
      if (isSunday(date)) bad('Sunday is the weekly off. Overrides are not allowed on a Sunday.'); // B08
      if (!await db.prepare('SELECT 1 FROM worker WHERE id = ?').get(Number(worker_id))) bad('Worker not found');
      rec = await db.prepare('SELECT * FROM daily_attendance WHERE worker_id = ? AND date = ?').get(Number(worker_id), date);
      if (!rec) {
        const id = (await db.prepare("INSERT INTO daily_attendance (worker_id, date, status, check_in_time) VALUES (?,?,'absent',NULL)").run(Number(worker_id), date)).lastInsertRowid;
        rec = await db.prepare('SELECT * FROM daily_attendance WHERE id = ?').get(Number(id));
      }
    }
    if (!rec) throw new HttpError(404, 'Record not found');
    if (isSunday(rec.date)) bad('Sunday is the weekly off. Overrides are not allowed on a Sunday.'); // B08
    if (rec.status === new_status) bad('The new status is the same as the current status');
    await db.prepare('UPDATE daily_attendance SET status = ? WHERE id = ?').run(new_status, rec.id);
    await db.prepare('INSERT INTO override (attendance_id, old_status, new_status, reason, supervisor_id, timestamp) VALUES (?,?,?,?,?,?)')
      .run(rec.id, rec.status, new_status, why, req.user.id, fmtTs(new Date()));
    return rec.id;
  });
  res.json({ attendance_id: result });
});

// ---------- reports ----------
app.get('/api/reports/daily', auth(...VIEW), async (req, res) => {
  const date = validDate(req.query.date) ? req.query.date : fmtDate(new Date());
  res.json(await dayView(date, req.query.shift_id));
});

async function payable(from, to) {
  await closeDays();
  if (!validDate(from) || !validDate(to) || from > to) bad('Choose a valid date range');
  return await db.prepare(`SELECT w.id, w.name, w.employee_code, s.name shift_name,
      COUNT(a.id) FILTER (WHERE a.status = 'present') AS present, COUNT(a.id) FILTER (WHERE a.status = 'late') AS late,
      COUNT(a.id) FILTER (WHERE a.status = 'absent') AS absent, COUNT(a.id) FILTER (WHERE a.status IN ('present','late')) AS payable_days
    FROM worker w JOIN shift s ON s.id = w.shift_id
    LEFT JOIN daily_attendance a ON a.worker_id = w.id AND a.date BETWEEN ? AND ?
    GROUP BY w.id, s.name HAVING w.active = 1 OR COUNT(a.id) > 0
    ORDER BY CAST(w.employee_code AS INTEGER)`).all(from, to);
}
app.get('/api/reports/payable', auth(...VIEW), async (req, res) => res.json(await payable(req.query.from, req.query.to)));
app.get('/api/reports/payable.csv', auth(...VIEW), async (req, res) => {
  const rows = await payable(req.query.from, req.query.to);
  const q = v => /[",\n]/.test(String(v)) ? `"${String(v).replace(/"/g, '""')}"` : String(v);
  const lines = [['Worker code', 'Name', 'Shift', 'Present', 'Late', 'Absent', 'Payable days', 'From', 'To'].join(',')]
    .concat(rows.map(r => [r.employee_code, r.name, r.shift_name, r.present, r.late, r.absent, r.payable_days, req.query.from, req.query.to].map(q).join(',')));
  res.set('Content-Type', 'text/csv; charset=utf-8');
  res.set('Content-Disposition', `attachment; filename="facein-payable-days_${req.query.from}_to_${req.query.to}.csv"`);
  res.send(lines.join('\r\n') + '\r\n');
});

app.get('/api/reports/summary', auth('supervisor', 'owner'), async (req, res) => {
  await closeDays();
  const today = fmtDate(new Date());
  const weekFrom = addDays(today, -6), monthFrom = addDays(today, -29);
  const pinCheckins = await db.prepare(`SELECT ca.timestamp, w.name, w.employee_code, k.name kiosk FROM checkin_attempt ca
    JOIN worker w ON w.id = ca.worker_id JOIN kiosk k ON k.id = ca.kiosk_id
    WHERE ca.method = 'pin' AND ca.result = 'success' AND substr(ca.timestamp,1,10) >= ? ORDER BY ca.id DESC`).all(weekFrom);
  const overrides = await db.prepare(`SELECT o.timestamp, o.old_status, o.new_status, o.reason, u.name supervisor, a.id attendance_id, a.date, w.name, w.employee_code
    FROM override o JOIN daily_attendance a ON a.id = o.attendance_id JOIN worker w ON w.id = a.worker_id JOIN app_user u ON u.id = o.supervisor_id
    WHERE substr(o.timestamp,1,10) >= ? ORDER BY o.id DESC`).all(weekFrom);
  const topLate = await db.prepare(`SELECT w.id, w.name, w.employee_code, COUNT(*) n FROM daily_attendance a JOIN worker w ON w.id = a.worker_id
    WHERE a.status = 'late' AND a.date >= ? GROUP BY w.id ORDER BY n DESC, w.name LIMIT 5`).all(monthFrom);
  const topOverrides = await db.prepare(`SELECT w.id, w.name, w.employee_code, COUNT(*) n FROM override o JOIN daily_attendance a ON a.id = o.attendance_id
    JOIN worker w ON w.id = a.worker_id WHERE a.date >= ? GROUP BY w.id ORDER BY n DESC, w.name LIMIT 5`).all(monthFrom);
  const noConsent = (await db.prepare(`SELECT COUNT(*) n FROM face_template ft JOIN worker w ON w.id = ft.worker_id WHERE ${ACTIVE_CONSENT_SQL} <> 'grant'`).get()).n;
  const templates = (await db.prepare('SELECT COUNT(*) n FROM face_template').get()).n;
  res.json({ weekFrom, monthFrom, today, pinCheckins, overrides, topLate, topOverrides, compliance: { templatesWithoutConsent: noConsent, templates } });
});

// ---------- settings / admin ----------
const validTime = t => /^([01]\d|2[0-3]):[0-5]\d$/.test(t || '');
const validGrace = g => Number.isInteger(Number(g)) && Number(g) >= 0 && Number(g) <= 120;

app.put('/api/shifts/:id', auth('admin', 'owner'), async (req, res) => {
  const s = await db.prepare('SELECT * FROM shift WHERE id = ?').get(Number(req.params.id));
  if (!s) throw new HttpError(404, 'Shift not found');
  const b = req.body || {};
  if (!validGrace(b.grace_minutes)) bad('Grace must be 0 to 120 minutes');
  if (req.user.role === 'owner') { // owner may change only the grace period (BR2)
    await db.prepare('UPDATE shift SET grace_minutes = ? WHERE id = ?').run(Number(b.grace_minutes), s.id);
  } else {
    if (!String(b.name || '').trim() || !validTime(b.start) || !validTime(b.end)) bad('Enter name, start and end (HH:MM)');
    await db.prepare('UPDATE shift SET name = ?, start = ?, "end" = ?, grace_minutes = ? WHERE id = ?').run(String(b.name).trim(), b.start, b.end, Number(b.grace_minutes), s.id);
  }
  res.json({ ok: true });
});
app.post('/api/shifts', auth('admin'), async (req, res) => {
  const b = req.body || {};
  if (!String(b.name || '').trim() || !validTime(b.start) || !validTime(b.end) || !validGrace(b.grace_minutes)) bad('Enter name, start, end (HH:MM) and grace (0-120)');
  const r = await db.prepare('INSERT INTO shift (name, start, "end", grace_minutes) VALUES (?,?,?,?)').run(String(b.name).trim(), b.start, b.end, Number(b.grace_minutes));
  res.json({ id: Number(r.lastInsertRowid) });
});

app.get('/api/admin/users', auth('admin'), async (req, res) => res.json(await db.prepare('SELECT id, name, email, role FROM app_user ORDER BY id').all()));
const ROLES = ['supervisor', 'hr', 'owner', 'admin'];
app.post('/api/admin/users', auth('admin'), async (req, res) => {
  const { name, email, role, password } = req.body || {};
  if (!String(name || '').trim() || !/^\S+@\S+\.\S+$/.test(email || '') || !ROLES.includes(role)) bad('Enter name, a valid email and a role');
  if (String(password || '').length < 8) bad('Password must be at least 8 characters');
  if (await db.prepare('SELECT 1 FROM app_user WHERE lower(email) = lower(?)').get(email.trim())) bad('Email already used');
  const r = await db.prepare('INSERT INTO app_user (name, email, password_hash, role) VALUES (?,?,?,?)').run(name.trim(), email.trim(), bcrypt.hashSync(password, 10), role);
  res.json({ id: Number(r.lastInsertRowid) });
});
app.put('/api/admin/users/:id', auth('admin'), async (req, res) => {
  const u = await db.prepare('SELECT * FROM app_user WHERE id = ?').get(Number(req.params.id));
  if (!u) throw new HttpError(404, 'User not found');
  const { role, password } = req.body || {};
  if (role !== undefined) {
    if (!ROLES.includes(role)) bad('Bad role');
    if (u.id === req.user.id && role !== 'admin') bad('You cannot remove your own admin role');
    await db.prepare('UPDATE app_user SET role = ? WHERE id = ?').run(role, u.id);
  }
  if (password !== undefined) {
    if (String(password).length < 8) bad('Password must be at least 8 characters');
    await db.prepare('UPDATE app_user SET password_hash = ? WHERE id = ?').run(bcrypt.hashSync(String(password), 10), u.id);
  }
  res.json({ ok: true });
});
app.delete('/api/admin/users/:id', auth('admin'), async (req, res) => {
  const id = Number(req.params.id);
  if (id === req.user.id) bad('You cannot delete yourself');
  if (await db.prepare('SELECT 1 FROM override WHERE supervisor_id = ?').get(id)) bad('This user has made overrides, which are permanent. Change their role or password instead.');
  await db.prepare('DELETE FROM app_user WHERE id = ?').run(id);
  res.json({ ok: true });
});
app.get('/api/admin/kiosks', auth('admin'), async (req, res) => res.json(await db.prepare('SELECT * FROM kiosk ORDER BY id').all()));
app.post('/api/admin/kiosks', auth('admin'), async (req, res) => {
  const { name, location } = req.body || {};
  if (!String(name || '').trim() || !String(location || '').trim()) bad('Enter kiosk name and location');
  const r = await db.prepare('INSERT INTO kiosk (name, location) VALUES (?,?)').run(name.trim(), location.trim());
  res.json({ id: Number(r.lastInsertRowid) });
});
app.put('/api/admin/kiosks/:id', auth('admin'), async (req, res) => {
  const { name, location } = req.body || {};
  if (!String(name || '').trim() || !String(location || '').trim()) bad('Enter kiosk name and location');
  await db.prepare('UPDATE kiosk SET name = ?, location = ? WHERE id = ?').run(name.trim(), location.trim(), Number(req.params.id));
  res.json({ ok: true });
});

// ---------- static pages ----------
app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));
app.get('/', async (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));

app.use((err, req, res, next) => {
  const status = err.status || (err.type === 'entity.too.large' ? 413 : /constraint|BR\d/i.test(err.message) ? 400 : 500);
  if (status === 500) console.error(err);
  res.status(status).json({ error: status === 500 ? 'Something went wrong' : err.message });
});

(async () => {
  const kind = await init();
  console.log('Database: ' + kind);
  if (await seed()) console.log('Seeded demo data');
  await closeDays();
  app.listen(PORT, () => console.log(`FaceIn running on http://localhost:${PORT}  (kiosk: /kiosk)`));
})().catch(e => { console.error('Could not start FaceIn:', e); process.exit(1); });
