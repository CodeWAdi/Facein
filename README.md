# FaceIn - consent-first face attendance (prototype, dummy data only)

Node 22 + Express + PostgreSQL (hosted on Neon in production), vanilla JS front end. Face recognition runs in the browser with
face-api.js (models from jsDelivr CDN); only a 128-number descriptor is stored, never an image.

**Live scans** (Supervisor, HR, Owner): a page that lists every kiosk face scan and PIN entry as it happens, refreshing every
3 seconds. It shows time, kiosk, method, result and the worker's name when known; a face that is not recognised shows as
Unknown. It reads the existing check-in attempt log, so no face image or descriptor is stored for attempts.

## Run locally (webcam works on localhost)
    npm install
    npm start            # http://localhost:3000  (kiosk: http://localhost:3000/kiosk)
    npm run reset        # wipe the local database; it reseeds on next start

Without `DATABASE_URL` the app uses an embedded Postgres (PGlite) stored in `./data/pgdata`, so no install is needed.
To use a real Postgres locally instead: `DATABASE_URL=postgres://user:pass@localhost:5432/facein npm start`.

Demo logins (password `Demo@123`): supervisor@ / hr@ / owner@ / admin@facein.demo.
Kiosk PIN demo: worker codes 1001-1040, PIN 1234.

## Deploy on a public HTTPS link (Render, free)
1. Push this folder to a GitHub repo.
2. Render -> New -> Blueprint -> pick the repo (uses `render.yaml`). You get `https://facein-xxxx.onrender.com`.
   Or use the `Dockerfile` on any Docker host (Railway, Fly.io, Cloud Run).

## Permanent database (Neon Postgres, free)
Render's free disk is wiped on every restart/redeploy, so the data lives in a hosted Postgres instead.
1. Sign up at https://neon.tech (GitHub login is fine) -> create a project (Postgres 16 or 17, pick the region
   closest to your Render service, e.g. Singapore or US West).
2. Copy the connection string (Dashboard -> Connect, "pooled connection" is fine). It looks like
   `postgresql://user:password@ep-xxxx.region.aws.neon.tech/neondb?sslmode=require`.
3. Render -> your service -> Environment -> add `DATABASE_URL` = that string -> Save (Render redeploys).
On first start the app creates the 9 tables and the BR3/BR5 triggers and loads the demo data once. After that,
restarts and redeploys keep all data. To start over with fresh demo data, run this in Neon's SQL Editor and
restart the service: `DROP SCHEMA public CASCADE; CREATE SCHEMA public;`

## Environment
`SESSION_SECRET` (cookie signing), `FACE_THRESHOLD` (default 0.45; lower = stricter), `TZ` (default Asia/Kolkata),
`PORT`, `DATABASE_URL` (Postgres connection string; without it an embedded local database in `./data` is used).

## Assumptions
- Sunday is the weekly off; finished working days with no check-in become Absent.
- Payable days = Present + Late (after overrides). "This week" = last 7 days, "this month" = last 30 days.
- Worker codes are digits so they can be typed on the kiosk keypad. Every worker has a PIN as fallback.
- Seeded workers have consent records and historical face check-ins but no templates (no real faces in dummy data);
  enrol faces live from Workers -> worker -> Enrol face.
- Kiosk face match: distance <= 0.45 in 3 consecutive frames; the server re-checks the threshold, active consent and
  template before marking. BR1-BR5 are also enforced by Postgres constraints/triggers.
- Prototype only: the public kiosk endpoint serves face descriptors to the kiosk browser. A production build should
  register kiosk devices with a secret key and add PIN attempt limits.
