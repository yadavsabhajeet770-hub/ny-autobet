# NY AUTOBET deployment checklist

## 1. Supabase
Run `supabase/schema.sql` in the Supabase SQL editor. Keep RLS enabled.

## 2. Admin secret
Generate a bcrypt hash locally:

`node scripts/generate-admin-hash.mjs "your-long-admin-password"`

Create a long random `ADMIN_SECRET` (64+ characters). Never commit either secret.

## 3. Render environment
Set:
- `NODE_ENV=production`
- `SUPABASE_URL`
- `SUPABASE_SERVICE_ROLE_KEY`
- `ADMIN_PASSWORD_HASH`
- `ADMIN_SECRET`
- `ENGINE_BASE_URL` only when an authorized engine backend is available

## 4. Deploy
Use the included `render.yaml`, or configure:
- Build: `npm install`
- Start: `npm start`
- Health: `/health`

## 5. Verify
- `/health` reports database/engine state.
- `/admin` opens the protected control center.
- Generate one test license.
- Validate it from the main site.
- Stop its session from Admin and verify the browser receives `authError`.

## Security
Never expose `SUPABASE_SERVICE_ROLE_KEY`, `ADMIN_PASSWORD_HASH`, or `ADMIN_SECRET` in frontend code. Rotate all secrets if they are ever leaked.
