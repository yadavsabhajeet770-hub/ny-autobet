# NY AUTOBET — Production-ready deployment package

## Included
- Rebranded NY AUTOBET frontend with the original supplied UI/functionality preserved where possible.
- Premium responsive `/admin` control center with animated glass UI.
- Server-side license generation using one-time plaintext display; only SHA-256 license hashes are stored.
- Bcrypt admin password verification, HTTP-only admin session cookie, CSRF protection, login rate limiting, security headers, audit logs and session revocation.
- License expiry, status, device/session limits and admin audit trail.
- Supabase schema with RLS enabled. The backend uses the service-role key only on the server.
- Optional `ENGINE_BASE_URL` bridge for an original betting engine that you own/control.

## Important
The uploaded KINGPIN ZIP did not contain the original betting-engine server source. Therefore this package does **not** pretend that the missing betting engine has been recreated. The UI, licensing and admin infrastructure are real; engine operations require the original backend or an authorized upstream configured through `ENGINE_BASE_URL`.

## Deploy
1. Create a Supabase project and run `supabase/schema.sql`.
2. Generate a bcrypt password hash for the admin password.
3. Set the variables in `.env.example` on Render (never commit secrets).
4. Deploy this folder as a Node web service with `npm install` and `npm start`.
5. Open `/admin` and create licenses.

## Security notes
- Never put `SUPABASE_SERVICE_ROLE_KEY` in frontend code.
- Keep the admin password hash and `ADMIN_SECRET` in Render environment variables.
- Rotate secrets if they are ever exposed.
- License keys are shown in full only immediately after generation; the database stores only a hash and last four characters.
