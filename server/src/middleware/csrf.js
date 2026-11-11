import { doubleCsrf } from 'csrf-csrf';

// Anti-CSRF protection using the *signed double-submit cookie* pattern (csrf-csrf v4).
//
// Why the existing defenses were not enough:
//   - CORS only stops the attacker's page from READING the response. The browser
//     still SENDS a plain <form> POST (no preflight), cookie attached, and the
//     server still acts on it. CSRF only needs the write to succeed.
//   - SameSite=Lax keys off the registrable domain, not the port. localhost:1337
//     and localhost:4000 are the same site, so the auth cookie is still sent.
//
// What this adds: a secret token that only our own front-end can obtain and echo
// back in the `x-csrf-token` header. The token is an HMAC over a random value,
// the user's session (the JWT cookie) and a server secret. A copy lives in an
// httpOnly cookie; the request must ALSO carry the same token in a header. An
// attacker page can neither read the token nor set a custom header from an
// auto-submitting form, and cannot forge the HMAC without the secret, so a
// forged request fails validation and is rejected with 403.

// Pre-auth routes run before a session exists, so there is nothing to bind a
// token to and nothing for an attacker to gain. They stay exempt.
const CSRF_EXEMPT_PATHS = new Set(['/api/auth/login', '/api/auth/register']);

function getSecret() {
  // Evaluated per request so tests / dotenv can set it after this module loads.
  const secret = process.env.CSRF_SECRET || process.env.JWT_SECRET;
  if (!secret) throw new Error('CSRF_SECRET (or JWT_SECRET) must be set');
  return secret;
}

export const {
  generateCsrfToken,
  doubleCsrfProtection,
  invalidCsrfTokenError
} = doubleCsrf({
  getSecret,
  // Bind every token to the session that requested it: the JWT in the auth
  // cookie. A token minted for one login cannot be replayed for another.
  getSessionIdentifier: (req) => req.cookies?.token || '',
  // No `__Host-` prefix: the demo runs over plain http://localhost and that
  // prefix requires Secure/HTTPS. Use it (with secure: true) in production.
  cookieName: 'csrf-token',
  cookieOptions: {
    httpOnly: true,
    sameSite: 'lax',
    secure: false, // true in production (HTTPS only)
    path: '/'
  },
  // Only the header counts. Never fall back to the cookie or body here — that
  // would turn the check into "cookie equals cookie" and defeat the point.
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token'],
  // "Safe" methods are never protected; the pre-auth routes are skipped by path.
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],
  skipCsrfProtection: (req) => CSRF_EXEMPT_PATHS.has(req.path)
});

// GET /api/csrf-token — hand the logged-in client a fresh token (and set the
// matching cookie). Mounted behind requireAuth so a token is always bound to a
// real session.
export function issueCsrfToken(req, res) {
  const csrfToken = generateCsrfToken(req, res, { overwrite: true });
  res.json({ csrfToken });
}
