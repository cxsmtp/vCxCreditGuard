'use strict';

// Response hardening for every route: the API only ever returns JSON, so the
// Content-Security-Policy forbids everything (nothing on a JSON response should
// load or run), and HSTS tells browsers to use HTTPS only once the demo is put
// behind TLS. Set here, once, rather than per route, so a new route cannot
// forget them.
const SECURITY_HEADERS = Object.freeze({
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
  'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Permissions-Policy': 'geolocation=(), microphone=(), camera=(), payment=()',
  'Cache-Control': 'no-store',
});

function securityHeaders(req, res, next) {
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
    res.setHeader(name, value);
  }
  next();
}

// The last middleware: a malformed JSON body or an unexpected failure answers
// with a short JSON error, never Express's default HTML page with a stack trace.
// eslint-disable-next-line no-unused-vars
function errorHandler(err, req, res, next) {
  if (err && (err.type === 'entity.parse.failed' || err.type === 'entity.too.large')) {
    const status = err.type === 'entity.too.large' ? 413 : 400;
    return res.status(status).json({ error: 'invalid request body' });
  }
  // eslint-disable-next-line no-console
  console.error('ecom-demo: unhandled error', err && err.message ? err.message : err);
  return res.status(500).json({ error: 'internal error' });
}

module.exports = { SECURITY_HEADERS, securityHeaders, errorHandler };
