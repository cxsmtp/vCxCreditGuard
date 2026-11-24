'use strict';

const helmet = require('helmet');

// Response hardening for every route, set once in server.js so a new route
// cannot forget it. helmet sets the standard security headers; the options
// below tighten its defaults for an API that only ever returns JSON:
//   * HSTS for a year, subdomains included: browsers use HTTPS only once the
//     demo is put behind TLS.
//   * A Content-Security-Policy that allows nothing (nothing on a JSON response
//     should load or run) and forbids framing.
//   * Framing denied outright, and no referrer.
const helmetMiddleware = helmet({
  strictTransportSecurity: {
    maxAge: 31536000,
    includeSubDomains: true,
  },
  contentSecurityPolicy: {
    useDefaults: false,
    directives: {
      defaultSrc: ["'none'"],
      frameAncestors: ["'none'"],
      baseUri: ["'none'"],
      formAction: ["'none'"],
    },
  },
  xFrameOptions: { action: 'deny' },
  referrerPolicy: { policy: 'no-referrer' },
  crossOriginOpenerPolicy: { policy: 'same-origin' },
  crossOriginResourcePolicy: { policy: 'same-origin' },
});

// What helmet does not cover: no browser features, and nothing cached.
function extraHeaders(req, res, next) {
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=(), payment=()');
  res.setHeader('Cache-Control', 'no-store');
  next();
}

const securityHeaders = [helmetMiddleware, extraHeaders];

// The answer for anything unexpected: a short JSON body, never the error's
// message or stack. The details go to the server log only.
function internalError(res, err) {
  // eslint-disable-next-line no-console
  console.error('ecom-demo: unhandled error:', err && err.message ? err.message : err);
  return res.status(500).json({ error: 'internal error' });
}

// The last middleware: a malformed JSON body or an unexpected failure answers
// with a short JSON error, never Express's default HTML page with a stack trace.
// eslint-disable-next-line no-unused-vars
function errorHandler(err, req, res, next) {
  if (err && (err.type === 'entity.parse.failed' || err.type === 'entity.too.large')) {
    const status = err.type === 'entity.too.large' ? 413 : 400;
    return res.status(status).json({ error: 'invalid request body' });
  }
  return internalError(res, err);
}

module.exports = { securityHeaders, errorHandler, internalError };
