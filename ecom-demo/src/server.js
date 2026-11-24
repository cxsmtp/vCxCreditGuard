'use strict';

const express = require('express');
const products = require('./products');
const checkout = require('./checkout');
const { securityHeaders, errorHandler } = require('./security');

const app = express();
// Do not advertise the framework and version.
app.disable('x-powered-by');
app.use(securityHeaders);
// A cart is a few hundred bytes; refuse anything much larger.
app.use(express.json({ limit: '16kb', strict: true }));

app.get('/health', (req, res) => res.json({ status: 'ok' }));

app.use('/api/products', products);
app.use('/api/checkout', checkout);

// Fallback 404 for unknown routes.
app.use((req, res) => res.status(404).json({ error: 'not found' }));
app.use(errorHandler);

const PORT = process.env.PORT || 3000;

if (require.main === module) {
  app.listen(PORT, () => {
    // eslint-disable-next-line no-console
    console.log(`ecom-demo listening on http://localhost:${PORT}`);
  });
}

module.exports = app;
