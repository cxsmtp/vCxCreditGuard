'use strict';

const express = require('express');
const products = require('./products');
const checkout = require('./checkout');

const app = express();
app.use(express.json());

app.get('/health', (req, res) => res.json({ status: 'ok' }));

app.use('/api/products', products);
app.use('/api/checkout', checkout);

// Fallback 404 for unknown routes.
app.use((req, res) => res.status(404).json({ error: 'not found' }));

const PORT = process.env.PORT || 3000;

if (require.main === module) {
  app.listen(PORT, () => {
    // eslint-disable-next-line no-console
    console.log(`ecom-demo listening on http://localhost:${PORT}`);
  });
}

module.exports = app;
