'use strict';

const express = require('express');
const db = require('./db');

const router = express.Router();

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// Accept a cart of { productId, quantity } items, verify stock, compute the
// total from server-side prices, decrement stock and record the order.
router.post('/', (req, res) => {
  const { email, items } = req.body || {};

  if (typeof email !== 'string' || !EMAIL_RE.test(email)) {
    return res.status(400).json({ error: 'a valid email is required' });
  }
  if (!Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ error: 'cart is empty' });
  }

  const getProduct = db.prepare('SELECT * FROM products WHERE id = ?');
  const lines = [];
  let total = 0;

  for (const item of items) {
    const id = Number.parseInt(item && item.productId, 10);
    const qty = Number.parseInt(item && item.quantity, 10);

    if (!Number.isInteger(id) || !Number.isInteger(qty) || qty <= 0) {
      return res.status(400).json({ error: 'invalid cart item' });
    }

    const product = getProduct.get(id);
    if (!product) {
      return res.status(404).json({ error: `product ${id} not found` });
    }
    if (product.stock < qty) {
      return res
        .status(409)
        .json({ error: `insufficient stock for ${product.name}` });
    }

    total += product.price * qty;
    lines.push({ product, qty });
  }

  const finalize = db.transaction(() => {
    const decrement = db.prepare(
      'UPDATE products SET stock = stock - ? WHERE id = ?'
    );
    for (const line of lines) {
      decrement.run(line.qty, line.product.id);
    }

    const order = db
      .prepare(
        'INSERT INTO orders (email, total, created_at) VALUES (?, ?, ?)'
      )
      .run(email, total, new Date().toISOString());

    return order.lastInsertRowid;
  });

  const orderId = finalize();
  res.status(201).json({ orderId, total: Number(total.toFixed(2)) });
});

module.exports = router;
