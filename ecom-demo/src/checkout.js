'use strict';

const express = require('express');
const db = require('./db');
const validate = require('./validate');

const router = express.Router();

const getProduct = db.prepare('SELECT * FROM products WHERE id = ?');
// The stock guard is in the statement itself, so stock can never go negative.
const decrement = db.prepare(
  'UPDATE products SET stock = stock - ? WHERE id = ? AND stock >= ?'
);
const insertOrder = db.prepare(
  'INSERT INTO orders (email, total, created_at) VALUES (?, ?, ?)'
);

class CheckoutError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

// Stock is checked and taken in one transaction: all lines or none.
const placeOrder = db.transaction((email, quantities) => {
  let totalCents = 0;
  for (const [id, qty] of quantities) {
    const product = getProduct.get(id);
    if (!product) {
      throw new CheckoutError(404, `product ${id} not found`);
    }
    if (decrement.run(qty, id, qty).changes !== 1) {
      throw new CheckoutError(409, `insufficient stock for product ${id}`);
    }
    totalCents += Math.round(product.price * 100) * qty;
  }
  const total = totalCents / 100;
  const order = insertOrder.run(email, total, new Date().toISOString());
  return { orderId: order.lastInsertRowid, total };
});

// Accept a cart of { productId, quantity } items, verify stock, compute the
// total from server-side prices, decrement stock and record the order.
router.post('/', (req, res) => {
  const body = req.body && typeof req.body === 'object' ? req.body : {};
  const email = validate.email(body.email);
  const { items } = body;

  if (email === null) {
    return res.status(400).json({ error: 'a valid email is required' });
  }
  if (!Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ error: 'cart is empty' });
  }
  if (items.length > validate.MAX_CART_ITEMS) {
    return res.status(400).json({ error: 'too many cart items' });
  }

  // The same product listed twice is one line: otherwise each line would pass
  // the stock check on its own and together take more than there is.
  const quantities = new Map();
  for (const item of items) {
    const id = validate.productId(item && item.productId);
    const qty = validate.quantity(item && item.quantity);
    if (id === null || qty === null) {
      return res.status(400).json({ error: 'invalid cart item' });
    }
    const combined = (quantities.get(id) || 0) + qty;
    if (combined > validate.MAX_QUANTITY) {
      return res.status(400).json({ error: 'invalid cart item' });
    }
    quantities.set(id, combined);
  }

  try {
    const { orderId, total } = placeOrder(email, quantities);
    return res.status(201).json({ orderId: Number(orderId), total });
  } catch (err) {
    if (err instanceof CheckoutError) {
      return res.status(err.status).json({ error: err.message });
    }
    throw err;
  }
});

module.exports = router;
