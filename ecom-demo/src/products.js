'use strict';

const express = require('express');
const db = require('./db');

const router = express.Router();

// List products, optionally filtered by category.
router.get('/', (req, res) => {
  const { category } = req.query;

  if (category) {
    const rows = db
      .prepare('SELECT * FROM products WHERE category = ? ORDER BY name')
      .all(category);
    return res.json(rows);
  }

  const rows = db.prepare('SELECT * FROM products ORDER BY name').all();
  res.json(rows);
});

// Fetch a single product by id.
router.get('/:id', (req, res) => {
  const id = Number.parseInt(req.params.id, 10);
  if (!Number.isInteger(id)) {
    return res.status(400).json({ error: 'invalid product id' });
  }

  const product = db.prepare('SELECT * FROM products WHERE id = ?').get(id);
  if (!product) {
    return res.status(404).json({ error: 'product not found' });
  }

  res.json(product);
});

module.exports = router;
