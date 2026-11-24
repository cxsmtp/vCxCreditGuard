'use strict';

const express = require('express');
const db = require('./db');
const validate = require('./validate');

const router = express.Router();

const listAll = db.prepare('SELECT * FROM products ORDER BY name');
const listByCategory = db.prepare('SELECT * FROM products WHERE category = ? ORDER BY name');
const getById = db.prepare('SELECT * FROM products WHERE id = ?');

// List products, optionally filtered by category.
router.get('/', (req, res) => {
  const raw = req.query.category;

  if (raw !== undefined) {
    const category = validate.category(raw);
    if (category === null) {
      return res.status(400).json({ error: 'invalid category' });
    }
    return res.json(listByCategory.all(category));
  }

  res.json(listAll.all());
});

// Fetch a single product by id.
router.get('/:id', (req, res) => {
  const id = validate.productId(req.params.id);
  if (id === null) {
    return res.status(400).json({ error: 'invalid product id' });
  }

  const product = getById.get(id);
  if (!product) {
    return res.status(404).json({ error: 'product not found' });
  }

  res.json(product);
});

module.exports = router;
