'use strict';

const Database = require('better-sqlite3');

// In-memory database seeded with a small product catalog. This keeps the demo
// self-contained (no external database required).
const db = new Database(':memory:');

db.exec(`
  CREATE TABLE products (
    id       INTEGER PRIMARY KEY,
    name     TEXT NOT NULL,
    category TEXT NOT NULL,
    price    REAL NOT NULL,
    stock    INTEGER NOT NULL
  );

  CREATE TABLE orders (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    email      TEXT NOT NULL,
    total      REAL NOT NULL,
    created_at TEXT NOT NULL
  );
`);

const seed = [
  [1, 'Aeron Mug', 'kitchen', 14.5, 120],
  [2, 'Trailhead Backpack', 'outdoor', 89.0, 40],
  [3, 'Lumen Desk Lamp', 'home', 45.99, 65],
  [4, 'Cascade Water Bottle', 'outdoor', 22.0, 200],
  [5, 'Meridian Notebook', 'office', 9.75, 300],
];

const insert = db.prepare(
  'INSERT INTO products (id, name, category, price, stock) VALUES (?, ?, ?, ?, ?)'
);
for (const row of seed) {
  insert.run(row);
}

module.exports = db;
