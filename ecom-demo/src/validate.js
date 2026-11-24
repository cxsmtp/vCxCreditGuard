'use strict';

// Strict input parsing shared by the routes. Number.parseInt accepts "12abc"
// and silently drops the rest, so ids and quantities are matched whole instead.

const ID_RE = /^[1-9][0-9]{0,8}$/;
const MAX_QUANTITY = 100;
const MAX_CART_ITEMS = 50;
const MAX_EMAIL_LENGTH = 254;
const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]+\.[^\s@]+$/;
const CATEGORY_RE = /^[a-z][a-z0-9-]{0,31}$/;

// A positive integer, given as a JSON number or a string of digits.
function positiveInt(value, max) {
  let n;
  if (typeof value === 'number') {
    n = value;
  } else if (typeof value === 'string' && ID_RE.test(value)) {
    n = Number(value);
  } else {
    return null;
  }
  if (!Number.isSafeInteger(n) || n <= 0 || (max !== undefined && n > max)) {
    return null;
  }
  return n;
}

function productId(value) {
  return positiveInt(value);
}

function quantity(value) {
  return positiveInt(value, MAX_QUANTITY);
}

function email(value) {
  if (typeof value !== 'string' || value.length > MAX_EMAIL_LENGTH) {
    return null;
  }
  return EMAIL_RE.test(value) ? value : null;
}

// One category name; a repeated ?category= arrives as an array and is refused.
function category(value) {
  if (typeof value !== 'string') {
    return null;
  }
  const text = value.trim().toLowerCase();
  return CATEGORY_RE.test(text) ? text : null;
}

module.exports = {
  MAX_CART_ITEMS,
  MAX_QUANTITY,
  category,
  email,
  productId,
  quantity,
};
