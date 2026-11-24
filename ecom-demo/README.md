# ecom-demo

A small, self-contained e-commerce demo API used to demonstrate a Checkmarx One
scan. It exposes a product catalog and a checkout endpoint backed by an
in-memory SQLite database.

## Run

```bash
npm ci        # exactly what package-lock.json says
npm start
# -> ecom-demo listening on http://localhost:3000
```

## Endpoints

| Method | Path                       | Description                                  |
| ------ | -------------------------- | -------------------------------------------- |
| GET    | `/health`                  | Liveness check.                              |
| GET    | `/api/products`            | List products (`?category=` filter).         |
| GET    | `/api/products/:id`        | Fetch one product.                           |
| POST   | `/api/checkout`            | Place an order for a cart of items.          |

### Checkout request

```json
{
  "email": "shopper@example.com",
  "items": [
    { "productId": 1, "quantity": 2 },
    { "productId": 4, "quantity": 1 }
  ]
}
```

The total is computed server-side from stored prices; stock is verified and
decremented inside a single transaction.

## Hardening

- Every response carries the [helmet](https://helmetjs.github.io/) headers,
  tightened for a JSON-only API: `Strict-Transport-Security` (one year,
  subdomains), a deny-all `Content-Security-Policy`, `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`, plus
  `Permissions-Policy` and `Cache-Control: no-store` (`src/security.js`);
  `X-Powered-By` is off.
- Input is validated strictly (`src/validate.js`): whole-number ids and
  quantities, at most 50 cart lines and 100 of one product, a single short
  category name. Repeated products in one cart are combined before the stock
  check, and the stock guard is part of the `UPDATE`, so an order can never
  oversell.
- Bodies over 16 KB, malformed JSON and unexpected failures get a short JSON
  error, never the error's message or a stack trace (those go to the server log).
- All SQL is parameterised. Dependencies are locked in `package-lock.json`.
