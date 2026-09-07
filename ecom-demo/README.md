# ecom-demo

A small, self-contained e-commerce demo API used to demonstrate a Checkmarx One
scan. It exposes a product catalog and a checkout endpoint backed by an
in-memory SQLite database.

## Run

```bash
npm install
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
