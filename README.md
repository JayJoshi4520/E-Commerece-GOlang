# Database Initialization

## 1. Create Tables in Database using **001_init.sql** file
```
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'buyer' CHECK (role IN ('buyer', 'seller')),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

CREATE TABLE IF NOT EXISTS products (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  price_cents INTEGER NOT NULL CHECK (price_cents >= 0),
  stock INTEGER NOT NULL DEFAULT 0 CHECK (stock >= 0),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_email TEXT NOT NULL,
  token_hash TEXT NOT NULL,
  user_agent TEXT,
  ip_addr TEXT,
  created_at TIMESTAMPTZ DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  revoked BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(user_email);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires ON refresh_tokens(expires_at);

```
## 2. Do Migration
```
psql postgres://app:example@localhost:5432/app -c "CREATE EXTENSION IF NOT EXISTS pgcrypto;"
psql postgres://app:example@localhost:5432/app -f deployments/db/migrations/001_init.sql
```
## 3. Seed Some products using **products.sql**
```
INSERT INTO products (title, description, price_cents, stock)
VALUES
 ('Wireless Mouse', 'Ergonomic 2.4GHz mouse', 1999, 100),
 ('Mechanical Keyboard', 'RGB brown switches', 7999, 50),
 ('USB-C Hub', '7-in-1 hub with HDMI', 4599, 75)
ON CONFLICT DO NOTHING;
```
## 4. Initialize the product table in database schema using SQL commands.
```
psql postgres://app:example@localhost:5432/app -f deployments/db/seed/products.sql
```
## 5. Create Makefile
```
.PHONY: up down ps logs seed

up:
	docker compose -f deployments/docker-compose.yml up -d

down:
	docker compose -f deployments/docker-compose.yml down -v

ps:
	docker compose -f deployments/docker-compose.yml ps

logs:
	docker compose -f deployments/docker-compose.yml logs -f --tail=100

seed:
	psql postgres://app:example@localhost:5432/app -f deployments/db/seed/products.sql

```

## 6. Run Seed Makefile
```
make seed
```

## 7. Order Migration using 002_order.sql
```
-- orders
CREATE TABLE IF NOT EXISTS orders (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_email TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending','paid','failed','cancelled')),
  total_cents INTEGER NOT NULL CHECK (total_cents >= 0),
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);

-- order_items
CREATE TABLE IF NOT EXISTS order_items (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  order_id UUID NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
  product_id UUID NOT NULL REFERENCES products(id),
  qty INTEGER NOT NULL CHECK (qty > 0),
  price_cents INTEGER NOT NULL CHECK (price_cents >= 0)
);
```
## 8. Run Migration
```
psql postgres://app:example@localhost:5432/app -f deployments/db/migrations/002_orders.sql
```
