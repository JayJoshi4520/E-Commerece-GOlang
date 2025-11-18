INSERT INTO products (title, description, price_cents, stock)
VALUES
 ('Wireless Mouse', 'Ergonomic 2.4GHz mouse', 1999, 100),
 ('Mechanical Keyboard', 'RGB brown switches', 7999, 50),
 ('USB-C Hub', '7-in-1 hub with HDMI', 4599, 75)
ON CONFLICT DO NOTHING;
