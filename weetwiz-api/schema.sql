CREATE TABLE IF NOT EXISTS users (
  id                  INTEGER PRIMARY KEY AUTOINCREMENT,
  email               TEXT NOT NULL UNIQUE,
  stripe_customer_id  TEXT UNIQUE,
  created_at          TEXT DEFAULT (datetime('now'))
);

-- NOTE: usage_count/last_used_at added via ALTER TABLE against the live prod DB
-- (CREATE TABLE IF NOT EXISTS is a no-op on an existing table — this DDL only
-- documents current shape / applies on a fresh DB, e.g. local wrangler d1).
CREATE TABLE IF NOT EXISTS api_keys (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id      INTEGER NOT NULL REFERENCES users(id),
  key          TEXT NOT NULL UNIQUE,
  active       INTEGER NOT NULL DEFAULT 1,
  usage_count  INTEGER NOT NULL DEFAULT 0,
  last_used_at TEXT,
  created_at   TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS purchases (
  id                          INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id                     INTEGER NOT NULL REFERENCES users(id),
  stripe_checkout_session_id  TEXT UNIQUE,
  stripe_payment_intent_id    TEXT UNIQUE,
  amount_cents                INTEGER,
  currency                    TEXT DEFAULT 'usd',
  status                      TEXT NOT NULL DEFAULT 'pending',
  created_at                  TEXT DEFAULT (datetime('now'))
);
