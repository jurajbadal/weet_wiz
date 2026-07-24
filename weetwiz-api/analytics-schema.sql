CREATE TABLE IF NOT EXISTS domain_scores (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  hostname         TEXT NOT NULL UNIQUE,
  run_count        INTEGER NOT NULL DEFAULT 0,
  avg_score        REAL NOT NULL DEFAULT 0,
  last_score       INTEGER,
  last_scanned_at  TEXT,
  created_at       TEXT DEFAULT (datetime('now'))
);
