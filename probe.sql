CREATE TABLE IF NOT EXISTS eg_probe (id INTEGER PRIMARY KEY CHECK (id = 1), value TEXT NOT NULL);
INSERT INTO eg_probe (id, value) VALUES (1, 'execution-guard-v030') ON CONFLICT(id) DO UPDATE SET value = excluded.value;
