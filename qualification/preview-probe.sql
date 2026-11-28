-- Apply ONLY to the dedicated Preview D1, never production.
CREATE TABLE IF NOT EXISTS eg_probe (id INTEGER PRIMARY KEY,value TEXT NOT NULL);
INSERT INTO eg_probe(id,value) VALUES(1,'execution-guard-v030') ON CONFLICT(id) DO NOTHING;
CREATE TABLE IF NOT EXISTS eg_preview_identity (id INTEGER PRIMARY KEY,value TEXT NOT NULL);
INSERT INTO eg_preview_identity(id,value) VALUES(1,'execution-guard-preview-v1') ON CONFLICT(id) DO NOTHING;
