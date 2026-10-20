CREATE TABLE IF NOT EXISTS access_logs (
    id INTEGER PRIMARY KEY,
    at TEXT NOT NULL,
    ip TEXT,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    status INTEGER NOT NULL,
    user_agent TEXT,
    referer TEXT,
    duration_ms INTEGER NOT NULL,
    student_id TEXT,
    real_name TEXT
);

CREATE INDEX IF NOT EXISTS access_logs_at_idx ON access_logs (at);

CREATE TABLE IF NOT EXISTS log_budget (
    day INTEGER PRIMARY KEY,
    used INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS cleanup_budget (
    day INTEGER PRIMARY KEY,
    reserved INTEGER NOT NULL
);
