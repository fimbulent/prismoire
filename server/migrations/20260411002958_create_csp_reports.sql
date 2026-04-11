CREATE TABLE IF NOT EXISTS csp_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    received_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    document_uri TEXT,
    referrer TEXT,
    violated_directive TEXT,
    effective_directive TEXT,
    original_policy TEXT,
    blocked_uri TEXT,
    source_file TEXT,
    line_number INTEGER,
    column_number INTEGER,
    status_code INTEGER,
    script_sample TEXT
);

CREATE INDEX IF NOT EXISTS idx_csp_reports_received_at ON csp_reports(received_at);
