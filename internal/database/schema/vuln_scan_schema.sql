-- scan_results Table
CREATE TABLE IF NOT EXISTS scan_results (
    scan_id TEXT PRIMARY KEY,
    timestamp TEXT,
    scan_status TEXT,
    resource_type TEXT,
    resource_name TEXT
);

-- vulnerabilities Table
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id TEXT,
    scan_id TEXT,
    severity TEXT,
    cvss REAL,
    status TEXT,
    package_name TEXT,
    current_version TEXT,
    fixed_version TEXT,
    description TEXT,
    published_date TEXT,
    link TEXT,
    PRIMARY KEY (id, scan_id),
    FOREIGN KEY (scan_id) REFERENCES scan_results(scan_id)
);

-- risk_factors Table
CREATE TABLE IF NOT EXISTS risk_factors (
    vulnerability_id TEXT,
    scan_id TEXT,
    risk_factor TEXT,
    PRIMARY KEY (vulnerability_id, scan_id, risk_factor),
    FOREIGN KEY (vulnerability_id, scan_id) REFERENCES vulnerabilities(id, scan_id)
);

-- scan_summary Table
CREATE TABLE IF NOT EXISTS scan_summary (
    scan_id TEXT PRIMARY KEY,
    total_vulnerabilities INTEGER,
    critical_count INTEGER,
    high_count INTEGER,
    medium_count INTEGER,
    low_count INTEGER,
    fixable_count INTEGER,
    compliant BOOLEAN,
    FOREIGN KEY (scan_id) REFERENCES scan_results(scan_id)
);

-- scan_metadata Table
CREATE TABLE IF NOT EXISTS scan_metadata (
    scan_id TEXT PRIMARY KEY,
    scanner_version TEXT,
    policies_version TEXT,
    FOREIGN KEY (scan_id) REFERENCES scan_results(scan_id)
);

-- scanning_rules Table
CREATE TABLE IF NOT EXISTS scanning_rules (
    scan_id TEXT,
    rule TEXT,
    PRIMARY KEY (scan_id, rule),
    FOREIGN KEY (scan_id) REFERENCES scan_results(scan_id)
);

-- excluded_paths Table
CREATE TABLE IF NOT EXISTS excluded_paths (
    scan_id TEXT,
    path TEXT,
    PRIMARY KEY (scan_id, path),
    FOREIGN KEY (scan_id) REFERENCES scan_results(scan_id)
);
