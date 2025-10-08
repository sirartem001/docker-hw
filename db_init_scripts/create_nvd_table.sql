CREATE TABLE nvd_cpes (
  cpe_name_id UUID PRIMARY KEY,
  cpe_name TEXT NOT NULL,
  created TIMESTAMP WITH TIME ZONE,
  last_modified TIMESTAMP WITH TIME ZONE,
  deprecated BOOLEAN DEFAULT FALSE,
  deprecated_by TEXT,
  titles JSONB,
  raw JSONB
);
