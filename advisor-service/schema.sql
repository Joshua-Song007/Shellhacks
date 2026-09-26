-- Advisor DB schema (currentDev.md item 4). Derived/structured data only;
-- raw events live in the tcell-telemetry-raw Space, never here.
-- Run as doadmin (owns the schema), then the GRANTs give the advisor user access.

CREATE TABLE IF NOT EXISTS incidents (
    id            bigserial   PRIMARY KEY,
    threat_id     text        NOT NULL CHECK (threat_id ~ '^[0-9a-f]{64}$'),  -- SHA-256 hex (FR-D-9)
    device_pubkey text        NOT NULL,                                       -- mesh identity key, hex
    ts            timestamptz NOT NULL,
    score         integer     NOT NULL CHECK (score >= 0),
    actions       text[]      NOT NULL,                                       -- ordered Stage-1 action names
    attack_ids    text[]      NOT NULL,
    latency_ns    bigint      CHECK (latency_ns >= 0),                        -- NFR-1
    UNIQUE (device_pubkey, threat_id, ts)                                     -- idempotent re-uploads
);
CREATE INDEX IF NOT EXISTS incidents_device_ts ON incidents (device_pubkey, ts);

-- ponytail: trend summaries as a view over incidents, not a second table; materialize if it gets slow.
CREATE OR REPLACE VIEW device_risk_daily AS
SELECT device_pubkey,
       date_trunc('day', ts) AS day,
       count(*)              AS incidents,
       max(score)            AS max_score,
       avg(score)::numeric(6,1) AS avg_score
FROM incidents
GROUP BY device_pubkey, date_trunc('day', ts);

GRANT SELECT, INSERT ON incidents TO advisor;
GRANT USAGE ON SEQUENCE incidents_id_seq TO advisor;
GRANT SELECT ON device_risk_daily TO advisor;
