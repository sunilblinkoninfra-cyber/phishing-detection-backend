-- ==============================
-- Core email decisions
-- ==============================
CREATE TABLE email_decisions (
    id UUID PRIMARY KEY,
    risk_score INTEGER NOT NULL,
    category VARCHAR(10) NOT NULL,
    decision VARCHAR(15) NOT NULL,
    findings JSONB NOT NULL,
    model_version VARCHAR(50),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ==============================
-- SOC alerts (WARM + HOT)
-- ==============================
CREATE TABLE soc_alerts (
    id UUID PRIMARY KEY,
    email_id UUID NOT NULL REFERENCES email_decisions(id),
    category VARCHAR(10) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'OPEN',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ==============================
-- SOC analyst actions (IMMUTABLE)
-- ==============================
CREATE TABLE soc_actions (
    id UUID PRIMARY KEY,
    alert_id UUID NOT NULL REFERENCES soc_alerts(id),
    action VARCHAR(30) NOT NULL,
    acted_by JSONB NOT NULL,
    notes TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ==============================
-- Audit log (append-only)
-- ==============================
CREATE TABLE audit_log (
    id UUID PRIMARY KEY,
    entity_type VARCHAR(50),
    entity_id UUID,
    action VARCHAR(50),
    actor JSONB,
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ==============================
-- ML feedback (future training)
-- ==============================
CREATE TABLE ml_feedback (
    id UUID PRIMARY KEY,
    email_id UUID NOT NULL,
    label VARCHAR(20) NOT NULL, -- FP / TP
    model_version VARCHAR(50),
    source VARCHAR(20), -- SOC / AUTO
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
-- ==============================
-- Tenant registry
-- ==============================
CREATE TABLE tenants (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ==============================
-- Tenant risk policies
-- ==============================
CREATE TABLE tenant_policies (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    cold_threshold INT NOT NULL,
    warm_threshold INT NOT NULL,
    weights JSONB NOT NULL,
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ==============================
-- Blocklists (authoritative)
-- ==============================
CREATE TABLE blocklists (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    block_type VARCHAR(20) NOT NULL, -- SENDER | DOMAIN | URL
    value TEXT NOT NULL,
    created_by JSONB NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    active BOOLEAN DEFAULT TRUE
);
