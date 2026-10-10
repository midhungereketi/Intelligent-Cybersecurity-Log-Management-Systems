-- Member 1 metadata. Run against PostgreSQL after creating the database.
CREATE TABLE IF NOT EXISTS device (
    device_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    device_name VARCHAR(120) NOT NULL,
    ip_address INET,
    mac_address VARCHAR(17),
    device_type VARCHAR(60) NOT NULL,
    operating_system VARCHAR(120),
    location VARCHAR(120),
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE'
        CHECK (status IN ('ACTIVE', 'INACTIVE')),
    CONSTRAINT device_name_unique UNIQUE (device_name)
);

CREATE TABLE IF NOT EXISTS log_source (
    source_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    source_name VARCHAR(120) NOT NULL,
    source_type VARCHAR(60) NOT NULL,
    ip_address INET,
    protocol VARCHAR(30),
    device_id BIGINT NOT NULL REFERENCES device(device_id) ON DELETE RESTRICT,
    CONSTRAINT source_name_device_unique UNIQUE (device_id, source_name)
);

CREATE INDEX IF NOT EXISTS log_source_device_idx ON log_source(device_id);
