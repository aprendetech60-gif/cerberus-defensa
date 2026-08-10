-- Inicializar base de datos CERBERUS
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Crear índices adicionales
CREATE INDEX IF NOT EXISTS idx_audit_records_timestamp 
    ON audit_records(timestamp DESC);
    
CREATE INDEX IF NOT EXISTS idx_execution_records_created 
    ON execution_records(created_at DESC);