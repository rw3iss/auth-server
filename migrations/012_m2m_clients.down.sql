-- Migration 012 down: drop the m2m_clients table.
--
-- No FK dependencies — m2m_clients is referenced only by audit_log entries
-- (and those store details as JSON, not as a FK), so this is safe.

DROP INDEX IF EXISTS idx_m2m_clients_created_at;
DROP INDEX IF EXISTS idx_m2m_clients_client_id;
DROP TABLE IF EXISTS m2m_clients;
