-- Ghost Data Still Exists: point-in-time database snapshot
-- Captured at: 2026-06-05T12:00:00Z
-- Database topology: failover_replica
BEGIN TRANSACTION;
CREATE TABLE customer_profiles_primary (resource_id TEXT PRIMARY KEY, user_id TEXT, full_name TEXT, email TEXT, phone TEXT, account_status TEXT, updated_at TEXT);
CREATE TABLE customer_profiles_failover_replica (resource_id TEXT PRIMARY KEY, user_id TEXT, full_name TEXT, email TEXT, phone TEXT, account_status TEXT, updated_at TEXT);
INSERT INTO customer_profiles_failover_replica VALUES('account_9901','user_901','Tess Halvorsen','tess.halvorsen@example.org','+47 912 33 101','ACTIVE','2026-06-05T11:00:00Z');
INSERT INTO customer_profiles_primary VALUES('account_9999','user_9999','Ravi Okonkwo-Lee','ravi.okonkwo.lee@example.org','+234 802 555 9999','ACTIVE','2026-06-05T11:00:00Z');
COMMIT;
