INSERT OR IGNORE INTO auth_provider_settings (k, v, updated_at) VALUES
('stepup.enabled', '0', strftime('%s','now')),
('stepup.ttl_sec', '300', strftime('%s','now')),
('trust_device.enabled', '0', strftime('%s','now'));
