INSERT OR IGNORE INTO auth_provider_settings (k, v, updated_at) VALUES
('otp.default_channel', 'email', strftime('%s','now')),
('otp.email_provider', 'none', strftime('%s','now')),
('otp.sms_provider', 'none', strftime('%s','now')),
('otp.wa_provider', 'none', strftime('%s','now'));
