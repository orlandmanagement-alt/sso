CREATE TABLE IF NOT EXISTS auth_provider_settings (
  k TEXT PRIMARY KEY,
  v TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);

INSERT OR IGNORE INTO auth_provider_settings (k, v, updated_at) VALUES
('otp_default_channel', 'email', strftime('%s','now')),
('otp_resend_cooldown_sec', '30', strftime('%s','now')),
('otp_expiry_sec', '300', strftime('%s','now')),
('otp_email_provider', 'resend', strftime('%s','now')),
('otp_email_from', 'no-reply@orlandmanagement.com', strftime('%s','now')),
('otp_resend_api_key', '', strftime('%s','now')),
('otp_sms_provider', 'disabled', strftime('%s','now')),
('otp_sms_api_key', '', strftime('%s','now')),
('otp_sms_sender', 'ORLAND', strftime('%s','now')),
('otp_wa_provider', 'disabled', strftime('%s','now')),
('otp_wa_api_key', '', strftime('%s','now')),
('otp_wa_sender', '', strftime('%s','now'));
