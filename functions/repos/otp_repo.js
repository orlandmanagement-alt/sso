export async function insertOtpRequest(env, row){
  await env.DB.prepare(`
    INSERT INTO otp_requests (
      id, purpose, identifier_hash, otp_hash, otp_salt,
      attempts, max_attempts, created_at, expires_at, consumed_at
    ) VALUES (?,?,?,?,?,?,?,?,?,?)
  `).bind(
    row.id,
    row.purpose,
    row.identifier_hash,
    row.otp_hash,
    row.otp_salt,
    row.attempts,
    row.max_attempts,
    row.created_at,
    row.expires_at,
    row.consumed_at
  ).run();
}

export async function getLatestActiveOtp(env, purpose, identifier_hash, now){
  return await env.DB.prepare(`
    SELECT *
    FROM otp_requests
    WHERE purpose = ?
      AND identifier_hash = ?
      AND consumed_at IS NULL
      AND expires_at >= ?
    ORDER BY created_at DESC
    LIMIT 1
  `).bind(purpose, identifier_hash, now).first();
}

export async function bumpOtpAttempt(env, id){
  await env.DB.prepare(`
    UPDATE otp_requests
    SET attempts = attempts + 1
    WHERE id = ?
  `).bind(id).run();
}

export async function consumeOtp(env, id, now){
  await env.DB.prepare(`
    UPDATE otp_requests
    SET consumed_at = ?
    WHERE id = ?
  `).bind(now, id).run();
}
