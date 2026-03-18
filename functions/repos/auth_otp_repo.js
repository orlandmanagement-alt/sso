export async function createOtp(env, payload){
  await env.DB.prepare(`
    INSERT INTO otp_requests (
      id, purpose, identifier_hash, otp_hash, otp_salt,
      attempts, max_attempts, created_at, expires_at, consumed_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(
    payload.id,
    payload.purpose,
    payload.identifier_hash,
    payload.otp_hash,
    payload.otp_salt,
    payload.attempts,
    payload.max_attempts,
    payload.created_at,
    payload.expires_at,
    payload.consumed_at
  ).run();
}

export async function getActiveOtp(env, purpose, identifier_hash, now){
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

export async function consumeOtp(env, id, now){
  await env.DB.prepare(`
    UPDATE otp_requests
    SET consumed_at = ?
    WHERE id = ?
  `).bind(now, id).run();
}

export async function bumpOtp(env, id){
  await env.DB.prepare(`
    UPDATE otp_requests
    SET attempts = attempts + 1
    WHERE id = ?
  `).bind(id).run();
}
