export async function insertOtpRequest(env, r){
  await env.DB.prepare("INSERT INTO otp_requests (id, purpose, identifier_hash, otp_hash, otp_salt, attempts, max_attempts, created_at, expires_at, consumed_at) VALUES (?,?,?,?,?,?,?,?,?,?)").bind(r.id, r.purpose, r.identifier_hash, r.otp_hash, r.otp_salt, r.attempts, r.max_attempts, r.created_at, r.expires_at, r.consumed_at).run();
}
export async function getLatestActiveOtp(env, p, h, n){
  return await env.DB.prepare("SELECT * FROM otp_requests WHERE purpose=? AND identifier_hash=? AND consumed_at IS NULL AND expires_at>=? ORDER BY created_at DESC LIMIT 1").bind(p, h, n).first();
}
export async function bumpOtpAttempt(env, id){
  await env.DB.prepare("UPDATE otp_requests SET attempts=attempts+1 WHERE id=?").bind(id).run();
}
export async function consumeOtp(env, id, now){
  await env.DB.prepare("UPDATE otp_requests SET consumed_at=? WHERE id=?").bind(now, id).run();
}
