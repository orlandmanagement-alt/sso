export async function createOtp(env, p){
  await env.DB.prepare("INSERT INTO otp_requests (id, purpose, identifier_hash, otp_hash, otp_salt, attempts, max_attempts, created_at, expires_at, consumed_at) VALUES (?,?,?,?,?,?,?,?,?,?)").bind(p.id, p.purpose, p.identifier_hash, p.otp_hash, p.otp_salt, p.attempts, p.max_attempts, p.created_at, p.expires_at, p.consumed_at).run();
}
export async function getActiveOtp(env, purpose, hash, now){
  return await env.DB.prepare("SELECT * FROM otp_requests WHERE purpose=? AND identifier_hash=? AND consumed_at IS NULL AND expires_at>=? ORDER BY created_at DESC LIMIT 1").bind(purpose, hash, now).first();
}
export async function consumeOtp(env, id, now){
  await env.DB.prepare("UPDATE otp_requests SET consumed_at=? WHERE id=?").bind(now, id).run();
}
export async function bumpOtp(env, id){
  await env.DB.prepare("UPDATE otp_requests SET attempts=attempts+1 WHERE id=?").bind(id).run();
}
