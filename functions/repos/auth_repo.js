export { findUserByEmail, getUserRoles } from "./users_repo.js";

export async function findInviteByEmailHash(env, hash) {
  return await env.DB.prepare(`
    SELECT * FROM invites 
    WHERE email_hash = ? AND used_at IS NULL AND expires_at >= strftime('%s','now') 
    LIMIT 1
  `).bind(hash).first();
}
