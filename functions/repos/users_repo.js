import { normEmail } from "../_lib/validate.js";

export async function findUserByEmail(env, email){
  return await env.DB.prepare(`
    SELECT id, email_norm, display_name, status,
           password_hash, password_salt, password_iter, password_algo,
           locked_until, pw_fail_count
    FROM users
    WHERE email_norm = ?
    LIMIT 1
  `).bind(normEmail(email)).first();
}

export async function findUserByWa(env, wa){
  return await env.DB.prepare(`
    SELECT id, email_norm, display_name, status,
           password_hash, password_salt, password_iter, password_algo,
           locked_until, pw_fail_count
    FROM users
    WHERE phone = ?
    LIMIT 1
  `).bind(String(wa || "").trim()).first();
}

export async function updateLoginFailure(env, user_id, count, lock_until, now){
  await env.DB.prepare(`
    UPDATE users 
    SET pw_fail_count = ?, locked_until = ?, updated_at = ?
    WHERE id = ?
  `).bind(count, lock_until, now, user_id).run();
}

export async function resetLoginFailure(env, user_id){
  await env.DB.prepare(`
    UPDATE users 
    SET pw_fail_count = 0, locked_until = NULL 
    WHERE id = ?
  `).bind(user_id).run();
}

export async function getUserRoles(env, user_id){
  const r = await env.DB.prepare(`
    SELECT r.name AS name
    FROM user_roles ur
    JOIN roles r ON r.id = ur.role_id
    WHERE ur.user_id = ?
  `).bind(user_id).all();
  return (r.results || []).map(x => String(x.name || ""));
}

export async function createUser(env, payload){
  await env.DB.prepare(`
    INSERT INTO users (
      id, email_norm, display_name, status, phone,
      password_hash, password_salt, password_iter, password_algo,
      created_at, updated_at, pw_fail_count
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
  `).bind(payload.id, payload.email_norm, payload.display_name, payload.status, payload.phone, payload.password_hash, payload.password_salt, payload.password_iter, payload.password_algo, payload.created_at, payload.updated_at).run();
}

export async function attachRole(env, user_id, role_name){
  const role = await env.DB.prepare("SELECT id FROM roles WHERE name = ?").bind(role_name).first();
  const rid = role?.id || crypto.randomUUID();
  if(!role?.id) await env.DB.prepare("INSERT INTO roles (id, name, created_at) VALUES (?, ?, strftime('%s','now'))").bind(rid, role_name).run();
  await env.DB.prepare("INSERT OR IGNORE INTO user_roles (user_id, role_id, created_at) VALUES (?, ?, strftime('%s','now'))").bind(user_id, rid).run();
}

export async function updateUserPassword(env, user_id, data){
  await env.DB.prepare("UPDATE users SET password_hash=?, password_salt=?, password_iter=?, password_algo=?, updated_at=?, pw_fail_count=0, locked_until=NULL WHERE id=?").bind(data.password_hash, data.password_salt, data.password_iter, data.password_algo, data.updated_at, user_id).run();
}
