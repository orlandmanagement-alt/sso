import { normEmail } from "../_lib/validate.js";

export async function findUserByEmail(env, email){
  return await env.DB.prepare(`
    SELECT id, email_norm, display_name, status,
           password_hash, password_salt, password_iter, password_algo
    FROM users
    WHERE email_norm = ?
    LIMIT 1
  `).bind(normEmail(email)).first();
}

export async function findUserByWa(env, wa){
  return await env.DB.prepare(`
    SELECT id, email_norm, display_name, status,
           password_hash, password_salt, password_iter, password_algo
    FROM users
    WHERE phone = ?
    LIMIT 1
  `).bind(String(wa || "").trim()).first();
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

export async function ensureRole(env, name){
  let row = await env.DB.prepare(`
    SELECT id
    FROM roles
    WHERE name = ?
    LIMIT 1
  `).bind(String(name || "")).first();

  if(row?.id) return row.id;

  const id = crypto.randomUUID();
  await env.DB.prepare(`
    INSERT INTO roles (id, name, created_at)
    VALUES (?, ?, strftime('%s','now'))
  `).bind(id, String(name || "")).run();

  return id;
}

export async function createUser(env, payload){
  await env.DB.prepare(`
    INSERT INTO users (
      id, email_norm, display_name, status, phone,
      password_hash, password_salt, password_iter, password_algo,
      created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(
    payload.id,
    payload.email_norm,
    payload.display_name,
    payload.status,
    payload.phone,
    payload.password_hash,
    payload.password_salt,
    payload.password_iter,
    payload.password_algo,
    payload.created_at,
    payload.updated_at
  ).run();
}

export async function attachRole(env, user_id, role_name){
  const role_id = await ensureRole(env, role_name);
  await env.DB.prepare(`
    INSERT OR IGNORE INTO user_roles (user_id, role_id, created_at)
    VALUES (?, ?, strftime('%s','now'))
  `).bind(user_id, role_id).run();
}

export async function updateUserPassword(env, user_id, data){
  await env.DB.prepare(`
    UPDATE users
    SET password_hash = ?,
        password_salt = ?,
        password_iter = ?,
        password_algo = ?,
        updated_at = ?
    WHERE id = ?
  `).bind(
    data.password_hash,
    data.password_salt,
    data.password_iter,
    data.password_algo,
    data.updated_at,
    user_id
  ).run();
}
