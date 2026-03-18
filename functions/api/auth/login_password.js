import { readJson } from "../../_lib/validate.js";
import { loginPasswordService } from "../../services/auth/auth_login_service.js";

export async function onRequestPost({ request, env }){
  const body = await readJson(request) || {};
  return await loginPasswordService({ request, env, body });
}
