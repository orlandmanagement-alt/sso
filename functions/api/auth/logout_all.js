import { onLogoutAll } from "../../services/auth/session_service.js";

export async function onRequestPost({ request, env }){
  return onLogoutAll({ request, env });
}
