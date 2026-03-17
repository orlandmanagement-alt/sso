import { onLogout } from "../../services/auth/session_service.js";

export async function onRequestPost({ request, env }){
  return onLogout({ request, env });
}
