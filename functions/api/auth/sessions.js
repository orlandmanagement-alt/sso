import { onSessions } from "../../services/auth/session_service.js";

export async function onRequestGet({ request, env }){
  return onSessions({ request, env });
}
