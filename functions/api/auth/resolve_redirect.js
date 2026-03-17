import { onResolveRedirect } from "../../services/auth/redirect_service.js";

export async function onRequestGet({ request, env }){
  return onResolveRedirect({ request, env });
}
