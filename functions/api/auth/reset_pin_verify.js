import { verifyPasswordResetService } from "../../services/auth/auth_reset_service.js";
export async function onRequestPost(context){
  const clone = await context.request.clone();
  const body = await clone.json().catch(()=>({}));
  body.new_password = body.pin; // Menerima PIN untuk di-hash
  context.body = body;
  return verifyPasswordResetService(context);
}
