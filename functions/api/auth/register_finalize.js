import { verifyRegisterService } from "../../services/auth/auth_register_service.js";
export async function onRequestPost(context){
  const clone = await context.request.clone();
  const body = await clone.json().catch(()=>({}));
  body.password = body.pin; // Menerima PIN untuk di-hash
  context.body = body;
  return verifyRegisterService(context);
}
