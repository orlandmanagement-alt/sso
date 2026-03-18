import { redirect } from "../../_lib/response.js";
import { getGoogleUser, getFacebookUser } from "../../_lib/oauth_helper.js";

export async function onRequestGet({ request, env }) {
  const url = new URL(request.url);
  const provider = url.searchParams.get("provider");
  const code = url.searchParams.get("code");
  const baseUrl = url.origin;
  const redirectUri = `${baseUrl}/api/auth/oauth_callback?provider=${provider}`;

  try {
    let userData = null;
    if (provider === "google") userData = await getGoogleUser(code, env, redirectUri);
    else if (provider === "facebook") userData = await getFacebookUser(code, env, redirectUri);

    if(!userData || !userData.email) throw new Error("Gagal mengambil email dari provider.");

    // Cek Database kita
    const existingUser = await env.DB.prepare("SELECT * FROM users WHERE email=? OR social_id=?").bind(userData.email, userData.id).first();
    
    if (existingUser) {
      // JIKA SUDAH PUNYA AKUN: Langsung Login (Set Session Cookie di sini pada versi pro, lalu redirect)
      return redirect(`${baseUrl}/?social_status=success`);
    } else {
      // JIKA BELUM PUNYA AKUN: Lempar ke halaman Frontend untuk lengkapi form (No HP & Password)
      const query = new URLSearchParams({ 
        social_status: 'incomplete', provider: provider, social_id: userData.id, 
        name: userData.name || '', email: userData.email || '' 
      });
      return redirect(`${baseUrl}/?${query.toString()}`);
    }
  } catch (err) {
    return redirect(`${baseUrl}/?social_status=error&msg=OauthFailed`);
  }
}
