import { makeSessionCookie } from "../../../_lib/cookies.js";

// Helper Penentu URL Portal
function getPortalUrl(role) {
  return role === 'client' ? 'https://client.orlandmanagement.com' : 'https://talent.orlandmanagement.com';
}

export async function onRequestGet({ request, env, params }) {
  const provider = params.provider;
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const host = url.origin;
  
  if (!code) return Response.redirect(`${host}/?error=no_code`, 302);

  let socialEmail = "";
  let socialName = "";

  try {
    if (provider === "facebook") {
      const FB_APP_ID = "929223529699044";
      // PERHATIAN: Masukkan App Secret dari FB Developer (Pengaturan > Dasar) di Environment Variable CLoudflare Pages Anda
      const FB_SECRET = env.FB_APP_SECRET || "GANTI_DENGAN_APP_SECRET_ASLI_JIKA_TIDAK_PAKAI_ENV"; 
      const cb = `${host}/api/auth/callback/facebook`;
      
      // Tukar Code dengan Access Token
      const tokenRes = await fetch(`https://graph.facebook.com/v18.0/oauth/access_token?client_id=${FB_APP_ID}&redirect_uri=${cb}&client_secret=${FB_SECRET}&code=${code}`);
      const tokenData = await tokenRes.json();
      if (!tokenData.access_token) throw new Error("FB Token Gagal");

      // Ambil Profil
      const profileRes = await fetch(`https://graph.facebook.com/me?fields=id,name,email&access_token=${tokenData.access_token}`);
      const profileData = await profileRes.json();
      socialEmail = profileData.email || `fb_${profileData.id}@orlandmanagement.com`;
      socialName = profileData.name || "Facebook User";
    } 
    else if (provider === "tiktok") {
      const TIKTOK_KEY = "awkzny81taard1oq";
      const TIKTOK_SECRET = "Rc84LwOcSuv4bNEjboyjLqVI2L5DyyT2";
      const cb = `${host}/api/auth/callback/tiktok`;

      // Tukar Code
      const tokenBody = new URLSearchParams({ client_key: TIKTOK_KEY, client_secret: TIKTOK_SECRET, code: code, grant_type: "authorization_code", redirect_uri: cb });
      const tokenRes = await fetch('https://open.tiktokapis.com/v2/oauth/token/', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: tokenBody });
      const tokenData = await tokenRes.json();
      if (!tokenData.access_token) throw new Error("TikTok Token Gagal");

      // Ambil Profil (TikTok jarang kasih email, kita buat dummy email)
      const profileRes = await fetch('https://open.tiktokapis.com/v2/user/info/?fields=open_id,display_name', { headers: { 'Authorization': `Bearer ${tokenData.access_token}` } });
      const profileData = await profileRes.json();
      const open_id = profileData?.data?.user?.open_id || crypto.randomUUID();
      socialEmail = `tiktok_${open_id}@orlandmanagement.com`;
      socialName = profileData?.data?.user?.display_name || "TikTok User";
    }

    // === LOGIKA DATABASE ===
    const now = Math.floor(Date.now() / 1000);
    const user = await env.DB.prepare("SELECT * FROM users WHERE email=?").bind(socialEmail).first();

    if (user) {
      // USER LAMA -> Buat Sesi & Arahkan ke Portal
      const sid = crypto.randomUUID();
      await env.DB.prepare("INSERT INTO sessions (id, user_id, role, created_at, expires_at) VALUES (?,?,?,?,?)").bind(sid, user.id, user.role, now, now + 604800).run();
      
      return new Response(null, {
        status: 302,
        headers: { 'Location': getPortalUrl(user.role), 'Set-Cookie': makeSessionCookie(sid).headers['Set-Cookie'] }
      });
    } else {
      // USER BARU -> Lempar ke UI Lengkapi Profil dengan parameter URL
      const tempToken = btoa(JSON.stringify({ email: socialEmail, name: socialName }));
      const redirectParams = new URLSearchParams({
        new_social: "true", temp_token: tempToken, name: socialName, email: socialEmail, provider: provider
      });
      return Response.redirect(`${host}/?${redirectParams.toString()}`, 302);
    }

  } catch (err) {
    return Response.redirect(`${host}/?error=social_auth_failed`, 302);
  }
}
