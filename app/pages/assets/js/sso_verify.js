document.getElementById("verifyForm").addEventListener("submit", async (e) => {
  e.preventDefault();

  const otp = qs("otp").value.trim();
  const identifier = localStorage.getItem("sso_identifier") || "";

  if(!identifier){
    showMsg("Missing identifier, please login again");
    return;
  }

  if(!otp){
    showMsg("OTP required");
    return;
  }

  showMsg("Verifying OTP...");

  try{
    const res = await fetch(`${API_BASE}/auth/verify_otp`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ identifier, otp }),
      credentials: "include"
    });

    const data = await res.json();

    if(data.status === "ok"){
      showMsg("Login success");
      const nextUrl = await resolveRedirect();
      window.location.href = nextUrl;
      return;
    }

    showMsg("Failed: " + JSON.stringify(data));
  }catch(err){
    showMsg("Verify failed: " + String(err?.message || err));
  }
});

async function resolveRedirect(){
  try{
    const res = await fetch(`${API_BASE}/auth/resolve_redirect`, {
      credentials: "include"
    });
    const data = await res.json();
    return data?.data?.redirect_url || "/";
  }catch{
    return "/";
  }
}
