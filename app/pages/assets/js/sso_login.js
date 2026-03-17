document.getElementById("loginForm").addEventListener("submit", async (e) => {
  e.preventDefault();

  const identifier = qs("identifier").value.trim();
  if(!identifier){
    showMsg("Identifier required");
    return;
  }

  showMsg("Requesting OTP...");

  try{
    const res = await fetch(`${API_BASE}/auth/request_otp`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ identifier })
    });

    const data = await parseJsonSafe(res);

    if(res.ok && data.status === "ok"){
      localStorage.setItem("sso_identifier", identifier);
      showMsg("OTP sent");
      window.location.href = "./verify.html";
      return;
    }

    showMsg("Failed: " + JSON.stringify(data));
  }catch(err){
    showMsg("Request failed: " + String(err?.message || err));
  }
});
