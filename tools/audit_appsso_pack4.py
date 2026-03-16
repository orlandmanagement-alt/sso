from pathlib import Path
import json

root = Path(".")
files = [
    "functions/api/auth/verify_phone.js",
    "functions/api/auth/exchange.js",
    "functions/api/auth/refresh.js",
    "functions/api/auth/verify_otp.js",
]

checks = {}
for f in files:
    p = root / f
    checks[f] = {
        "exists": p.exists(),
        "size_ok": False
    }
    if p.exists():
        checks[f]["size_ok"] = len(p.read_text().strip()) > 40

(root / "tools/appsso_pack4_audit.json").write_text(json.dumps(checks, indent=2))

lines = []
lines.append("[SUMMARY]")
for k, v in checks.items():
    lines.append(f"{k}.exists: {v['exists']}")
    lines.append(f"{k}.size_ok: {v['size_ok']}")
    lines.append("")
lines.append("[NEXT_SMOKE_TEST]")
lines.append("1. POST /functions/api/auth/request_otp")
lines.append("2. POST /functions/api/auth/verify_otp")
lines.append("3. GET  /functions/api/auth/me")
lines.append("4. GET  /functions/api/auth/sessions")
lines.append("5. POST /functions/api/auth/revoke_session")
lines.append("6. POST /functions/api/auth/step_up_request")
lines.append("7. POST /functions/api/auth/step_up_verify")
lines.append("8. POST /functions/api/auth/verify_phone")
lines.append("9. POST /functions/api/auth/exchange")
lines.append("10. POST /functions/api/auth/logout")
lines.append("11. POST /functions/api/auth/logout_all")
(root / "tools/appsso_pack4_audit.txt").write_text("\n".join(lines))
print("[OK] wrote tools/appsso_pack4_audit.txt")
