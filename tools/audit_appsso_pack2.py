from pathlib import Path
import json

root = Path(".")
files = [
    "functions/api/auth/request_otp.js",
    "functions/api/auth/me.js",
    "functions/api/auth/logout.js",
    "functions/api/auth/logout_all.js",
    "functions/api/auth/step_up_request.js",
    "functions/api/auth/step_up_verify.js",
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

(root / "tools/appsso_pack2_audit.json").write_text(json.dumps(checks, indent=2))

lines = []
lines.append("[SUMMARY]")
for k, v in checks.items():
    lines.append(f"{k}.exists: {v['exists']}")
    lines.append(f"{k}.size_ok: {v['size_ok']}")
    lines.append("")
(root / "tools/appsso_pack2_audit.txt").write_text("\n".join(lines))
print("[OK] wrote tools/appsso_pack2_audit.txt")
