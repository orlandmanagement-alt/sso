from pathlib import Path
import json

root = Path(".")

api_files = [
    "functions/api/auth/request_otp.js",
    "functions/api/auth/verify_otp.js",
    "functions/api/auth/me.js",
    "functions/api/auth/refresh.js",
    "functions/api/auth/logout.js",
    "functions/api/auth/logout_all.js",
    "functions/api/auth/sessions.js",
    "functions/api/auth/revoke_session.js",
    "functions/api/auth/resolve_redirect.js",
    "functions/api/auth/step_up_request.js",
    "functions/api/auth/step_up_verify.js",
    "functions/api/auth/verify_phone.js",
    "functions/api/auth/exchange.js",
]

helper_files = [
    "functions/_core/auth.js",
    "functions/_core/otp_providers.js",
    "functions/api/auth/_helper/auth_queries.js",
    "functions/api/auth/_helper/auth_service.js",
    "functions/api/auth/_helper/auth_validator.js",
    "functions/api/auth/_helper/auth_session.js",
    "functions/api/auth/_helper/auth_stepup.js",
    "functions/api/auth/_helper/auth_redirect.js",
]

migration_files = [
    "database/migrations/012_sso_hardening.sql",
    "database/migrations/013_sso_otp_providers.sql",
    "database/migrations/014_sso_stepup_hardening.sql",
]

api_results = [{"file": f, "exists": (root / f).exists()} for f in api_files]
helper_results = [{"file": f, "exists": (root / f).exists()} for f in helper_files]
migration_results = [{"file": f, "exists": (root / f).exists()} for f in migration_files]

report = {
    "api_ok_count": sum(1 for x in api_results if x["exists"]),
    "api_total": len(api_results),
    "helper_ok_count": sum(1 for x in helper_results if x["exists"]),
    "helper_total": len(helper_results),
    "migration_ok_count": sum(1 for x in migration_results if x["exists"]),
    "migration_total": len(migration_results),
    "api_results": api_results,
    "helper_results": helper_results,
    "migration_results": migration_results,
}

(root / "tools/appsso_final_smoke_test.json").write_text(json.dumps(report, indent=2))

lines = []
lines.append("[SUMMARY]")
lines.append(f"api_ok_count: {report['api_ok_count']}")
lines.append(f"api_total: {report['api_total']}")
lines.append(f"helper_ok_count: {report['helper_ok_count']}")
lines.append(f"helper_total: {report['helper_total']}")
lines.append(f"migration_ok_count: {report['migration_ok_count']}")
lines.append(f"migration_total: {report['migration_total']}")
lines.append("")

lines.append("[API_FILES]")
for x in api_results:
    lines.append(f"- {'OK' if x['exists'] else 'MISS'} | {x['file']}")
lines.append("")

lines.append("[HELPER_FILES]")
for x in helper_results:
    lines.append(f"- {'OK' if x['exists'] else 'MISS'} | {x['file']}")
lines.append("")

lines.append("[MIGRATION_FILES]")
for x in migration_results:
    lines.append(f"- {'OK' if x['exists'] else 'MISS'} | {x['file']}")
lines.append("")

lines.append("[MANUAL_FLOW]")
lines.append("1. POST /functions/api/auth/request_otp")
lines.append("2. POST /functions/api/auth/verify_otp")
lines.append("3. GET  /functions/api/auth/me")
lines.append("4. GET  /functions/api/auth/sessions")
lines.append("5. POST /functions/api/auth/revoke_session")
lines.append("6. POST /functions/api/auth/step_up_request")
lines.append("7. POST /functions/api/auth/step_up_verify")
lines.append("8. POST /functions/api/auth/verify_phone")
lines.append("9. POST /functions/api/auth/exchange")
lines.append("10. GET /functions/api/auth/resolve_redirect")
lines.append("11. POST /functions/api/auth/logout")
lines.append("12. POST /functions/api/auth/logout_all")

(root / "tools/appsso_final_smoke_test.txt").write_text("\n".join(lines))
print("[OK] wrote tools/appsso_final_smoke_test.txt")
print("[OK] wrote tools/appsso_final_smoke_test.json")
