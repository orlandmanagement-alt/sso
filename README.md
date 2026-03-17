# appsso

SSO portal for Orland Management.

## Structure
- public/: static ui
- functions/: cloudflare pages functions
- database/migrations/: manual sql migrations

## Required env
- HASH_PEPPER
- COOKIE_DOMAIN=.orlandmanagement.com
- SESSION_TTL_MIN=720
- SSO_OTP_TTL_SEC=300
- SSO_DEFAULT_REDIRECT_TALENT=https://talent.orlandmanagement.com
- SSO_DEFAULT_REDIRECT_CLIENT=https://client.orlandmanagement.com
- SSO_DEFAULT_REDIRECT_ADMIN=https://dashboard.orlandmanagement.com
- SSO_DEFAULT_REDIRECT_DENIED=https://sso.orlandmanagement.com/access-denied.html
