# fake-idp

A minimal OpenID Connect (OIDC) identity provider for **testing auth flows**. Based on
[xiaoyi-zhang_data/fake_idp](https://github.com/xiaoyi-zhang_data/fake_idp), with two changes:

- **`nonce` support** — the `nonce` from the authorization request is carried through the
  authorization code and embedded in the issued `id_token` (required by relying parties that
  pin the id_token `nonce` against a cookie, e.g. Databricks OIDC account SSO).
- **Env-driven config** — `ISSUER` and `PORT` are read from the environment so the same image
  runs anywhere without code edits.

> ⚠️ Testing only. Ships a hardcoded demo RSA signing key and a demo username/password. Do not
> use for anything real.

## Endpoints

`/.well-known/openid-configuration`, `/authorize`, `/login`, `/token`, `/userinfo`, `/jwks`.
Supports authorization-code, password (ROPC), client-credentials, and refresh-token grants.

## Configuration

| Env var | Default | Purpose |
|---|---|---|
| `FAKE_IDP_ISSUER` | `http://localhost:5000` | The issuer URL. **Must equal the public URL the IdP is served at** (the discovery doc derives `authorization_endpoint`/`token_endpoint`/`jwks_uri` from it, and the `id_token` `iss` claim uses it). |
| `PORT` | `5000` | Listen port. |

Default demo credentials live at the top of `app.py` (`ALLOWED_USER` / `ALLOWED_PASSWORD`).

## Run locally

```bash
pip install -r requirements.txt
FAKE_IDP_ISSUER=http://localhost:5000 python app.py
```

## Deploy (render.com)

A `render.yaml` blueprint is included. After the first deploy, set `FAKE_IDP_ISSUER` to the
service's public URL (e.g. `https://fake-idp-xxxx.onrender.com`) and redeploy so the discovery
document and tokens use the correct issuer.
