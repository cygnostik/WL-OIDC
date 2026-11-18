# Deployment and operations

## Requirements

Use PHP 8.4 or newer with PDO MySQL, OpenSSL, Sodium, mbstring and Argon2id password hashing. Install dependencies from the committed Composer lockfile. Use a dedicated MySQL or MariaDB database with InnoDB. The integration suite exercises MySQL and MariaDB-compatible SQL. Configure an SMTP mailbox for setup and recovery messages.

| Setting | Purpose |
| --- | --- |
| `PD_DB_DSN` | Example `mysql:host=127.0.0.1;dbname=oidc;charset=utf8mb4` |
| `PD_DB_USER`, `PD_DB_PASSWORD` | Dedicated database credential |
| `PD_OIDC_ISSUER` | Exact public root HTTPS URL, without a trailing slash |
| `PD_OIDC_PRIVATE_KEY_FILE` | Readable private RSA PEM file, 2048 bits or more |
| `PD_OIDC_ENCRYPTION_KEY` | Base64 encoding of 32 random bytes |
| `PD_THEME` | Theme directory slug. The generic distribution defaults to `standard`. |
| `PD_TRUSTED_PROXY_IPS` | Optional exact addresses of proxies that append or replace `X-Forwarded-For` with their connecting peer |
| `PD_MAIL_FROM` | Sender address and SMTP username |
| `PD_SMTP_HOST`, `PD_SMTP_PORT` | Verified SMTP server, port 465 for TLS or 587 for STARTTLS |
| `PD_SMTP_PASSWORD` | Mailbox credential |

Keep database credentials, SMTP credentials and keys outside the document root and repository. Generate a key with `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out signing.pem` under a restrictive umask. Generate the encryption key with `openssl rand -base64 32`. Keep the public issuer, subject identifiers and key files stable across releases.

## Initialize and register a client

```sh
composer install --no-dev --no-interaction
php bin/pd-oidc init
php bin/pd-oidc create-user admin@example.test "Identity admin" read --verified
php bin/pd-oidc grant-identity-admin admin@example.test
php bin/pd-oidc register-client example-client "Example service" members https://app.example.test/auth/callback
```

Use a real address you have verified for the first admin. The CLI prompts for the password. To register an operator-only client, replace `members` with `operators`. Repeat `register-client` for the same ID to update its name, complete callback list and admission requirement. Account overrides and disabled state carry forward. Disable a client with `php bin/pd-oidc set-service-enabled CLIENT_ID off`.

Clients discover endpoints at `ISSUER/.well-known/openid-configuration`. Configure a public client with Authorization Code and S256 PKCE, the exact registered HTTPS callback, and scopes `openid profile email` as needed. Validate state, nonce if supplied, RS256 signature, issuer, audience and expiry. Use `(issuer, sub)` as the stable account identifier. The `pd_role` claim is scoped to the requesting client.

Clients supporting renewal may use `grant_type=refresh_token` when an identity administrator enables a longer [service login duration](admin.md#set-how-long-a-service-login-lasts). Replace the stored refresh token after each exchange and coalesce concurrent requests for the same session. Reusing a rotated token revokes the renewal session. Send the most recent refresh token to the advertised revocation endpoint on logout. Keep tokens in secure storage and verify each new ID token. Public clients may supply `client_id` on refresh, which must match the original grant.

## Run the issuer

For development, set `PD_OIDC_ISSUER=http://127.0.0.1:3000` and run `php -S 127.0.0.1:3000 -t public`. HTTP issuers are limited to loopback. For a TLS deployment, serve the Apache image or another PHP runtime with only `public/` as document root. The image listens on port 3000.

```sh
docker build -t wl-oidc .
docker run --rm --env-file /private/issuer.env \
  --mount type=bind,source=/private/signing.pem,target=/run/secrets/signing.pem,readonly \
  -p 127.0.0.1:3000:3000 wl-oidc
```

Set `PD_OIDC_PRIVATE_KEY_FILE=/run/secrets/signing.pem` in that environment. Provide a database DSN reachable from the container. Initialize the database with the same image and environment before exposing the issuer. Configure the proxy to redirect HTTP to HTTPS, preserve method, query and body, and reach the private listener. Check the public sign-in, discovery, JWKS and callback before handing the issuer to a client.

Run `php bin/pd-oidc send-account-mail` regularly as a worker with both runtime configuration and SMTP settings. It sends due messages and backs off on failure. Run `php bin/pd-oidc prune` regularly to clear expired OIDC grants and refresh sessions. Keep SMTP credentials in the mail worker environment. Rotate and review logs without recording credentials or account-link codes.

## Update, back up and recover

Back up the dedicated database, keys, deployment settings and custom themes to restricted storage. Test restore in isolation. Before a new release, exercise the [maintenance checks](maintenance.md) against a disposable database. Apply additive database migrations via `php bin/pd-oidc init` before switching the runtime and restarting the mail worker. Keep the previous release available and verify discovery, sign-in, user management and mail delivery after cutover.

If an application rollback is needed, switch back to the previous build and retain the database changes when the release notes say they are backward compatible. Restore data from a validated backup only when needed. Coordinate signing-key changes with clients and token expiration. The current implementation serves one signing key, so key replacement needs a planned reauthentication window.
