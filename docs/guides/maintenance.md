# Core maintenance

## Boundaries and compatibility

| Area | Source | Stable interfaces |
| --- | --- | --- |
| Sign-in and forms | `src/Web/`, `views/` | Browser routes, account session invalidation, theme manifest |
| Protocol | `src/Oidc/` | Advertised discovery, exact callbacks, PKCE, issuer and subject, `pd_role` |
| Admission and lifecycle | `src/Access/`, `src/Pilot/` | Default policy, service overrides, separate identity administration, mail and audit states |
| Database and operations | `database/`, `bin/pd-oidc`, `deploy/apache.conf` | Additive migrations, stable CLI and `PD_*` environment |
| Branding | `public/assets/tokens.css`, `public/assets/themes/` | [Semantic theme contract v1](themes.md) |

Keep access checks in the application and provider. Themes supply presentation and approved brand assets. Preserve existing users, subjects, effective roles and password-reset semantics during updates. A migration that changes a stable interface needs explicit upgrade and rollback instructions.

## Verify a change

Run `php tests/service-access.php` for the policy matrix and run the integration suite against a new disposable database. The suite creates fixture clients and users, reads encrypted queued mail for testing and exercises authorization code exchange, client boundaries, admin approval, recovery, session invalidation and code replay.

```sh
composer install --no-interaction
composer validate --strict
composer audit --locked
PD_DB_DSN='mysql:host=127.0.0.1;dbname=oidc_test;charset=utf8mb4' \
  PD_DB_USER=local_test_user PD_DB_PASSWORD=local_test_password \
  python3 tests/run-integration.py
```

The integration runner refuses a database with tables. Drop and recreate the disposable database before a repeat. To verify mail delivery for a deployment, run the account flow with a controlled mailbox and use `PD_TEST_READ_CODE` to supply an executable that returns the 64-character code for the supplied purpose and applicant address.

## Extend and release

1. Add a small regression case for changes to authentication, authorization, account recovery, persistence or migrations.
2. For database changes, prefer additive, repeatable migrations and rehearse upgrade on a fixture running the prior release. Retain active issuer URLs, keys and account identifiers.
3. Test a stock skin and a custom skin. Flag updates to documented selectors or tokens and supply defaults for new roles.
4. Review dependency changes against the lockfile and verify a clean installation. Tag a reviewed snapshot and summarize changes, migration order, any compatibility impact and rollback options.

Report security issues through the repository's private vulnerability reporting channel.
