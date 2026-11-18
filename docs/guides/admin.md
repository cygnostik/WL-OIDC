# Identity administrator guide

## Get access to the user manager

The deployment operator grants identity administration using `php bin/pd-oidc grant-identity-admin EMAIL` after verifying the account holder. Sign in and choose **User manager**, or open `/admin`. A service Admin manages privileges within that service. Identity administrators manage account approval and service assignments at the issuer.

For the first admin of a fresh installation, see [Deployment](deployment.md). The operator can remove identity administration using `php bin/pd-oidc revoke-identity-admin EMAIL`.

## Review a signup

1. Open **Signup requests** in the user manager.
2. Read the name, email and note. Verify unexpected requests using your normal process.
3. Optionally assign a service and role, then select **Approve**. Select **Decline** to close the request.

Approval starts the account in **Selected services only** mode and emails a 48-hour setup link. The user can sign in after opening the link and choosing a password. Leaving service assignment empty gives the user access to the issuer account page until you add a service grant.

## Manage a user

Search by name or email, then open the user. Set the account status, access mode and default role. Each service has independent access and role overrides.

| Setting | Effect |
| --- | --- |
| All registered services | Eligible services include future registrations. |
| Selected services only | The user needs an explicit Allow per service. |
| Allow or Deny | The service-specific setting takes precedence over the access mode. |
| Inherit role | Use the account's default Read, Write or Admin role. |
| Operator-only service | Entry also requires the effective Admin service role. |
| Disabled account or service | The issuer denies new access. Disabling an account also invalidates its issuer sessions. |

For example, give someone selected access, grant **Allow** on a members service and leave the role at Read. An operator-only dashboard also needs a service Administrator role. A role override by itself leaves the access decision unchanged.

Disabling a user or changing their service access affects new grants and the issuer's UserInfo endpoint. A project can continue honoring a previously issued ID token until its expiry. Current ID tokens last 15 minutes. Each project manages its own session and is responsible for reauthorization.

The user manager protects identity administrator accounts from web disablement. A deployment operator can revoke that authority first when necessary. Approval, decline and user edits are recorded in `pd_identity_audit` for operator review.

## Help with setup and recovery

The user's **Forgot password?** flow sends a new link to their email. It resends setup instructions for an approved account awaiting verification. For missing mail, check that the user is eligible, the mail worker is running, the SMTP credentials are current and the message is in the recipient's inbox or spam folder. Inspect mail-worker logs for delivery failures and the queue for expired or retrying entries. Each link is single-use.
