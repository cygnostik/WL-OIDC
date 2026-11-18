#!/usr/bin/env python3
"""Run the HTTP suite against an empty disposable MySQL or MariaDB database."""

import base64
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import tempfile
import time
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
DB_CHECK = """require 'vendor/autoload.php';
$db = PdOidc\\Pilot\\Accounts::fromEnvironment()->connection();
if ((int) $db->query('SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE()')->fetchColumn() !== 0) {
    fwrite(STDERR, "Integration tests require an empty, disposable database.\\n");
    exit(1);
}
"""
READ_CODE = """#!/usr/bin/env php
<?php
require 'vendor/autoload.php';
$db = PdOidc\\Pilot\\Accounts::fromEnvironment()->connection();
$query = $db->prepare('SELECT m.sealed_token FROM pd_account_mail m JOIN pd_account_links l USING (token_hash)
    JOIN pd_accounts a ON a.subject = l.subject WHERE l.purpose = ? AND a.email = ? ORDER BY l.expires_at DESC LIMIT 1');
$query->execute([$argv[1], $argv[2]]);
$sealed = $query->fetchColumn();
if (!$sealed) {
    exit(1);
}
$size = SODIUM_CRYPTO_SECRETBOX_NONCEBYTES;
echo sodium_crypto_secretbox_open(substr($sealed, $size), substr($sealed, 0, $size), PdOidc\\Pilot\\AccountLinks::mailKey());
"""


def main():
    os.chdir(ROOT)
    subprocess.run(["php", "-r", DB_CHECK], check=True)
    with tempfile.TemporaryDirectory(prefix="oidc-integration-") as work:
        runtime = Path(work)
        key = runtime / "signing.pem"
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(key)],
            stderr=subprocess.DEVNULL,
            check=True,
        )
        reader = runtime / "read-code"
        reader.write_text(READ_CODE)
        reader.chmod(0o700)
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        issuer = f"http://127.0.0.1:{port}"
        password = secrets.token_urlsafe(28)
        admin_email = "identity-admin@example.test"
        env = dict(
            os.environ,
            PD_OIDC_ISSUER=issuer,
            PD_OIDC_PRIVATE_KEY_FILE=str(key),
            PD_OIDC_ENCRYPTION_KEY=base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
            PD_TEST_ADMIN_EMAIL=admin_email,
            PD_TEST_ADMIN_PASSWORD=password,
            PD_TEST_APPLICANT="applicant@example.test",
            PD_TEST_READ_CODE=str(reader),
            PHP_CLI_SERVER_WORKERS="4",
        )

        def cli(*args, stdin=None):
            subprocess.run(["php", "bin/pd-oidc", *args], env=env, input=stdin, text=True, check=True)

        cli("init")
        cli("init")
        cli("register-client", "example-client", "Example service", "operators", "https://app.example.test/auth/callback")
        cli("register-client", "example-members", "Member service", "members", "https://members.example.test/auth/callback?source=account")
        cli("create-user", admin_email, "Identity admin", "admin", "--verified", stdin=password + "\n")
        cli("grant-identity-admin", admin_email)
        cli("create-user", "member@example.test", "Service member", "read", "--verified", stdin=password + "\n")

        with (runtime / "server.log").open("w+") as log:
            server = subprocess.Popen(
                ["php", "-d", f"session.save_path={runtime}", "-S", f"127.0.0.1:{port}", "-t", "public"],
                env=env, stdout=log, stderr=log, start_new_session=True,
            )
            try:
                for _ in range(80):
                    try:
                        with urllib.request.urlopen(issuer + "/", timeout=1) as response:
                            if response.status == 200:
                                break
                    except OSError:
                        time.sleep(0.05)
                else:
                    raise RuntimeError("The local issuer did not start.")
                subprocess.run(["node", "tests/account-management.mjs"], env=env, check=True)
                subprocess.run(["node", "tests/pilot-flow.mjs"], env=dict(
                    env, PD_TEST_EMAIL=admin_email, PD_TEST_PASSWORD=password, PD_TEST_POLICY_CHANGES="1",
                    PD_TEST_OTHER_CLIENT_ID="example-members",
                    PD_TEST_OTHER_CALLBACK="https://members.example.test/auth/callback?source=account",
                ), check=True)
                subprocess.run(["node", "tests/pilot-flow.mjs"], env=dict(
                    env, PD_TEST_EMAIL="member@example.test", PD_TEST_PASSWORD=password,
                    PD_TEST_CLIENT_ID="example-members", PD_TEST_CALLBACK="https://members.example.test/auth/callback?source=account",
                    PD_TEST_EXPECTED_ROLE="read", PD_TEST_POLICY_CHANGES="0",
                ), check=True)
            except Exception:
                log.seek(0)
                print(log.read()[-8000:])
                raise
            finally:
                if server.poll() is None:
                    os.killpg(server.pid, signal.SIGTERM)
                    server.wait(timeout=5)


if __name__ == "__main__":
    main()
