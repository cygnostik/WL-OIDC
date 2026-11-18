<h1><?= $data['purpose'] === 'activate' ? 'Set your password' : 'Reset your password' ?></h1>
<?php require __DIR__ . '/feedback.php'; ?>
<?php if ($data['purpose'] !== null): ?>
    <p>Use at least 15 characters.</p>
    <form action="/password/reset" method="post">
        <input type="hidden" name="csrf" value="<?= $escape($csrf) ?>">
        <input type="hidden" name="action" value="save">
        <label>New password <input type="password" name="password" autocomplete="new-password" minlength="15" required></label>
        <label>Confirm new password <input type="password" name="confirm" autocomplete="new-password" minlength="15" required></label>
        <button type="submit">Save password</button>
    </form>
<?php endif; ?>
<form action="/password/reset" method="post" id="open-account-link"<?= $data['purpose'] === null ? '' : ' hidden' ?>>
    <input type="hidden" name="csrf" value="<?= $escape($csrf) ?>">
    <input type="hidden" name="action" value="open">
    <label>Code from your email <input name="code" maxlength="64" autocomplete="off" required></label>
    <button type="submit">Continue</button>
</form>
<script src="/assets/account-link.js" defer></script>
<?php if ($data['purpose'] === null): ?>
    <p><a href="/password/forgot">Request a new link</a></p>
<?php endif; ?>
<p><a href="/">Back to sign in</a></p>
