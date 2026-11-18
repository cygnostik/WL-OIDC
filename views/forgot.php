<h1>Forgot password?</h1>
<?php require __DIR__ . '/feedback.php'; ?>
<?php if ($notice === ''): ?>
    <form action="/password/forgot" method="post">
        <input type="hidden" name="csrf" value="<?= $escape($csrf) ?>">
        <label>Email address <input type="email" name="email" autocomplete="email" maxlength="254" required></label>
        <button type="submit">Send reset link</button>
    </form>
<?php endif; ?>
<p><a href="/">Back to sign in</a></p>
