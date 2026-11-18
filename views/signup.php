<h1>Create account</h1>
<?php require __DIR__ . '/feedback.php'; ?>
<?php if ($notice === ''): ?>
    <form action="/create-account" method="post">
        <input type="hidden" name="csrf" value="<?= $escape($csrf) ?>">
        <label>First name <input name="first_name" autocomplete="given-name" maxlength="80" value="<?= $escape($data['first'] ?? '') ?>" required></label>
        <label>Last name <input name="last_name" autocomplete="family-name" maxlength="80" value="<?= $escape($data['last'] ?? '') ?>" required></label>
        <label>Email address <input type="email" name="email" autocomplete="email" maxlength="254" value="<?= $escape($data['enteredEmail'] ?? '') ?>" required></label>
        <label>
            Which system should the admin assign you to?
            <textarea name="note" rows="4" maxlength="1000" required><?= $escape($data['note'] ?? '') ?></textarea>
        </label>
        <button type="submit">Request account</button>
    </form>
<?php endif; ?>
<p><a href="/">Back to sign in</a></p>
