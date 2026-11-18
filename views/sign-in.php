<?php $account = $data['account']; ?>
<?php if ($account !== null): ?>
    <h1>Your <?= $escape($brand['name']) ?> account</h1>
    <p><?= $escape($account->name) ?><br><?= $escape($account->email) ?></p>
    <?php if ($data['admin']): ?>
        <p><a href="/admin">User manager</a></p>
    <?php endif; ?>
    <form action="/logout" method="post">
        <input type="hidden" name="csrf" value="<?= $escape($csrf) ?>">
        <button type="submit">Sign out</button>
    </form>
<?php else: ?>
    <h1>Sign in to <?= $escape($brand['name']) ?></h1>
    <?php require __DIR__ . '/feedback.php'; ?>
    <?php if ($data['message'] !== ''): ?>
        <p class="form-error" role="alert"><?= $escape($data['message']) ?></p>
    <?php endif; ?>
    <form action="/login" method="post">
        <input type="hidden" name="csrf" value="<?= $escape($csrf) ?>">
        <input type="hidden" name="flow" value="<?= $escape($data['flowId']) ?>">
        <label>
            Email
            <input type="email" name="email" autocomplete="username" maxlength="254" required>
        </label>
        <label>
            Password
            <input type="password" name="password" autocomplete="current-password" required>
        </label>
        <button type="submit">Sign in</button>
    </form>
    <nav aria-label="Account help" class="form-links">
        <a href="/create-account">Create account</a>
        <span aria-hidden="true">·</span>
        <a href="/password/forgot">Forgot password?</a>
    </nav>
<?php endif; ?>
