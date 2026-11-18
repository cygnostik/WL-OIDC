<?php $user = $data['user']; ?>
<?php $roles = ['read' => 'Read', 'write' => 'Write', 'admin' => 'Admin']; ?>
<nav class="form-links" aria-label="User manager"><a href="/admin">User manager</a></nav>
<h1><?= $escape($user['display_name']) ?></h1>
<p><?= $escape($user['email']) ?> · <?= $user['email_verified'] ? 'Email verified' : 'Awaiting setup' ?><?= $user['identity_admin'] ? ' · Identity administrator' : '' ?></p>
<?php require __DIR__ . '/feedback.php'; ?>
<form method="post" action="/admin/user?subject=<?= $escape($user['subject']) ?>">
    <input type="hidden" name="csrf" value="<?= $escape($csrf) ?>">
    <div class="fields">
        <label>Account status
            <select name="status">
                <option value="enabled"<?= $user['enabled'] ? ' selected' : '' ?>>Enabled</option>
                <option value="disabled"<?= !$user['enabled'] ? ' selected' : '' ?>>Disabled</option>
            </select>
        </label>
        <label>Default service access
            <select name="access_mode">
                <option value="all"<?= $user['allow_all_services'] ? ' selected' : '' ?>>All registered services</option>
                <option value="selected"<?= !$user['allow_all_services'] ? ' selected' : '' ?>>Selected services only</option>
            </select>
        </label>
        <label>Default role
            <select name="default_role">
                <?php foreach ($roles as $value => $label): ?>
                    <option value="<?= $escape($value) ?>"<?= $user['default_role'] === $value ? ' selected' : '' ?>><?= $escape($label) ?></option>
                <?php endforeach; ?>
            </select>
        </label>
    </div>
    <?php foreach ($data['services'] as $service): ?>
        <?php $client = $service['client_id']; ?>
        <?php $access = $service['access_override'] === null ? 'inherit' : ($service['access_override'] ? 'allow' : 'deny'); ?>
        <fieldset>
            <legend><?= $escape($service['display_name']) ?><?= $service['enabled'] ? '' : ' (disabled)' ?></legend>
            <?php if ($service['requires_operator']): ?><p class="operator-note">Requires the Admin service role.</p><?php endif; ?>
            <div class="fields">
                <label>Access override
                    <select name="access[<?= $escape($client) ?>]">
                        <?php foreach (['inherit' => 'Inherit', 'allow' => 'Allow', 'deny' => 'Deny'] as $value => $label): ?>
                            <option value="<?= $escape($value) ?>"<?= $access === $value ? ' selected' : '' ?>><?= $escape($label) ?></option>
                        <?php endforeach; ?>
                    </select>
                </label>
                <label>Role override
                    <select name="service_role[<?= $escape($client) ?>]">
                        <?php foreach (['inherit' => 'Inherit'] + $roles as $value => $label): ?>
                            <option value="<?= $escape($value) ?>"<?= ($service['role_override'] ?? 'inherit') === $value ? ' selected' : '' ?>><?= $escape($label) ?></option>
                        <?php endforeach; ?>
                    </select>
                </label>
            </div>
        </fieldset>
    <?php endforeach; ?>
    <button type="submit">Save changes</button>
</form>
