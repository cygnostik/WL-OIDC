<nav class="form-links" aria-label="Account"><a href="/account">Your account</a></nav>
<h1>User manager</h1>
<?php require __DIR__ . '/feedback.php'; ?>
<?php $roles = ['read' => 'Read', 'write' => 'Write', 'admin' => 'Admin']; ?>
<?php $pageUrl = static fn(int $users, int $requests): string => '/admin?' . http_build_query(['q' => $data['search'], 'page' => $users, 'requests' => $requests]); ?>
<section>
    <h2>Signup requests</h2>
    <?php if ($data['requests'] === []): ?><p>No pending requests on this page.</p><?php endif; ?>
    <?php foreach (array_slice($data['requests'], 0, 30) as $signup): ?>
        <article class="review">
            <h3><?= $escape($signup['first_name'] . ' ' . $signup['last_name']) ?></h3>
            <p><?= $escape($signup['email']) ?></p>
            <p class="signup-note"><?= $escape($signup['note']) ?></p>
            <form action="/admin" method="post">
                <input type="hidden" name="csrf" value="<?= $escape($csrf) ?>">
                <input type="hidden" name="id" value="<?= $escape($signup['id']) ?>">
                <div class="fields">
                    <label>Assign to service
                        <select name="service">
                            <option value="">No service yet</option>
                            <?php foreach ($data['services'] as $service): ?>
                                <?php if ($service['enabled']): ?>
                                    <option value="<?= $escape($service['client_id']) ?>"><?= $escape($service['display_name']) ?></option>
                                <?php endif; ?>
                            <?php endforeach; ?>
                        </select>
                    </label>
                    <label>Service role
                        <select name="assigned_role">
                            <?php foreach ($roles as $value => $label): ?>
                                <option value="<?= $escape($value) ?>"><?= $escape($label) ?></option>
                            <?php endforeach; ?>
                        </select>
                    </label>
                </div>
                <div class="actions">
                    <button type="submit" name="decision" value="approve">Approve</button>
                    <button type="submit" name="decision" value="decline" class="secondary">Decline</button>
                </div>
            </form>
        </article>
    <?php endforeach; ?>
    <nav class="form-links" aria-label="Signup pages">
        <?php if ($data['requestPage'] > 1): ?><a href="<?= $escape($pageUrl($data['page'], $data['requestPage'] - 1)) ?>">Previous requests</a><?php endif; ?>
        <?php if (count($data['requests']) > 30): ?><a href="<?= $escape($pageUrl($data['page'], $data['requestPage'] + 1)) ?>">Next requests</a><?php endif; ?>
    </nav>
</section>
<?php if ($data['services'] !== []): ?>
    <section>
        <h2>Service login duration</h2>
        <p>Set the longest a supported service can keep a login active. Enter 0 for a 15-minute session.</p>
        <?php foreach ($data['services'] as $service): ?>
            <form class="search" action="/admin" method="post">
                <input type="hidden" name="csrf" value="<?= $escape($csrf) ?>">
                <input type="hidden" name="action" value="set_login_days">
                <input type="hidden" name="service" value="<?= $escape($service['client_id']) ?>">
                <label><?= $escape($service['display_name']) ?> (days)
                    <input type="number" name="login_days" min="0" max="<?= \PdOidc\Oidc\RefreshSessions::MAX_DAYS ?>" value="<?= (int) $service['login_days'] ?>" required>
                </label>
                <button type="submit" class="secondary">Save duration</button>
            </form>
        <?php endforeach; ?>
    </section>
<?php endif; ?>
<section>
    <h2>Users</h2>
    <form method="get" action="/admin" class="search">
        <label>Find by name or email <input type="search" name="q" maxlength="200" value="<?= $escape($data['search']) ?>"></label>
        <button type="submit" class="secondary">Search</button>
    </form>
    <?php if ($data['users'] === []): ?><p>No matching users on this page.</p><?php endif; ?>
    <?php if ($data['users'] !== []): ?>
        <ul class="user-list">
            <?php foreach (array_slice($data['users'], 0, 30) as $user): ?>
                <li>
                    <a href="/admin/user?subject=<?= $escape($user['subject']) ?>"><?= $escape($user['display_name']) ?></a>
                    <span><?= $escape($user['email']) ?></span>
                    <span><?= !$user['enabled'] ? 'Disabled' : (!$user['email_verified'] ? 'Awaiting setup' : 'Active') ?> · <?= $escape($roles[$user['default_role']]) ?> · <?= $user['allow_all_services'] ? 'All services' : 'Selected only' ?></span>
                </li>
            <?php endforeach; ?>
        </ul>
    <?php endif; ?>
    <nav class="form-links" aria-label="User pages">
        <?php if ($data['page'] > 1): ?><a href="<?= $escape($pageUrl($data['page'] - 1, $data['requestPage'])) ?>">Previous users</a><?php endif; ?>
        <?php if (count($data['users']) > 30): ?><a href="<?= $escape($pageUrl($data['page'] + 1, $data['requestPage'])) ?>">Next users</a><?php endif; ?>
    </nav>
</section>
