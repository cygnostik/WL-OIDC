<?php if ($notice !== ''): ?>
    <p role="status"><?= $escape($notice) ?></p>
<?php endif; ?>
<?php if (!empty($data['error'])): ?>
    <p class="form-error" role="alert"><?= $escape($data['error']) ?></p>
<?php endif; ?>
