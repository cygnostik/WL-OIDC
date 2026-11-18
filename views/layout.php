<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title><?= $escape($brand['name']) ?></title>
    <link rel="stylesheet" href="/assets/tokens.css">
    <link rel="stylesheet" href="<?= $assetPath ?>/theme.css">
    <link rel="stylesheet" href="/assets/layout.css">
</head>
<body>
    <main<?= str_starts_with($view, 'admin') ? ' class="wide"' : '' ?>>
        <?php if (!empty($brand['logo'])): ?>
            <img class="brand-logo" src="<?= $assetPath ?>/<?= rawurlencode($brand['logo']) ?>" alt="">
        <?php endif; ?>
        <?php require __DIR__ . '/' . $view . '.php'; ?>
    </main>
</body>
</html>
