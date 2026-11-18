# Distribution defaults

Set the issuer and theme through deployment environment variables. For a branded image, you can add a deployment-specific `defaults.php` here that returns an array with optional `issuer` and `theme` strings. PHP loads this file as trusted application code. Keep credentials, signing keys, and user data in deployment storage.
