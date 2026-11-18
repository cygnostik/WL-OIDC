<?php
declare(strict_types=1);

use PdOidc\Access\Role;
use PdOidc\Access\ServiceAccess;

require __DIR__ . '/../src/Access/Role.php';
require __DIR__ . '/../src/Access/ServiceAccess.php';

$cases = [
    'inherited read' => [[true, true, true, Role::Read], Role::Read],
    'selected only' => [[true, true, false, Role::Read, null, Role::Admin], null],
    'allow and override' => [[true, true, false, Role::Read, true, Role::Write], Role::Write],
    'explicit deny' => [[true, true, true, Role::Admin, false], null],
    'disabled user' => [[false, true, true, Role::Admin, true], null],
    'disabled service' => [[true, false, true, Role::Admin, true], null],
    'operator dashboard rejects read' => [[true, true, true, Role::Read, null, null, true], null],
    'operator dashboard rejects write' => [[true, true, true, Role::Write, null, null, true], null],
    'operator admitted' => [[true, true, false, Role::Read, true, Role::Admin, true], Role::Admin],
    'operator downgrade' => [[true, true, true, Role::Admin, null, Role::Read, true], null],
];
foreach ($cases as $name => [$arguments, $expected]) {
    if (ServiceAccess::effectiveRole(...$arguments) !== $expected) {
        throw new RuntimeException($name);
    }
}
echo count($cases), " service policy cases passed\n";
