<?php
declare(strict_types=1);

namespace PdOidc\Access;

enum Role: string
{
    case Read = 'read';
    case Write = 'write';
    case Admin = 'admin';
}
