<?php
declare(strict_types=1);

namespace PdOidc\Access;

final class ServiceAccess
{
    /** Evaluate current stored policy for a registered client. Null means deny. */
    public static function effectiveRole(
        bool $userEnabled,
        bool $serviceEnabled,
        bool $allowAllServices,
        Role $defaultRole,
        ?bool $accessOverride = null,
        ?Role $roleOverride = null,
        bool $requiresOperator = false,
    ): ?Role {
        if (!$userEnabled || !$serviceEnabled || !($accessOverride ?? $allowAllServices)) {
            return null;
        }

        $role = $roleOverride ?? $defaultRole;
        if ($requiresOperator && $role !== Role::Admin) {
            return null;
        }
        return $role;
    }
}
