<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Identity;

/**
 * The resource owner, as this package needs to see them: an identifier that becomes a token's
 * `sub`, a name a consent screen can show, and the roles a scope policy maps to scopes.
 *
 * Distinct from `OAuth\Entities\User`, which is the bare value league/oauth2-server passes
 * around, and from `VoltCMS\UserAccess\User`, which is the stored record. This is the shape the
 * seam between them speaks, so an application with a different user store fills
 * `IdentityProviderInterface` without either of the other two leaking into it.
 *
 * There is deliberately no `isActive()`: a deactivated account is not an inactive Identity, it is
 * the absence of one. `IdentityProviderInterface::findUser()` returns null for it, which is what
 * makes a token stop validating the moment the account is disabled.
 *
 * Immutable.
 */
final class Identity
{
    public const EXCEPTION_IDENTIFIER_REQUIRED = 5001;
    public const EXCEPTION_ROLE_MALFORMED      = 5002;

    public readonly string $identifier;
    public readonly string $displayName;

    /** @var list<string> */
    public readonly array $roles;

    /**
     * @param list<string> $roles
     *
     * @throws \InvalidArgumentException with one of the EXCEPTION_* codes above.
     */
    public function __construct(string $identifier, string $displayName = '', array $roles = [])
    {
        $identifier = trim($identifier);

        if ($identifier === '') {
            throw new \InvalidArgumentException(
                'An identity needs an identifier; it becomes the token subject.',
                self::EXCEPTION_IDENTIFIER_REQUIRED,
            );
        }

        $normalised = [];

        foreach ($roles as $role) {
            if (!is_string($role) || trim($role) === '') {
                throw new \InvalidArgumentException('Roles must be non-empty strings.', self::EXCEPTION_ROLE_MALFORMED);
            }

            if (!in_array(trim($role), $normalised, true)) {
                $normalised[] = trim($role);
            }
        }

        $this->identifier  = $identifier;
        $this->displayName = $displayName === '' ? $identifier : $displayName;
        $this->roles       = $normalised;
    }

    public function hasRole(string $role): bool
    {
        return in_array($role, $this->roles, true);
    }
}
