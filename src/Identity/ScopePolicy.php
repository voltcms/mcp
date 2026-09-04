<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Identity;

use VoltCMS\MCP\Contracts\ScopePolicyInterface;

/**
 * Roles to scopes, as a table the deployment writes down.
 *
 * This is the last thing standing between "the client asked for `mcp:write`" and "the token says
 * `mcp:write`", and it is consulted twice — once before the user is asked to consent, so nobody is
 * offered something they cannot grant, and once on every token validation, so a demotion takes
 * effect before the token expires rather than an hour later.
 *
 * Roles are group names from `voltcms/useraccess`, matched exactly and case-sensitively. A role
 * that is not in the table grants nothing; an unknown role is not an error, because groups are the
 * application's to name and most of them will have nothing to do with MCP.
 *
 * Immutable.
 */
final class ScopePolicy implements ScopePolicyInterface
{
    public const EXCEPTION_SCOPE_MALFORMED = 9001;

    /** @var array<string, list<string>> */
    private readonly array $byRole;

    /** @var list<string> */
    private readonly array $forEveryone;

    /**
     * @param array<string, list<string>> $byRole      Role name => the scopes it grants.
     * @param list<string>                $forEveryone Scopes any authenticated user may grant.
     *
     * @throws \InvalidArgumentException if a scope is not a non-empty string.
     */
    public function __construct(array $byRole, array $forEveryone = [])
    {
        $validated = [];

        foreach ($byRole as $role => $scopes) {
            $validated[(string) $role] = self::validate($scopes);
        }

        $this->byRole      = $validated;
        $this->forEveryone = self::validate($forEveryone);
    }

    /**
     * The single-user case, stated in one line: everyone who can log in can grant everything.
     *
     * Correct for the deployment this package targets — a personal site whose only account is the
     * owner's — and wrong the moment there is a second account, which is why it has to be asked
     * for by name rather than being the default.
     *
     * @param list<string> $scopes
     */
    public static function everyoneMay(array $scopes): self
    {
        return new self([], $scopes);
    }

    /**
     * @return list<string>
     */
    public function grantableFor(Identity $identity): array
    {
        $granted = $this->forEveryone;

        foreach ($identity->roles as $role) {
            foreach ($this->byRole[$role] ?? [] as $scope) {
                if (!in_array($scope, $granted, true)) {
                    $granted[] = $scope;
                }
            }
        }

        return array_values($granted);
    }

    /**
     * @param list<string> $scopes
     *
     * @return list<string>
     */
    private static function validate(array $scopes): array
    {
        $validated = [];

        foreach ($scopes as $scope) {
            if (!is_string($scope) || trim($scope) === '') {
                throw new \InvalidArgumentException(
                    'Scope names must be non-empty strings.',
                    self::EXCEPTION_SCOPE_MALFORMED,
                );
            }

            if (!in_array($scope, $validated, true)) {
                $validated[] = $scope;
            }
        }

        return $validated;
    }
}
