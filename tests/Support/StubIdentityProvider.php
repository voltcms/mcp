<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Tests\Support;

use VoltCMS\MCP\Contracts\IdentityProviderInterface;
use VoltCMS\MCP\Http\Request;
use VoltCMS\MCP\Identity\Identity;

/**
 * An identity provider with no session and no store behind it, so an endpoint test can say "this
 * visitor is logged in" or "this one is not" in one line. `UserAccessIdentityProvider` is tested
 * against real user and group directories separately.
 */
final class StubIdentityProvider implements IdentityProviderInterface
{
    private ?Identity $current;

    /** @var array<string, Identity> */
    private array $known = [];

    public function __construct(?Identity $current = null)
    {
        $this->current = $current;

        if ($current !== null) {
            $this->known[$current->identifier] = $current;
        }
    }

    public function currentUser(Request $request): ?Identity
    {
        return $this->current;
    }

    public function findUser(string $identifier): ?Identity
    {
        return $this->known[$identifier] ?? null;
    }

    public function forget(string $identifier): void
    {
        unset($this->known[$identifier]);
    }
}
