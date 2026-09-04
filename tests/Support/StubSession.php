<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Tests\Support;

use VoltCMS\MCP\Contracts\SessionInterface;

/**
 * A session with no session in it. `UserAccessSession` starts a PHP session on first use, which is
 * a `Set-Cookie` header and therefore the one thing the rest of the package promises never to do —
 * so identity tests say who is logged in directly instead.
 */
final class StubSession implements SessionInterface
{
    public function __construct(private ?string $identifier = null)
    {
    }

    public function currentUserIdentifier(): ?string
    {
        return $this->identifier;
    }

    public function logIn(?string $identifier): void
    {
        $this->identifier = $identifier;
    }
}
