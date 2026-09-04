<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Tests\Support;

use VoltCMS\MCP\Contracts\ScopePolicyInterface;
use VoltCMS\MCP\Identity\Identity;

/**
 * Grants a fixed list regardless of who is asking, so a test about the authorize endpoint is about
 * the authorize endpoint. The real role-to-scope mapping is `ScopePolicy`, tested on its own.
 */
final class StubScopePolicy implements ScopePolicyInterface
{
    /** @var list<string> */
    private array $scopes;

    /**
     * @param list<string> $scopes
     */
    public function __construct(array $scopes)
    {
        $this->scopes = $scopes;
    }

    public function grantableFor(Identity $identity): array
    {
        return $this->scopes;
    }
}
