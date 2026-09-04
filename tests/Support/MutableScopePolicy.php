<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Tests\Support;

use VoltCMS\MCP\Contracts\ScopePolicyInterface;
use VoltCMS\MCP\Identity\Identity;

/**
 * A policy whose answer can change between the authorization and the refresh, which is the whole
 * scenario worth testing: roles are edited in the application long after a client stopped asking
 * permission, and the refresh flow has no consent screen to notice.
 */
final class MutableScopePolicy implements ScopePolicyInterface
{
    /**
     * @param list<string> $scopes
     */
    public function __construct(public array $scopes)
    {
    }

    public function grantableFor(Identity $identity): array
    {
        return $this->scopes;
    }
}
