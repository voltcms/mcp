<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Contracts;

use VoltCMS\MCP\Identity\Identity;

/**
 * The map from what a user is to what a token may carry.
 *
 * This is the only thing standing between "the client asked for `mcp:write`" and "the token says
 * `mcp:write`". It is consulted twice: once at the authorize endpoint, which narrows the request
 * to what this returns before anyone is asked to consent, and once on every token validation,
 * where a scope the user's roles no longer support invalidates a live token. Both are needed —
 * the first so a user is never asked to approve something they cannot grant, the second so a
 * demotion takes effect before the token expires.
 */
interface ScopePolicyInterface
{
    /**
     * Every scope this identity may grant, in the order they should be offered.
     *
     * An empty list means the account can grant nothing; the authorize endpoint refuses rather
     * than issuing a token with no scopes.
     *
     * @return list<string>
     */
    public function grantableFor(Identity $identity): array;
}
