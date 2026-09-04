<?php

declare(strict_types=1);

namespace VoltCMS\MCP\OAuth\Entities;

use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\ScopeTrait;

/**
 * One OAuth scope, as league/oauth2-server wants to see it.
 *
 * Scopes are configuration, not stored records: the set this server is willing to grant comes
 * from Configuration, so there is nothing here to persist.
 */
final class Scope implements ScopeEntityInterface
{
    use EntityTrait;
    use ScopeTrait;

    public function __construct(string $identifier)
    {
        $this->identifier = $identifier;
    }
}
