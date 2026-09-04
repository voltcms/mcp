<?php

declare(strict_types=1);

namespace VoltCMS\MCP\OAuth\Entities;

use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\UserEntityInterface;

/**
 * The resource owner, reduced to the only thing league/oauth2-server asks for: an identifier
 * that ends up as the token's `sub` claim.
 *
 * The real user record lives in voltcms/useraccess and is reached through
 * UserAccessIdentityProvider; this is the value object league passes around.
 */
final class User implements UserEntityInterface
{
    use EntityTrait;

    public function __construct(string $identifier)
    {
        $this->identifier = $identifier;
    }
}
