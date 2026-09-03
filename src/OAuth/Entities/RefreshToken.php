<?php

declare(strict_types=1);

namespace VoltCMS\MCP\OAuth\Entities;

use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\RefreshTokenTrait;

/**
 * A refresh token.
 *
 * Refresh tokens are the credential that actually matters for revocation: access tokens are
 * short-lived JWTs that are not checked against the store on every request, so killing the
 * refresh path is what ends a grant immediately. See SECURITY.md.
 */
final class RefreshToken implements RefreshTokenEntityInterface
{
    use EntityTrait;
    use RefreshTokenTrait;
}
