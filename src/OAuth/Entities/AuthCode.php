<?php

declare(strict_types=1);

namespace VoltCMS\MCP\OAuth\Entities;

use League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use League\OAuth2\Server\Entities\Traits\AuthCodeTrait;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\TokenEntityTrait;

/**
 * An authorization code.
 *
 * league's traits carry everything: the code is created by the grant, handed to
 * AuthCodeRepository to persist, and read back only to answer "was this revoked?". Single-use
 * semantics are league's, and AuthCodeRepositoryTest covers them because we are the ones
 * promising them.
 */
final class AuthCode implements AuthCodeEntityInterface
{
    use EntityTrait;
    use TokenEntityTrait;
    use AuthCodeTrait;
}
