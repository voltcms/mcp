<?php

declare(strict_types=1);

namespace VoltCMS\MCP\OAuth\Entities;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\Traits\ClientTrait;
use League\OAuth2\Server\Entities\Traits\EntityTrait;

/**
 * A registered OAuth client.
 *
 * `supportsGrantType()` is deliberately overridden rather than inherited. league's `ClientTrait`
 * returns `true` for every grant type, and `AbstractGrant::supportsGrantType()` reaches the
 * method through `method_exists()`, so a client registered for the authorization-code flow would
 * otherwise be free to use any other grant the server has enabled. The registered list is the
 * authority here.
 */
final class Client implements ClientEntityInterface
{
    use EntityTrait;
    use ClientTrait;

    public const GRANT_AUTHORIZATION_CODE = 'authorization_code';
    public const GRANT_REFRESH_TOKEN      = 'refresh_token';

    /** @var list<string> */
    private array $grantTypes;

    /**
     * @param string|list<string> $redirectUri
     * @param list<string>        $grantTypes
     */
    public function __construct(
        string $identifier,
        string $name,
        string|array $redirectUri,
        bool $isConfidential = false,
        array $grantTypes = [self::GRANT_AUTHORIZATION_CODE, self::GRANT_REFRESH_TOKEN],
    ) {
        $this->identifier     = $identifier;
        $this->name           = $name;
        $this->redirectUri    = $redirectUri;
        $this->isConfidential = $isConfidential;
        $this->grantTypes     = array_values($grantTypes);
    }

    public function supportsGrantType(string $grantType): bool
    {
        return in_array($grantType, $this->grantTypes, true);
    }

    /**
     * @return list<string>
     */
    public function grantTypes(): array
    {
        return $this->grantTypes;
    }
}
