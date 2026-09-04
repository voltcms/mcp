<?php

declare(strict_types=1);

namespace VoltCMS\MCP\OAuth\Repositories;

use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use VoltCMS\MCP\Configuration;
use VoltCMS\MCP\OAuth\Entities\ResourceBoundAccessToken;
use VoltCMS\MCP\OAuth\Keys\KeyManager;
use VoltCMS\UserAccess\AuditLog;

/**
 * Issued access tokens.
 *
 * `getNewToken()` returns a ResourceBoundAccessToken rather than anything built on league's
 * `AccessTokenTrait` — that is the RFC 8707 tightening, and the entity's docblock says why.
 *
 * Access tokens are recorded here even though validating one does not read the store: the record
 * is what makes revocation and auditing possible at all, and what a future validator would
 * consult if instant revocation ever became worth the lookup.
 */
final class AccessTokenRepository extends FileDbRepository implements AccessTokenRepositoryInterface
{
    public const FIELD_CLIENT_ID = 'client_id';
    public const FIELD_USER_ID   = 'user_id';
    public const FIELD_SCOPES    = 'scopes';

    /**
     * The KeyManager is optional and used for one thing: stamping the signing key's `kid` into the
     * token header. Without it the token is still valid, but a consumer reading a JWKS that
     * publishes more than one key — which is what a rotation produces — has no way to tell which
     * one to verify with.
     */
    public function __construct(
        Configuration $configuration,
        ?AuditLog $auditLog = null,
        private readonly ?KeyManager $keys = null,
    ) {
        parent::__construct($configuration, $auditLog);
    }

    protected function collection(): string
    {
        return 'access_tokens';
    }

    /**
     * @param ScopeEntityInterface[] $scopes
     */
    public function getNewToken(
        ClientEntityInterface $clientEntity,
        array $scopes,
        string|null $userIdentifier = null,
    ): AccessTokenEntityInterface {
        $token = new ResourceBoundAccessToken(
            $this->configuration->issuer,
            $this->configuration->resource,
            $this->keys?->keyId(),
        );
        $token->setClient($clientEntity);

        foreach ($scopes as $scope) {
            $token->addScope($scope);
        }

        if ($userIdentifier !== null) {
            $token->setUserIdentifier($userIdentifier);
        }

        return $token;
    }

    public function persistNewAccessToken(AccessTokenEntityInterface $accessTokenEntity): void
    {
        $this->insert([
            self::FIELD_OAUTH_ID   => $accessTokenEntity->getIdentifier(),
            self::FIELD_CLIENT_ID  => $accessTokenEntity->getClient()->getIdentifier(),
            self::FIELD_USER_ID    => $accessTokenEntity->getUserIdentifier() ?? '',
            self::FIELD_SCOPES     => self::scopeIdentifiers($accessTokenEntity->getScopes()),
            self::FIELD_EXPIRES_AT => $accessTokenEntity->getExpiryDateTime()->getTimestamp(),
            self::FIELD_REVOKED    => false,
        ]);

        $this->audit('access_token.issued', [
            'token_id'  => $accessTokenEntity->getIdentifier(),
            'client_id' => $accessTokenEntity->getClient()->getIdentifier(),
            'user_id'   => $accessTokenEntity->getUserIdentifier(),
        ]);
    }

    public function revokeAccessToken(string $tokenId): void
    {
        $this->revoke($tokenId);
        $this->audit('access_token.revoked', ['token_id' => $tokenId]);
    }

    public function isAccessTokenRevoked(string $tokenId): bool
    {
        return $this->isRevoked($tokenId);
    }

    /**
     * @param ScopeEntityInterface[] $scopes
     *
     * @return list<string>
     */
    private static function scopeIdentifiers(array $scopes): array
    {
        return array_values(array_map(
            static fn (ScopeEntityInterface $scope): string => $scope->getIdentifier(),
            $scopes,
        ));
    }
}
