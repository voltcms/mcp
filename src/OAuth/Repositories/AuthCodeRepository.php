<?php

declare(strict_types=1);

namespace VoltCMS\MCP\OAuth\Repositories;

use League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use VoltCMS\MCP\OAuth\Entities\AuthCode;

/**
 * Authorization codes.
 *
 * This store is what makes a code single-use: league revokes the code as it exchanges it and
 * asks `isAuthCodeRevoked()` before honouring the next attempt, so a replayed code is refused
 * here rather than in the grant. A store that forgot a code — or answered "not revoked" for one
 * it had never seen — would turn that guarantee off, which is why `isRevoked()` treats an absent
 * record as revoked.
 */
final class AuthCodeRepository extends FileDbRepository implements AuthCodeRepositoryInterface
{
    public const FIELD_CLIENT_ID    = 'client_id';
    public const FIELD_USER_ID      = 'user_id';
    public const FIELD_SCOPES       = 'scopes';
    public const FIELD_REDIRECT_URI = 'redirect_uri';

    protected function collection(): string
    {
        return 'auth_codes';
    }

    public function getNewAuthCode(): AuthCodeEntityInterface
    {
        return new AuthCode();
    }

    public function persistNewAuthCode(AuthCodeEntityInterface $authCodeEntity): void
    {
        $this->insert([
            self::FIELD_OAUTH_ID     => $authCodeEntity->getIdentifier(),
            self::FIELD_CLIENT_ID    => $authCodeEntity->getClient()->getIdentifier(),
            self::FIELD_USER_ID      => $authCodeEntity->getUserIdentifier() ?? '',
            self::FIELD_SCOPES       => array_values(array_map(
                static fn (ScopeEntityInterface $scope): string => $scope->getIdentifier(),
                $authCodeEntity->getScopes(),
            )),
            self::FIELD_REDIRECT_URI => $authCodeEntity->getRedirectUri() ?? '',
            self::FIELD_EXPIRES_AT   => $authCodeEntity->getExpiryDateTime()->getTimestamp(),
            self::FIELD_REVOKED      => false,
        ]);

        $this->audit('auth_code.issued', [
            'code_id'   => $authCodeEntity->getIdentifier(),
            'client_id' => $authCodeEntity->getClient()->getIdentifier(),
            'user_id'   => $authCodeEntity->getUserIdentifier(),
        ]);
    }

    public function revokeAuthCode(string $codeId): void
    {
        $this->revoke($codeId);
        $this->audit('auth_code.revoked', ['code_id' => $codeId]);
    }

    public function isAuthCodeRevoked(string $codeId): bool
    {
        return $this->isRevoked($codeId);
    }
}
