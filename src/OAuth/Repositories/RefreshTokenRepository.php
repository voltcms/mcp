<?php

declare(strict_types=1);

namespace VoltCMS\MCP\OAuth\Repositories;

use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use VoltCMS\MCP\OAuth\Entities\RefreshToken;

/**
 * Refresh tokens, and therefore the grant lifetime.
 *
 * league rotates on use: the presented token is revoked and a new one issued in the same
 * exchange. Both halves land in this store, so revoking a refresh token here ends the grant
 * immediately — the one revocation that is instant, and the reason SECURITY.md points at it
 * rather than at access-token revocation.
 */
final class RefreshTokenRepository extends FileDbRepository implements RefreshTokenRepositoryInterface
{
    public const FIELD_ACCESS_TOKEN_ID = 'access_token_id';
    public const FIELD_CLIENT_ID       = 'client_id';
    public const FIELD_USER_ID         = 'user_id';

    protected function collection(): string
    {
        return 'refresh_tokens';
    }

    public function getNewRefreshToken(): ?RefreshTokenEntityInterface
    {
        return new RefreshToken();
    }

    public function persistNewRefreshToken(RefreshTokenEntityInterface $refreshTokenEntity): void
    {
        $accessToken = $refreshTokenEntity->getAccessToken();

        $this->insert([
            self::FIELD_OAUTH_ID        => $refreshTokenEntity->getIdentifier(),
            self::FIELD_ACCESS_TOKEN_ID => $accessToken->getIdentifier(),
            self::FIELD_CLIENT_ID       => $accessToken->getClient()->getIdentifier(),
            self::FIELD_USER_ID         => $accessToken->getUserIdentifier() ?? '',
            self::FIELD_EXPIRES_AT      => $refreshTokenEntity->getExpiryDateTime()->getTimestamp(),
            self::FIELD_REVOKED         => false,
        ]);

        $this->audit('refresh_token.issued', [
            'token_id'        => $refreshTokenEntity->getIdentifier(),
            'access_token_id' => $accessToken->getIdentifier(),
            'client_id'       => $accessToken->getClient()->getIdentifier(),
        ]);
    }

    public function revokeRefreshToken(string $tokenId): void
    {
        $this->revoke($tokenId);
        $this->audit('refresh_token.revoked', ['token_id' => $tokenId]);
    }

    public function isRefreshTokenRevoked(string $tokenId): bool
    {
        return $this->isRevoked($tokenId);
    }

    /**
     * Revoke whichever refresh token was issued alongside this access token.
     *
     * RFC 7009 §2.1 leaves this optional — "the server MAY revoke the respective refresh token as
     * well" — but leaving it undone is what makes a revocation feel like it did nothing: the
     * client's next refresh succeeds and it is issued a fresh access token minutes later. Since
     * this is the store that decides whether a grant is still alive, this is where the grant ends.
     *
     * @return int Number of refresh tokens newly revoked.
     */
    public function revokeForAccessToken(string $accessTokenId): int
    {
        $revoked = $this->revokeWhere(self::FIELD_ACCESS_TOKEN_ID, $accessTokenId);

        if ($revoked > 0) {
            $this->audit('refresh_token.revoked', ['access_token_id' => $accessTokenId]);
        }

        return $revoked;
    }
}
