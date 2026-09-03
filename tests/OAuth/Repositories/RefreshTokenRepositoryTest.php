<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Tests\OAuth\Repositories;

use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException;
use VoltCMS\MCP\OAuth\Entities\Client;
use VoltCMS\MCP\OAuth\Repositories\AccessTokenRepository;
use VoltCMS\MCP\OAuth\Repositories\RefreshTokenRepository;
use VoltCMS\MCP\Tests\Support\RepositoryTestCase;

final class RefreshTokenRepositoryTest extends RepositoryTestCase
{
    private RefreshTokenRepository $repository;
    private AccessTokenRepository $accessTokens;

    protected function setUp(): void
    {
        parent::setUp();

        $this->repository   = new RefreshTokenRepository($this->configuration);
        $this->accessTokens = new AccessTokenRepository($this->configuration);
    }

    public function testAPersistedRefreshTokenIsNotRevoked(): void
    {
        $this->repository->persistNewRefreshToken($this->refreshToken('refresh-a', 'access-a'));

        $this->assertFalse($this->repository->isRefreshTokenRevoked('refresh-a'));
    }

    public function testARevokedRefreshTokenReadsAsRevoked(): void
    {
        $this->repository->persistNewRefreshToken($this->refreshToken('refresh-a', 'access-a'));

        $this->repository->revokeRefreshToken('refresh-a');

        $this->assertTrue($this->repository->isRefreshTokenRevoked('refresh-a'));
    }

    /**
     * Rotation, as league performs it: the presented token is revoked and its replacement stored
     * in the same exchange. Both halves have to land here, or a rotated grant would either keep
     * working from the old token or die on the new one.
     */
    public function testRotationRevokesTheOldTokenAndKeepsTheNewOne(): void
    {
        $this->repository->persistNewRefreshToken($this->refreshToken('refresh-a', 'access-a'));

        $this->repository->revokeRefreshToken('refresh-a');
        $this->repository->persistNewRefreshToken($this->refreshToken('refresh-b', 'access-b'));

        $this->assertTrue($this->repository->isRefreshTokenRevoked('refresh-a'));
        $this->assertFalse($this->repository->isRefreshTokenRevoked('refresh-b'));
    }

    public function testARefreshTokenThisServerNeverIssuedReadsAsRevoked(): void
    {
        $this->assertTrue($this->repository->isRefreshTokenRevoked('forged-identifier'));
    }

    public function testAnExpiredRefreshTokenReadsAsRevoked(): void
    {
        $this->repository->persistNewRefreshToken(
            $this->refreshToken('refresh-a', 'access-a', new \DateTimeImmutable('-1 second')),
        );

        $this->assertTrue($this->repository->isRefreshTokenRevoked('refresh-a'));
    }

    public function testRefusesToPersistTheSameIdentifierTwice(): void
    {
        $this->repository->persistNewRefreshToken($this->refreshToken('refresh-a', 'access-a'));

        $this->expectException(UniqueTokenIdentifierConstraintViolationException::class);

        $this->repository->persistNewRefreshToken($this->refreshToken('refresh-a', 'access-b'));
    }

    private function refreshToken(
        string $identifier,
        string $accessTokenIdentifier,
        ?\DateTimeImmutable $expiry = null,
    ): RefreshTokenEntityInterface {
        $accessToken = $this->accessTokens->getNewToken(
            new Client('claude-desktop', 'Claude Desktop', ['https://claude.ai/callback']),
            [],
            'jannis',
        );
        $accessToken->setIdentifier($accessTokenIdentifier);
        $accessToken->setExpiryDateTime(new \DateTimeImmutable('+1 hour'));

        $refreshToken = $this->repository->getNewRefreshToken();
        $this->assertNotNull($refreshToken);
        $refreshToken->setIdentifier($identifier);
        $refreshToken->setAccessToken($accessToken);
        $refreshToken->setExpiryDateTime($expiry ?? new \DateTimeImmutable('+30 days'));

        return $refreshToken;
    }
}
