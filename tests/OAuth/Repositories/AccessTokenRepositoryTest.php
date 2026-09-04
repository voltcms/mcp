<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Tests\OAuth\Repositories;

use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException;
use VoltCMS\MCP\OAuth\Entities\Client;
use VoltCMS\MCP\OAuth\Entities\ResourceBoundAccessToken;
use VoltCMS\MCP\OAuth\Entities\Scope;
use VoltCMS\MCP\OAuth\Repositories\AccessTokenRepository;
use VoltCMS\MCP\Tests\Support\RepositoryTestCase;
use VoltCMS\UserAccess\AuditLog;

final class AccessTokenRepositoryTest extends RepositoryTestCase
{
    private AccessTokenRepository $repository;

    protected function setUp(): void
    {
        parent::setUp();

        $this->repository = new AccessTokenRepository($this->configuration);
    }

    // --- Minting ---

    public function testMintsAResourceBoundAccessToken(): void
    {
        $token = $this->repository->getNewToken($this->client(), [new Scope('mcp:read')], 'jannis');

        $this->assertInstanceOf(ResourceBoundAccessToken::class, $token);
    }

    public function testMintsATokenCarryingTheRequestedScopes(): void
    {
        $token = $this->repository->getNewToken($this->client(), [new Scope('mcp:read')], 'jannis');

        $this->assertSame('mcp:read', $token->getScopes()[0]->getIdentifier());
    }

    public function testMintsATokenCarryingTheUserIdentifier(): void
    {
        $token = $this->repository->getNewToken($this->client(), [], 'jannis');

        $this->assertSame('jannis', $token->getUserIdentifier());
    }

    public function testMintsATokenWithoutAUserWhenNoneIsGiven(): void
    {
        $token = $this->repository->getNewToken($this->client(), []);

        $this->assertNull($token->getUserIdentifier());
    }

    // --- Persistence and revocation ---

    public function testAPersistedTokenIsNotRevoked(): void
    {
        $this->repository->persistNewAccessToken($this->persistableToken('token-a'));

        $this->assertFalse($this->repository->isAccessTokenRevoked('token-a'));
    }

    public function testARevokedTokenReadsAsRevoked(): void
    {
        $this->repository->persistNewAccessToken($this->persistableToken('token-a'));

        $this->repository->revokeAccessToken('token-a');

        $this->assertTrue($this->repository->isAccessTokenRevoked('token-a'));
    }

    public function testATokenThisServerNeverIssuedReadsAsRevoked(): void
    {
        $this->assertTrue($this->repository->isAccessTokenRevoked('forged-identifier'));
    }

    public function testAnExpiredTokenReadsAsRevoked(): void
    {
        $this->repository->persistNewAccessToken($this->persistableToken('token-a', new \DateTimeImmutable('-1 second')));

        $this->assertTrue($this->repository->isAccessTokenRevoked('token-a'));
    }

    public function testRefusesToPersistTheSameIdentifierTwice(): void
    {
        $this->repository->persistNewAccessToken($this->persistableToken('token-a'));

        $this->expectException(UniqueTokenIdentifierConstraintViolationException::class);

        $this->repository->persistNewAccessToken($this->persistableToken('token-a'));
    }

    public function testRevokingOneTokenLeavesAnotherUsable(): void
    {
        $this->repository->persistNewAccessToken($this->persistableToken('token-a'));
        $this->repository->persistNewAccessToken($this->persistableToken('token-b'));

        $this->repository->revokeAccessToken('token-a');

        $this->assertFalse($this->repository->isAccessTokenRevoked('token-b'));
    }

    // --- Audit ---

    public function testRecordsAnIssuanceInTheAuditLog(): void
    {
        $auditLog   = new AuditLog($this->storageDirectory . '/audit');
        $repository = new AccessTokenRepository($this->configuration, $auditLog);

        $repository->persistNewAccessToken($this->persistableToken('token-a'));

        $this->assertStringContainsString('access_token.issued', (string) file_get_contents((string) $auditLog->getFile()));
    }

    public function testRecordsARevocationInTheAuditLog(): void
    {
        $auditLog   = new AuditLog($this->storageDirectory . '/audit');
        $repository = new AccessTokenRepository($this->configuration, $auditLog);

        $repository->persistNewAccessToken($this->persistableToken('token-a'));
        $repository->revokeAccessToken('token-a');

        $this->assertStringContainsString('access_token.revoked', (string) file_get_contents((string) $auditLog->getFile()));
    }

    // --- Helpers ---

    private function client(): Client
    {
        return new Client('claude-desktop', 'Claude Desktop', ['https://claude.ai/callback']);
    }

    private function persistableToken(string $identifier, ?\DateTimeImmutable $expiry = null): AccessTokenEntityInterface
    {
        $token = $this->repository->getNewToken($this->client(), [new Scope('mcp:read')], 'jannis');
        $token->setIdentifier($identifier);
        $token->setExpiryDateTime($expiry ?? new \DateTimeImmutable('+1 hour'));

        return $token;
    }
}
