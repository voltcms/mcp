<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Tests\OAuth\Repositories;

use League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException;
use VoltCMS\MCP\OAuth\Entities\Client;
use VoltCMS\MCP\OAuth\Entities\Scope;
use VoltCMS\MCP\OAuth\Repositories\AuthCodeRepository;
use VoltCMS\MCP\Tests\Support\RepositoryTestCase;

final class AuthCodeRepositoryTest extends RepositoryTestCase
{
    private AuthCodeRepository $repository;

    protected function setUp(): void
    {
        parent::setUp();

        $this->repository = new AuthCodeRepository($this->configuration);
    }

    public function testAPersistedCodeIsNotRevoked(): void
    {
        $this->repository->persistNewAuthCode($this->code('code-a'));

        $this->assertFalse($this->repository->isAuthCodeRevoked('code-a'));
    }

    /**
     * Single use is league's guarantee, but this store is what enforces it: the grant revokes the
     * code as it redeems it and asks here before honouring a second attempt.
     */
    public function testARedeemedCodeCannotBeReplayed(): void
    {
        $this->repository->persistNewAuthCode($this->code('code-a'));

        $this->repository->revokeAuthCode('code-a');

        $this->assertTrue($this->repository->isAuthCodeRevoked('code-a'));
    }

    public function testACodeThisServerNeverIssuedReadsAsRevoked(): void
    {
        $this->assertTrue($this->repository->isAuthCodeRevoked('forged-code'));
    }

    public function testAnExpiredCodeReadsAsRevoked(): void
    {
        $this->repository->persistNewAuthCode($this->code('code-a', new \DateTimeImmutable('-1 second')));

        $this->assertTrue($this->repository->isAuthCodeRevoked('code-a'));
    }

    public function testRefusesToPersistTheSameCodeTwice(): void
    {
        $this->repository->persistNewAuthCode($this->code('code-a'));

        $this->expectException(UniqueTokenIdentifierConstraintViolationException::class);

        $this->repository->persistNewAuthCode($this->code('code-a'));
    }

    public function testStoresTheRedirectUriTheCodeWasIssuedFor(): void
    {
        $this->repository->persistNewAuthCode($this->code('code-a'));

        $files = glob($this->storageDirectory . '/auth_codes/*.json') ?: [];
        $this->assertCount(1, $files);

        $record = json_decode((string) file_get_contents($files[0]), true);

        $this->assertSame('https://claude.ai/callback', $record['redirect_uri'] ?? null);
    }

    public function testMintsACodeEntityLeagueCanPopulate(): void
    {
        $code = $this->repository->getNewAuthCode();
        $code->setIdentifier('code-a');

        $this->assertSame('code-a', $code->getIdentifier());
    }

    private function code(string $identifier, ?\DateTimeImmutable $expiry = null): AuthCodeEntityInterface
    {
        $code = $this->repository->getNewAuthCode();
        $code->setIdentifier($identifier);
        $code->setClient(new Client('claude-desktop', 'Claude Desktop', ['https://claude.ai/callback']));
        $code->setUserIdentifier('jannis');
        $code->setRedirectUri('https://claude.ai/callback');
        $code->addScope(new Scope('mcp:read'));
        $code->setExpiryDateTime($expiry ?? new \DateTimeImmutable('+10 minutes'));

        return $code;
    }
}
