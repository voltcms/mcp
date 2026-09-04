<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Tests\OAuth\Repositories;

use VoltCMS\MCP\OAuth\Entities\Client;
use VoltCMS\MCP\OAuth\Repositories\ClientRepository;
use VoltCMS\MCP\Tests\Support\RepositoryTestCase;

final class ClientRepositoryTest extends RepositoryTestCase
{
    private ClientRepository $repository;

    protected function setUp(): void
    {
        parent::setUp();

        $this->repository = new ClientRepository($this->configuration);
    }

    // --- Lookup ---

    public function testReadsBackARegisteredPublicClient(): void
    {
        $this->repository->save(new Client('claude-desktop', 'Claude Desktop', ['https://claude.ai/callback']));

        $client = $this->repository->getClientEntity('claude-desktop');

        $this->assertNotNull($client);
        $this->assertSame('Claude Desktop', $client->getName());
        $this->assertSame(['https://claude.ai/callback'], $client->getRedirectUri());
        $this->assertFalse($client->isConfidential());
    }

    public function testReturnsNullForAnUnknownClient(): void
    {
        $this->assertNull($this->repository->getClientEntity('never-registered'));
    }

    public function testReturnsNullForADeactivatedClient(): void
    {
        $this->repository->save(new Client('claude-desktop', 'Claude Desktop', ['https://claude.ai/callback']));

        $this->repository->deactivate('claude-desktop');

        $this->assertNull($this->repository->getClientEntity('claude-desktop'));
    }

    /**
     * The client id arrives from the query string, so this is the realistic shape of the FileDB
     * wildcard hazard: a lookup that prefix-matched would hand an attacker any client whose id
     * starts with a guessable prefix. See PLAN.md §4.8.
     */
    public function testDoesNotResolveAClientByAWildcardIdentifier(): void
    {
        $this->repository->save(new Client('claude-desktop', 'Claude Desktop', ['https://claude.ai/callback']));

        $this->assertNull($this->repository->getClientEntity('claude*'));
    }

    // --- Secrets ---

    public function testValidatesAConfidentialClientWithTheCorrectSecret(): void
    {
        $this->repository->save(new Client('server', 'Server', ['https://example.com/cb'], true), 'correct-horse');

        $this->assertTrue($this->repository->validateClient('server', 'correct-horse', 'authorization_code'));
    }

    public function testRefusesAConfidentialClientWithTheWrongSecret(): void
    {
        $this->repository->save(new Client('server', 'Server', ['https://example.com/cb'], true), 'correct-horse');

        $this->assertFalse($this->repository->validateClient('server', 'wrong-horse', 'authorization_code'));
    }

    public function testRefusesAConfidentialClientWithNoSecret(): void
    {
        $this->repository->save(new Client('server', 'Server', ['https://example.com/cb'], true), 'correct-horse');

        $this->assertFalse($this->repository->validateClient('server', null, 'authorization_code'));
    }

    public function testNeverStoresAClientSecretInCleartext(): void
    {
        $this->repository->save(new Client('server', 'Server', ['https://example.com/cb'], true), 'correct-horse');

        $stored = '';

        foreach (glob($this->storageDirectory . '/clients/*.json') ?: [] as $file) {
            $stored .= file_get_contents($file);
        }

        $this->assertStringNotContainsString('correct-horse', $stored);
    }

    public function testDoesNotStoreASecretForAPublicClient(): void
    {
        $this->repository->save(new Client('claude-desktop', 'Claude Desktop', ['https://claude.ai/callback']), 'ignored');

        $this->assertFalse($this->repository->validateClient('claude-desktop', 'ignored', 'authorization_code'));
    }

    public function testValidatesAPublicClientPresentingNoSecret(): void
    {
        $this->repository->save(new Client('claude-desktop', 'Claude Desktop', ['https://claude.ai/callback']));

        $this->assertTrue($this->repository->validateClient('claude-desktop', null, 'authorization_code'));
    }

    public function testRefusesAnUnknownClient(): void
    {
        $this->assertFalse($this->repository->validateClient('never-registered', 'anything', 'authorization_code'));
    }

    public function testRefusesADeactivatedClient(): void
    {
        $this->repository->save(new Client('server', 'Server', ['https://example.com/cb'], true), 'correct-horse');

        $this->repository->deactivate('server');

        $this->assertFalse($this->repository->validateClient('server', 'correct-horse', 'authorization_code'));
    }

    // --- Grant types ---

    public function testRefusesAGrantTypeTheClientIsNotRegisteredFor(): void
    {
        $this->repository->save(
            new Client('server', 'Server', ['https://example.com/cb'], true, [Client::GRANT_AUTHORIZATION_CODE]),
            'correct-horse',
        );

        $this->assertFalse($this->repository->validateClient('server', 'correct-horse', 'client_credentials'));
    }

    public function testRoundTripsTheRegisteredGrantTypes(): void
    {
        $this->repository->save(
            new Client('claude-desktop', 'Claude Desktop', ['https://claude.ai/callback'], false, [Client::GRANT_AUTHORIZATION_CODE]),
        );

        $client = $this->repository->getClientEntity('claude-desktop');

        $this->assertNotNull($client);
        $this->assertFalse($client->supportsGrantType(Client::GRANT_REFRESH_TOKEN));
    }
}
