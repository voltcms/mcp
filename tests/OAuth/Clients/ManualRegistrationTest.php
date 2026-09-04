<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Tests\OAuth\Clients;

use VoltCMS\MCP\OAuth\Clients\ManualRegistration;
use VoltCMS\MCP\OAuth\Repositories\ClientRepository;
use VoltCMS\MCP\Tests\Support\RepositoryTestCase;

/**
 * Registering a client from a script, which for most deployments is the only registration there is.
 */
final class ManualRegistrationTest extends RepositoryTestCase
{
    public function testRegistersAPublicClientThatCanBeReadBack(): void
    {
        $client = $this->registration()->registerPublic('Claude Desktop', ['https://claude.ai/callback']);

        $this->assertNotNull($this->clients()->getClientEntity($client->getIdentifier()));
    }

    public function testAPublicClientAuthenticatesWithNoSecret(): void
    {
        $client = $this->registration()->registerPublic('Claude Desktop', ['https://claude.ai/callback']);

        $this->assertTrue($this->clients()->validateClient($client->getIdentifier(), null, null));
    }

    public function testAPublicClientPresentingASecretIsRefused(): void
    {
        $client = $this->registration()->registerPublic('Claude Desktop', ['https://claude.ai/callback']);

        $this->assertFalse($this->clients()->validateClient($client->getIdentifier(), 'anything', null));
    }

    public function testGeneratesAnUnguessableIdentifier(): void
    {
        $first  = $this->registration()->registerPublic('One', ['https://claude.ai/callback']);
        $second = $this->registration()->registerPublic('Two', ['https://claude.ai/callback']);

        $this->assertNotSame($first->getIdentifier(), $second->getIdentifier());
        $this->assertGreaterThanOrEqual(20, strlen($first->getIdentifier()));
    }

    public function testAcceptsAChosenIdentifier(): void
    {
        $client = $this->registration()->registerPublic('Claude', ['https://claude.ai/callback'], 'claude-desktop');

        $this->assertSame('claude-desktop', $client->getIdentifier());
    }

    // --- Confidential clients ---

    public function testAConfidentialClientAuthenticatesWithTheSecretItWasGiven(): void
    {
        [$client, $secret] = $this->registration()->registerConfidential('Server', ['https://claude.ai/callback']);

        $this->assertTrue($this->clients()->validateClient($client->getIdentifier(), $secret, null));
    }

    public function testAConfidentialClientIsRefusedWithTheWrongSecret(): void
    {
        [$client] = $this->registration()->registerConfidential('Server', ['https://claude.ai/callback']);

        $this->assertFalse($this->clients()->validateClient($client->getIdentifier(), 'not-the-secret', null));
    }

    /**
     * The secret is returned once and stored only as a hash, so it is nowhere to be read back from.
     */
    public function testTheSecretIsNotRecoverableFromTheStore(): void
    {
        [, $secret] = $this->registration()->registerConfidential('Server', ['https://claude.ai/callback']);

        $stored = '';

        foreach (glob($this->storageDirectory . '/clients/*.json') ?: [] as $file) {
            $stored .= (string) file_get_contents($file);
        }

        $this->assertStringNotContainsString($secret, $stored);
    }

    // --- Refusals ---

    public function testRefusesAClientWithNoRedirectUri(): void
    {
        $this->expectExceptionCode(ManualRegistration::EXCEPTION_REDIRECT_URIS_REQUIRED);

        $this->registration()->registerPublic('Claude Desktop', []);
    }

    public function testRefusesAClientWhoseOnlyRedirectUriIsBlank(): void
    {
        $this->expectExceptionCode(ManualRegistration::EXCEPTION_REDIRECT_URIS_REQUIRED);

        $this->registration()->registerPublic('Claude Desktop', ['   ']);
    }

    // --- Deactivation ---

    public function testADeactivatedClientIsNoLongerFound(): void
    {
        $registration = $this->registration();
        $client       = $registration->registerPublic('Claude Desktop', ['https://claude.ai/callback']);

        $registration->deactivate($client->getIdentifier());

        $this->assertNull($this->clients()->getClientEntity($client->getIdentifier()));
    }

    private function registration(): ManualRegistration
    {
        return new ManualRegistration($this->clients());
    }

    private function clients(): ClientRepository
    {
        return new ClientRepository($this->configuration);
    }
}
