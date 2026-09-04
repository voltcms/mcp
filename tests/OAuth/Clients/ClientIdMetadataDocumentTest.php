<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Tests\OAuth\Clients;

use PHPUnit\Framework\TestCase;
use VoltCMS\MCP\OAuth\Clients\ClientIdMetadataDocument;
use VoltCMS\MCP\OAuth\Entities\Client;

/**
 * Validation of a document served by whoever the `client_id` parameter named.
 *
 * `testRefusesADocumentClaimingAnotherClientId` is the one that matters most: without it,
 * `https://attacker.example/client.json` could serve a document claiming to be Claude, and the
 * consent screen the user approves would name Claude while the authorization code went elsewhere.
 */
final class ClientIdMetadataDocumentTest extends TestCase
{
    private const URL = 'https://claude.ai/client.json';

    public function testAcceptsAWellFormedDocument(): void
    {
        $document = ClientIdMetadataDocument::fromDocument($this->document(), self::URL);

        $this->assertSame(self::URL, $document->clientId);
        $this->assertSame('Claude Desktop', $document->clientName);
    }

    public function testCarriesTheRedirectUris(): void
    {
        $document = ClientIdMetadataDocument::fromDocument($this->document(), self::URL);

        $this->assertSame(['https://claude.ai/callback'], $document->redirectUris);
    }

    public function testBuildsAPublicClient(): void
    {
        $client = ClientIdMetadataDocument::fromDocument($this->document(), self::URL)->toClient();

        $this->assertInstanceOf(Client::class, $client);
        $this->assertFalse($client->isConfidential());
    }

    public function testDefaultsToTheAuthorizationCodeAndRefreshGrants(): void
    {
        $document = ClientIdMetadataDocument::fromDocument($this->document(['grant_types' => null]), self::URL);

        $this->assertSame(['authorization_code', 'refresh_token'], $document->grantTypes);
    }

    public function testFallsBackToTheUrlWhenTheDocumentNamesNoClient(): void
    {
        $document = ClientIdMetadataDocument::fromDocument($this->document(['client_name' => null]), self::URL);

        $this->assertSame(self::URL, $document->clientName);
    }

    // --- Refusals ---

    /**
     * The whole basis of CIMD: a document is only about the URL it was served from.
     */
    public function testRefusesADocumentClaimingAnotherClientId(): void
    {
        $this->expectExceptionCode(ClientIdMetadataDocument::EXCEPTION_CLIENT_ID_MISMATCH);

        ClientIdMetadataDocument::fromDocument(
            $this->document(['client_id' => 'https://claude.ai/client.json']),
            'https://attacker.example/client.json',
        );
    }

    public function testRefusesADocumentThatClaimsNoClientIdAtAll(): void
    {
        $this->expectExceptionCode(ClientIdMetadataDocument::EXCEPTION_CLIENT_ID_MISMATCH);

        ClientIdMetadataDocument::fromDocument($this->document(['client_id' => null]), self::URL);
    }

    public function testRefusesADocumentWithNoRedirectUris(): void
    {
        $this->expectExceptionCode(ClientIdMetadataDocument::EXCEPTION_REDIRECT_URIS_MISSING);

        ClientIdMetadataDocument::fromDocument($this->document(['redirect_uris' => []]), self::URL);
    }

    public function testRefusesAPlainHttpRedirectUri(): void
    {
        $this->expectExceptionCode(ClientIdMetadataDocument::EXCEPTION_REDIRECT_URI_INSECURE);

        ClientIdMetadataDocument::fromDocument(
            $this->document(['redirect_uris' => ['http://claude.ai/callback']]),
            self::URL,
        );
    }

    /**
     * RFC 8252 §7.3: a desktop client's callback is a loopback URL on a random port, and there is
     * no transport there to secure.
     */
    public function testAcceptsALoopbackHttpRedirectUri(): void
    {
        $document = ClientIdMetadataDocument::fromDocument(
            $this->document(['redirect_uris' => ['http://127.0.0.1:49152/callback']]),
            self::URL,
        );

        $this->assertSame(['http://127.0.0.1:49152/callback'], $document->redirectUris);
    }

    public function testRefusesARedirectUriWithAFragment(): void
    {
        $this->expectExceptionCode(ClientIdMetadataDocument::EXCEPTION_REDIRECT_URI_INSECURE);

        ClientIdMetadataDocument::fromDocument(
            $this->document(['redirect_uris' => ['https://claude.ai/callback#token']]),
            self::URL,
        );
    }

    public function testRefusesARelativeRedirectUri(): void
    {
        $this->expectExceptionCode(ClientIdMetadataDocument::EXCEPTION_REDIRECT_URI_INSECURE);

        ClientIdMetadataDocument::fromDocument($this->document(['redirect_uris' => ['/callback']]), self::URL);
    }

    public function testRefusesAClientClaimingToHoldASecret(): void
    {
        $this->expectExceptionCode(ClientIdMetadataDocument::EXCEPTION_AUTH_METHOD_REFUSED);

        ClientIdMetadataDocument::fromDocument(
            $this->document(['token_endpoint_auth_method' => 'client_secret_basic']),
            self::URL,
        );
    }

    public function testRefusesAnUnsupportedGrantType(): void
    {
        $this->expectExceptionCode(ClientIdMetadataDocument::EXCEPTION_GRANT_TYPE_REFUSED);

        ClientIdMetadataDocument::fromDocument(
            $this->document(['grant_types' => ['client_credentials']]),
            self::URL,
        );
    }

    /**
     * The name goes on a consent screen. A newline in it is a client trying to shape what the user
     * reads; escaping is still the view's job, but this refuses the obvious.
     */
    public function testStripsControlCharactersFromTheClientName(): void
    {
        $document = ClientIdMetadataDocument::fromDocument(
            $this->document(['client_name' => "Claude\nAdministrator access"]),
            self::URL,
        );

        $this->assertSame('Claude Administrator access', $document->clientName);
    }

    public function testRefusesAnOverLongClientName(): void
    {
        $this->expectExceptionCode(ClientIdMetadataDocument::EXCEPTION_NAME_MALFORMED);

        ClientIdMetadataDocument::fromDocument(
            $this->document(['client_name' => str_repeat('a', ClientIdMetadataDocument::MAXIMUM_NAME_LENGTH + 1)]),
            self::URL,
        );
    }

    public function testRefusesAClientNameThatIsNotAString(): void
    {
        $this->expectExceptionCode(ClientIdMetadataDocument::EXCEPTION_NAME_MALFORMED);

        ClientIdMetadataDocument::fromDocument($this->document(['client_name' => ['a']]), self::URL);
    }

    public function testKeepsAtMostTheAllowedNumberOfRedirectUris(): void
    {
        $uris = array_map(
            static fn (int $index): string => 'https://claude.ai/callback/' . $index,
            range(1, ClientIdMetadataDocument::MAXIMUM_REDIRECT_URIS + 5),
        );

        $document = ClientIdMetadataDocument::fromDocument($this->document(['redirect_uris' => $uris]), self::URL);

        $this->assertCount(ClientIdMetadataDocument::MAXIMUM_REDIRECT_URIS, $document->redirectUris);
    }

    /**
     * @param array<string, mixed> $overrides
     *
     * @return array<string, mixed>
     */
    private function document(array $overrides = []): array
    {
        return array_filter(array_merge([
            'client_id'     => self::URL,
            'client_name'   => 'Claude Desktop',
            'redirect_uris' => ['https://claude.ai/callback'],
            'grant_types'   => ['authorization_code', 'refresh_token'],
        ], $overrides), static fn (mixed $value): bool => $value !== null);
    }
}
