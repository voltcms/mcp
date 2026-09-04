<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Tests;

use PHPUnit\Framework\TestCase;
use VoltCMS\MCP\Configuration;
use VoltCMS\MCP\EndpointUrls;

/**
 * Configuration is the package's guard against a header-derived issuer or audience (PLAN.md
 * §4.3), so every refusal below is a security behaviour and not merely input validation.
 */
final class ConfigurationTest extends TestCase
{
    private const KEY = 'PsUqBQ0YBaNlfyE8dLUt9dK4rMPVLQhZ8OrZfEXvOBs=';

    // --- Endpoint URLs ---

    public function testDerivesTheEndpointUrlsFromTheIssuerByDefault(): void
    {
        $config = $this->configuration();

        $this->assertSame('https://example.com/oauth/authorize', $config->authorizationEndpoint);
        $this->assertSame('https://example.com/oauth/token', $config->tokenEndpoint);
        $this->assertSame('https://example.com/oauth/revoke', $config->revocationEndpoint);
        $this->assertSame('https://example.com/oauth/jwks', $config->jwksUri);
        $this->assertSame('https://example.com/oauth/register', $config->registrationEndpoint);
    }

    public function testDerivedEndpointUrlsFollowTheIssuersPath(): void
    {
        $config = $this->configuration(issuer: 'https://example.com/blog');

        $this->assertSame('https://example.com/blog/oauth/authorize', $config->authorizationEndpoint);
    }

    public function testAcceptsExplicitEndpointUrls(): void
    {
        $config = $this->configuration(endpoints: new EndpointUrls(
            'https://example.com/auth',
            'https://example.com/tok',
            'https://example.com/rev',
            'https://example.com/keys',
        ));

        $this->assertSame('https://example.com/auth', $config->authorizationEndpoint);
        $this->assertNull($config->registrationEndpoint);
    }

    public function testRefusesAnEndpointUrlThatIsNotHttps(): void
    {
        $this->expectExceptionCode(Configuration::EXCEPTION_ENDPOINT_INSECURE);

        $this->configuration(endpoints: new EndpointUrls(
            'http://example.com/auth',
            'https://example.com/tok',
            'https://example.com/rev',
            'https://example.com/keys',
        ));
    }

    public function testRefusesARelativeEndpointUrl(): void
    {
        $this->expectExceptionCode(Configuration::EXCEPTION_ENDPOINT_MALFORMED);

        $this->configuration(endpoints: new EndpointUrls(
            '/oauth/authorize',
            'https://example.com/tok',
            'https://example.com/rev',
            'https://example.com/keys',
        ));
    }

    // --- Accepted configurations ---

    public function testExposesTheValuesItWasGiven(): void
    {
        $config = $this->configuration();

        $this->assertSame('https://example.com', $config->issuer);
        $this->assertSame('https://example.com/mcp', $config->resource);
        $this->assertSame('/var/private/mcp', $config->storageDirectory);
        $this->assertSame('/var/private/mcp/keys/private.key', $config->privateKeyPath);
        $this->assertSame('/var/private/mcp/keys/public.key', $config->publicKeyPath);
        $this->assertSame(self::KEY, $config->encryptionKey);
        $this->assertSame(['mcp:read', 'mcp:write'], $config->scopes);
    }

    public function testStripsATrailingSlashFromTheIssuer(): void
    {
        $config = $this->configuration(issuer: 'https://example.com/');

        $this->assertSame('https://example.com', $config->issuer);
    }

    public function testKeepsThePathOfTheResourceUrl(): void
    {
        $config = $this->configuration(resource: 'https://example.com/api/mcp');

        $this->assertSame('https://example.com/api/mcp', $config->resource);
    }

    public function testAcceptsPlainHttpForLoopback(): void
    {
        $config = $this->configuration(issuer: 'http://localhost:8080', resource: 'http://localhost:8080/mcp');

        $this->assertSame('http://localhost:8080', $config->issuer);
    }

    public function testStripsATrailingSeparatorFromTheStorageDirectory(): void
    {
        $config = $this->configuration(storageDirectory: '/var/private/mcp/');

        $this->assertSame('/var/private/mcp', $config->storageDirectory);
    }

    // --- Refused configurations ---

    public function testRefusesAnEmptyIssuer(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionCode(Configuration::EXCEPTION_ISSUER_REQUIRED);

        $this->configuration(issuer: '');
    }

    public function testRefusesAnIssuerWithoutAScheme(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionCode(Configuration::EXCEPTION_ISSUER_MALFORMED);

        $this->configuration(issuer: 'example.com');
    }

    public function testRefusesAnIssuerCarryingAQueryString(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionCode(Configuration::EXCEPTION_ISSUER_MALFORMED);

        $this->configuration(issuer: 'https://example.com?tenant=1');
    }

    public function testRefusesAnIssuerCarryingCredentials(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionCode(Configuration::EXCEPTION_ISSUER_MALFORMED);

        $this->configuration(issuer: 'https://user:secret@example.com');
    }

    public function testRefusesAPlainHttpIssuerOnAPublicHost(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionCode(Configuration::EXCEPTION_ISSUER_INSECURE);

        $this->configuration(issuer: 'http://example.com');
    }

    public function testRefusesAnEmptyResource(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionCode(Configuration::EXCEPTION_RESOURCE_REQUIRED);

        $this->configuration(resource: '');
    }

    public function testRefusesAPlainHttpResourceOnAPublicHost(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionCode(Configuration::EXCEPTION_RESOURCE_INSECURE);

        $this->configuration(resource: 'http://example.com/mcp');
    }

    public function testRefusesARelativeStorageDirectory(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionCode(Configuration::EXCEPTION_PATH_NOT_ABSOLUTE);

        $this->configuration(storageDirectory: 'storage/mcp');
    }

    public function testRefusesAnEmptyPrivateKeyPath(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionCode(Configuration::EXCEPTION_PATH_REQUIRED);

        $this->configuration(privateKeyPath: '');
    }

    public function testRefusesAnEmptyEncryptionKey(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionCode(Configuration::EXCEPTION_ENCRYPTION_KEY_REQUIRED);

        $this->configuration(encryptionKey: '');
    }

    public function testRefusesAnEncryptionKeyShorterThanThirtyTwoCharacters(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionCode(Configuration::EXCEPTION_ENCRYPTION_KEY_TOO_SHORT);

        $this->configuration(encryptionKey: 'too-short');
    }

    public function testRefusesAnEmptyScopeList(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionCode(Configuration::EXCEPTION_SCOPES_REQUIRED);

        $this->configuration(scopes: []);
    }

    public function testRefusesAScopeContainingASpace(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionCode(Configuration::EXCEPTION_SCOPE_MALFORMED);

        $this->configuration(scopes: ['mcp read']);
    }

    public function testRefusesADuplicatedScope(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionCode(Configuration::EXCEPTION_SCOPE_DUPLICATED);

        $this->configuration(scopes: ['mcp:read', 'mcp:read']);
    }

    // --- Lifetimes ---

    public function testDefaultsTheAuthorizationCodeLifetimeToTenMinutes(): void
    {
        $reference = new \DateTimeImmutable('2026-01-01T00:00:00+00:00');

        $this->assertSame(
            '2026-01-01T00:10:00+00:00',
            $reference->add($this->configuration()->authorizationCodeTtl)->format(\DATE_ATOM),
        );
    }

    public function testDefaultsTheAccessTokenLifetimeToOneHour(): void
    {
        $reference = new \DateTimeImmutable('2026-01-01T00:00:00+00:00');

        $this->assertSame(
            '2026-01-01T01:00:00+00:00',
            $reference->add($this->configuration()->accessTokenTtl)->format(\DATE_ATOM),
        );
    }

    public function testDefaultsTheRefreshTokenLifetimeToThirtyDays(): void
    {
        $reference = new \DateTimeImmutable('2026-01-01T00:00:00+00:00');

        $this->assertSame(
            '2026-01-31T00:00:00+00:00',
            $reference->add($this->configuration()->refreshTokenTtl)->format(\DATE_ATOM),
        );
    }

    public function testKeepsAnExplicitAccessTokenLifetime(): void
    {
        $reference = new \DateTimeImmutable('2026-01-01T00:00:00+00:00');
        $config    = $this->configuration(accessTokenTtl: new \DateInterval('PT15M'));

        $this->assertSame(
            '2026-01-01T00:15:00+00:00',
            $reference->add($config->accessTokenTtl)->format(\DATE_ATOM),
        );
    }

    // --- Scope lookup ---

    public function testReportsAConfiguredScopeAsSupported(): void
    {
        $this->assertTrue($this->configuration()->scopeIsSupported('mcp:write'));
    }

    public function testReportsAnUnknownScopeAsUnsupported(): void
    {
        $this->assertFalse($this->configuration()->scopeIsSupported('mcp:admin'));
    }

    // --- Helper ---

    /**
     * @param list<string> $scopes
     */
    private function configuration(
        string $issuer = 'https://example.com',
        string $resource = 'https://example.com/mcp',
        string $storageDirectory = '/var/private/mcp',
        string $privateKeyPath = '/var/private/mcp/keys/private.key',
        string $publicKeyPath = '/var/private/mcp/keys/public.key',
        string $encryptionKey = self::KEY,
        array $scopes = ['mcp:read', 'mcp:write'],
        ?\DateInterval $accessTokenTtl = null,
        ?EndpointUrls $endpoints = null,
    ): Configuration {
        return new Configuration(
            issuer:           $issuer,
            resource:         $resource,
            storageDirectory: $storageDirectory,
            privateKeyPath:   $privateKeyPath,
            publicKeyPath:    $publicKeyPath,
            encryptionKey:    $encryptionKey,
            scopes:           $scopes,
            accessTokenTtl:   $accessTokenTtl,
            endpoints:        $endpoints,
        );
    }
}
