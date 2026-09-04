<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Tests\OAuth\Tokens;

use Lcobucci\JWT\Configuration as JwtConfiguration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use PHPUnit\Framework\TestCase;
use VoltCMS\MCP\OAuth\Tokens\AccessTokenVerifier;
use VoltCMS\MCP\Tests\Support\TestKeys;

/**
 * The other half of the §4.2 tightening: `ResourceBoundAccessToken` puts the resource in `aud`,
 * and this refuses anything whose `aud` is something else. A verifier that only checked the
 * signature would happily accept a token this same server minted for a different audience.
 */
final class AccessTokenVerifierTest extends TestCase
{
    private const ISSUER   = 'https://example.com';
    private const RESOURCE = 'https://example.com/mcp';

    public function testRefusesToBeBuiltWithNoKeys(): void
    {
        $this->expectExceptionCode(AccessTokenVerifier::EXCEPTION_NO_VERIFICATION_KEY);

        new AccessTokenVerifier(self::ISSUER, self::RESOURCE, []);
    }

    public function testVerifiesATokenThisServerMinted(): void
    {
        $claims = $this->verifier()->verify($this->token());

        $this->assertSame('token-id', $claims?->identifier);
    }

    public function testCarriesTheClientIdentifierBack(): void
    {
        $this->assertSame('claude-desktop', $this->verifier()->verify($this->token())?->clientId);
    }

    public function testCarriesTheSubjectBack(): void
    {
        $this->assertSame('jannis', $this->verifier()->verify($this->token())?->subject);
    }

    public function testCarriesTheScopesBack(): void
    {
        $this->assertSame(['mcp:read'], $this->verifier()->verify($this->token())?->scopes);
    }

    public function testRefusesATokenSignedByAnotherKey(): void
    {
        $foreign = $this->token(privateKey: TestKeys::foreignPrivateKeyPem());

        $this->assertNull($this->verifier()->verify($foreign));
    }

    public function testRefusesATokenMintedForAnotherAudience(): void
    {
        $this->assertNull($this->verifier()->verify($this->token(audience: 'https://example.com/other')));
    }

    public function testRefusesATokenFromAnotherIssuer(): void
    {
        $this->assertNull($this->verifier()->verify($this->token(issuer: 'https://attacker.example')));
    }

    public function testRefusesSomethingThatIsNotAJwtAtAll(): void
    {
        $this->assertNull($this->verifier()->verify('not-a-token'));
    }

    /**
     * A retired signing key stays in the list until the last token it signed has expired, so a
     * rotation does not log every client out at once.
     */
    public function testAcceptsATokenSignedByARetiredKeyThatIsStillListed(): void
    {
        $foreign  = $this->token(privateKey: TestKeys::foreignPrivateKeyPem());
        $verifier = new AccessTokenVerifier(self::ISSUER, self::RESOURCE, [
            TestKeys::publicKeyPem(),
            TestKeys::foreignPublicKeyPem(),
        ]);

        $this->assertSame('token-id', $verifier->verify($foreign)?->identifier);
    }

    public function testDoesNotRejectAnExpiredToken(): void
    {
        $expired = $this->token(expiresAt: new \DateTimeImmutable('2020-01-01 00:00:00'));

        $this->assertNotNull($this->verifier()->verify($expired));
    }

    public function testAnExpiredTokenKnowsItHasExpired(): void
    {
        $expired = $this->token(expiresAt: new \DateTimeImmutable('2020-01-01 00:00:00'));

        $this->assertTrue($this->verifier()->verify($expired)?->hasExpired());
    }

    // --- Helpers ---

    private function verifier(): AccessTokenVerifier
    {
        return new AccessTokenVerifier(self::ISSUER, self::RESOURCE, [TestKeys::publicKeyPem()]);
    }

    private function token(
        ?string $privateKey = null,
        string $issuer = self::ISSUER,
        string $audience = self::RESOURCE,
        ?\DateTimeImmutable $expiresAt = null,
    ): string {
        $configuration = JwtConfiguration::forAsymmetricSigner(
            new Sha256(),
            InMemory::plainText($privateKey ?? TestKeys::privateKeyPem()),
            InMemory::plainText('empty', 'empty'),
        );

        $now = new \DateTimeImmutable();

        return $configuration->builder()
            ->issuedBy($issuer)
            ->permittedFor($audience)
            ->identifiedBy('token-id')
            ->issuedAt($now)
            ->expiresAt($expiresAt ?? $now->modify('+1 hour'))
            ->relatedTo('jannis')
            ->withClaim('client_id', 'claude-desktop')
            ->withClaim('scopes', ['mcp:read'])
            ->getToken($configuration->signer(), $configuration->signingKey())
            ->toString();
    }
}
