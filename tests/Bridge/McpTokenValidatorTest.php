<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Tests\Bridge;

use VoltCMS\MCP\Bridge\McpTokenValidator;
use VoltCMS\MCP\Contracts\ScopePolicyInterface;
use VoltCMS\MCP\Identity\Identity;
use VoltCMS\MCP\Tests\Support\EndpointTestCase;
use VoltCMS\MCP\Tests\Support\StubIdentityProvider;
use VoltCMS\MCP\Tests\Support\StubScopePolicy;
use VoltCMS\MCP\Tests\Support\TestKeys;
use VoltCMS\MCP\OAuth\Tokens\AccessTokenVerifier;

/**
 * The seam between the two halves of the package: tokens league minted, validated for `mcp/sdk`.
 *
 * The tokens under test are real ones, taken out of the token endpoint rather than hand-built, so
 * this is also the proof that what the authorization server issues is what the MCP endpoint
 * accepts.
 *
 * Three of these are SECURITY.md promises: an account deactivated after issue fails validation, a
 * role removed after issue narrows the token, and a revoked access token stops working immediately
 * rather than at expiry.
 */
final class McpTokenValidatorTest extends EndpointTestCase
{
    public function testAllowsATokenThisServerJustIssued(): void
    {
        $result = $this->validator()->validate($this->accessToken());

        $this->assertTrue($result->isAllowed());
    }

    public function testAttachesTheSubjectToTheRequest(): void
    {
        $attributes = $this->validator()->validate($this->accessToken())->getAttributes();

        $this->assertSame('jannis', $attributes[McpTokenValidator::ATTRIBUTE_SUBJECT]);
    }

    public function testAttachesTheClientToTheRequest(): void
    {
        $attributes = $this->validator()->validate($this->accessToken())->getAttributes();

        $this->assertSame(self::CLIENT_ID, $attributes[McpTokenValidator::ATTRIBUTE_CLIENT_ID]);
    }

    public function testAttachesTheIdentityToTheRequest(): void
    {
        $attributes = $this->validator()->validate($this->accessToken())->getAttributes();

        $this->assertInstanceOf(Identity::class, $attributes[McpTokenValidator::ATTRIBUTE_IDENTITY]);
    }

    // --- Refusals ---

    public function testRefusesSomethingThatIsNotAToken(): void
    {
        $result = $this->validator()->validate('not-a-token');

        $this->assertFalse($result->isAllowed());
        $this->assertSame(401, $result->getStatusCode());
    }

    public function testRefusesATokenSignedByAnotherKey(): void
    {
        $verifier = new AccessTokenVerifier(
            $this->configuration->issuer,
            $this->configuration->resource,
            [TestKeys::foreignPublicKeyPem()],
        );

        $this->assertFalse($this->validator(verifier: $verifier)->validate($this->accessToken())->isAllowed());
    }

    public function testRefusesATokenMintedForAnotherResource(): void
    {
        $verifier = new AccessTokenVerifier(
            $this->configuration->issuer,
            'https://example.com/other-mcp',
            [TestKeys::publicKeyPem()],
        );

        $this->assertFalse($this->validator(verifier: $verifier)->validate($this->accessToken())->isAllowed());
    }

    /**
     * SECURITY.md: revoking an access token takes effect now, because validation reads the store.
     * See docs/decisions/0005-validation-reads-the-store.md.
     */
    public function testRefusesARevokedTokenImmediately(): void
    {
        $token  = $this->accessToken();
        $claims = $this->validator()->validate($token)->getAttributes();

        $this->accessTokens->revokeAccessToken((string) $claims[McpTokenValidator::ATTRIBUTE_TOKEN_ID]);

        $this->assertFalse($this->validator()->validate($token)->isAllowed());
    }

    public function testRefusesATokenWhoseAccountHasBeenDeactivated(): void
    {
        $token = $this->accessToken();

        $identities = new StubIdentityProvider(new Identity('jannis', 'Jannis', ['editor']));
        $identities->forget('jannis');

        $this->assertFalse($this->validator(identities: $identities)->validate($token)->isAllowed());
    }

    public function testRefusesATokenWhoseAccountNoLongerGrantsAnyOfItsScopes(): void
    {
        $token  = $this->accessToken();
        $result = $this->validator(policy: new StubScopePolicy([]))->validate($token);

        $this->assertFalse($result->isAllowed());
        $this->assertSame(403, $result->getStatusCode());
    }

    // --- Narrowing ---

    public function testNarrowsTheTokenToWhatTheAccountStillGrants(): void
    {
        $token      = $this->accessToken();
        $attributes = $this->validator(policy: new StubScopePolicy(['mcp:read']))
            ->validate($token)
            ->getAttributes();

        $this->assertSame(['mcp:read'], $attributes[McpTokenValidator::ATTRIBUTE_SCOPES]);
    }

    public function testRefusesATokenMissingARequiredScope(): void
    {
        $token  = $this->accessToken();
        $result = $this->validator(
            policy: new StubScopePolicy(['mcp:read']),
            requiredScopes: ['mcp:write'],
        )->validate($token);

        $this->assertSame(403, $result->getStatusCode());
    }

    public function testTheChallengeNamesTheScopesThatWereRequired(): void
    {
        $token  = $this->accessToken();
        $result = $this->validator(
            policy: new StubScopePolicy(['mcp:read']),
            requiredScopes: ['mcp:write'],
        )->validate($token);

        $this->assertSame(['mcp:write'], $result->getScopes());
    }

    public function testAllowsATokenCarryingEveryRequiredScope(): void
    {
        $result = $this->validator(requiredScopes: ['mcp:read', 'mcp:write'])->validate($this->accessToken());

        $this->assertTrue($result->isAllowed());
    }

    /**
     * Every refusal says the same thing. A caller that could tell "expired" from "revoked" from
     * "no such account" has a small oracle over tokens it does not hold.
     */
    public function testEveryUnauthorizedRefusalReadsTheSame(): void
    {
        $unknown = $this->validator()->validate('not-a-token');

        $token      = $this->accessToken();
        $identities = new StubIdentityProvider(new Identity('jannis', 'Jannis', ['editor']));
        $identities->forget('jannis');
        $deactivated = $this->validator(identities: $identities)->validate($token);

        $this->assertSame($unknown->getErrorDescription(), $deactivated->getErrorDescription());
    }

    // --- Helpers ---

    private function accessToken(): string
    {
        return (string) $this->issueTokens()['access_token'];
    }

    /**
     * @param list<string> $requiredScopes
     */
    private function validator(
        ?AccessTokenVerifier $verifier = null,
        ?StubIdentityProvider $identities = null,
        ?ScopePolicyInterface $policy = null,
        array $requiredScopes = [],
    ): McpTokenValidator {
        return new McpTokenValidator(
            $verifier ?? new AccessTokenVerifier(
                $this->configuration->issuer,
                $this->configuration->resource,
                [TestKeys::publicKeyPem()],
            ),
            $this->accessTokens,
            $identities ?? new StubIdentityProvider(new Identity('jannis', 'Jannis', ['editor'])),
            $policy ?? new StubScopePolicy(['mcp:read', 'mcp:write']),
            $requiredScopes,
        );
    }
}
