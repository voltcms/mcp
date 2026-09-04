<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Tests\OAuth\Consent;

use PHPUnit\Framework\TestCase;
use VoltCMS\MCP\OAuth\Consent\ConsentTicketSigner;

/**
 * The consent ticket is what stops a cross-site POST from approving an authorization request, so
 * every case below is "an approval that must not carry over".
 */
final class ConsentTicketSignerTest extends TestCase
{
    private const SECRET = 'PsUqBQ0YBaNlfyE8dLUt9dK4rMPVLQhZ8OrZfEXvOBs=';

    public function testRefusesAnEmptySecret(): void
    {
        $this->expectExceptionCode(ConsentTicketSigner::EXCEPTION_SECRET_REQUIRED);

        new ConsentTicketSigner('');
    }

    public function testATicketVerifiesAgainstTheBindingItWasIssuedFor(): void
    {
        $signer = new ConsentTicketSigner(self::SECRET);

        $this->assertTrue($signer->verify($signer->issue($this->binding()), $this->binding()));
    }

    public function testATicketDoesNotVerifyAgainstADifferentUser(): void
    {
        $signer = new ConsentTicketSigner(self::SECRET);
        $ticket = $signer->issue($this->binding());

        $this->assertFalse($signer->verify($ticket, $this->binding(['user_id' => 'someone-else'])));
    }

    public function testATicketDoesNotVerifyAgainstADifferentClient(): void
    {
        $signer = new ConsentTicketSigner(self::SECRET);
        $ticket = $signer->issue($this->binding());

        $this->assertFalse($signer->verify($ticket, $this->binding(['client_id' => 'another-client'])));
    }

    public function testATicketDoesNotVerifyAgainstWiderScopes(): void
    {
        $signer = new ConsentTicketSigner(self::SECRET);
        $ticket = $signer->issue($this->binding(['scopes' => ['mcp:read']]));

        $this->assertFalse($signer->verify($ticket, $this->binding(['scopes' => ['mcp:read', 'mcp:write']])));
    }

    public function testATicketDoesNotVerifyAgainstADifferentRedirectUri(): void
    {
        $signer = new ConsentTicketSigner(self::SECRET);
        $ticket = $signer->issue($this->binding());

        $this->assertFalse($signer->verify($ticket, $this->binding(['redirect_uri' => 'https://attacker.example/cb'])));
    }

    public function testATicketSignedWithAnotherSecretDoesNotVerify(): void
    {
        $ticket = (new ConsentTicketSigner('a-different-secret-entirely-0000000000000'))->issue($this->binding());

        $this->assertFalse((new ConsentTicketSigner(self::SECRET))->verify($ticket, $this->binding()));
    }

    public function testAnExpiredTicketDoesNotVerify(): void
    {
        $signer = new ConsentTicketSigner(self::SECRET, 60);
        $ticket = $signer->issue($this->binding(), new \DateTimeImmutable('2026-01-01 12:00:00'));

        $this->assertFalse($signer->verify($ticket, $this->binding(), new \DateTimeImmutable('2026-01-01 12:01:01')));
    }

    public function testATicketWithAnExtendedExpiryDoesNotVerify(): void
    {
        $signer = new ConsentTicketSigner(self::SECRET);
        $ticket = $signer->issue($this->binding());

        [, $mac] = explode('.', $ticket, 2);

        $this->assertFalse($signer->verify((time() + 86400) . '.' . $mac, $this->binding()));
    }

    public function testAMalformedTicketDoesNotVerify(): void
    {
        $this->assertFalse((new ConsentTicketSigner(self::SECRET))->verify('not-a-ticket', $this->binding()));
    }

    /**
     * The binding is signed after `ksort()`, so a caller cannot change the signature by reordering
     * what it passes — otherwise "same approval, different order" would read as a forgery.
     */
    public function testTheOrderOfTheBindingDoesNotChangeTheSignature(): void
    {
        $signer = new ConsentTicketSigner(self::SECRET);
        $ticket = $signer->issue($this->binding());

        $this->assertTrue($signer->verify($ticket, array_reverse($this->binding(), true)));
    }

    /**
     * @param array<string, mixed> $overrides
     *
     * @return array<string, mixed>
     */
    private function binding(array $overrides = []): array
    {
        return array_merge([
            'client_id'      => 'claude-desktop',
            'code_challenge' => 'wg2rDjZ0T-h1kIsoTsWKzOaG7lNL5DfPTLNPTLNPTLN',
            'redirect_uri'   => 'https://claude.ai/callback',
            'resource'       => 'https://example.com/mcp',
            'scopes'         => ['mcp:read', 'mcp:write'],
            'state'          => 'xyz',
            'user_id'        => 'jannis',
        ], $overrides);
    }
}
