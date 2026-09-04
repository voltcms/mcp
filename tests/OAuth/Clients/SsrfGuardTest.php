<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Tests\OAuth\Clients;

use PHPUnit\Framework\TestCase;
use VoltCMS\MCP\OAuth\Clients\SsrfGuard;

/**
 * The guard in front of the one thing in this package that makes an outbound request.
 *
 * A `client_id` is an unauthenticated request parameter, and under CIMD it is a URL this server
 * fetches — so every case below is an address an attacker would like this server to reach on their
 * behalf. The cloud metadata service at `169.254.169.254` is the one that matters most: it is
 * reachable from inside almost every hosted environment and hands out credentials to anyone who
 * asks.
 *
 * The resolver is injected, so none of this touches DNS.
 */
final class SsrfGuardTest extends TestCase
{
    public function testAllowsAPublicHttpsUrl(): void
    {
        $this->assertSame('93.184.216.34', $this->guard(['93.184.216.34'])->guard('https://claude.ai/client.json'));
    }

    public function testRefusesPlainHttp(): void
    {
        $this->expectExceptionCode(SsrfGuard::EXCEPTION_SCHEME_INSECURE);

        $this->guard(['93.184.216.34'])->guard('http://claude.ai/client.json');
    }

    public function testRefusesAUrlWithNoHost(): void
    {
        $this->expectExceptionCode(SsrfGuard::EXCEPTION_URL_MALFORMED);

        $this->guard(['93.184.216.34'])->guard('/client.json');
    }

    /** A `file://` URL has no host at all, so it is refused before the scheme is even considered. */
    public function testRefusesAFileUrl(): void
    {
        $this->expectExceptionCode(SsrfGuard::EXCEPTION_URL_MALFORMED);

        $this->guard(['93.184.216.34'])->guard('file:///etc/passwd');
    }

    public function testRefusesAGopherUrlWithAHost(): void
    {
        $this->expectExceptionCode(SsrfGuard::EXCEPTION_SCHEME_INSECURE);

        $this->guard(['93.184.216.34'])->guard('gopher://claude.ai/client.json');
    }

    public function testRefusesANonStandardPort(): void
    {
        $this->expectExceptionCode(SsrfGuard::EXCEPTION_PORT_REFUSED);

        $this->guard(['93.184.216.34'])->guard('https://claude.ai:8443/client.json');
    }

    public function testRefusesEmbeddedCredentials(): void
    {
        $this->expectExceptionCode(SsrfGuard::EXCEPTION_URL_MALFORMED);

        $this->guard(['93.184.216.34'])->guard('https://user:pass@claude.ai/client.json');
    }

    // --- Addresses ---

    public function testRefusesLoopback(): void
    {
        $this->expectExceptionCode(SsrfGuard::EXCEPTION_ADDRESS_PRIVATE);

        $this->guard(['127.0.0.1'])->guard('https://localhost.attacker.example/client.json');
    }

    /**
     * The one that pays: a hostname the attacker controls, resolving to the address that hands out
     * cloud credentials. No hostname filter catches this; only looking at the address does.
     */
    public function testRefusesTheCloudMetadataAddress(): void
    {
        $this->expectExceptionCode(SsrfGuard::EXCEPTION_ADDRESS_PRIVATE);

        $this->guard(['169.254.169.254'])->guard('https://metadata.attacker.example/client.json');
    }

    public function testRefusesAPrivateRangeAddress(): void
    {
        $this->expectExceptionCode(SsrfGuard::EXCEPTION_ADDRESS_PRIVATE);

        $this->guard(['10.0.0.7'])->guard('https://internal.attacker.example/client.json');
    }

    public function testRefusesIpv6Loopback(): void
    {
        $this->expectExceptionCode(SsrfGuard::EXCEPTION_ADDRESS_PRIVATE);

        $this->guard(['::1'])->guard('https://six.attacker.example/client.json');
    }

    public function testRefusesAUniqueLocalIpv6Address(): void
    {
        $this->expectExceptionCode(SsrfGuard::EXCEPTION_ADDRESS_PRIVATE);

        $this->guard(['fd00::1'])->guard('https://six.attacker.example/client.json');
    }

    /**
     * A round-robin record whose second answer is private would otherwise be fetched on a retry,
     * so every address a host resolves to has to pass, not just the first.
     */
    public function testRefusesAHostWhoseSecondAddressIsPrivate(): void
    {
        $this->expectExceptionCode(SsrfGuard::EXCEPTION_ADDRESS_PRIVATE);

        $this->guard(['93.184.216.34', '10.0.0.7'])->guard('https://mixed.attacker.example/client.json');
    }

    public function testRefusesAHostThatDoesNotResolve(): void
    {
        $this->expectExceptionCode(SsrfGuard::EXCEPTION_HOST_UNRESOLVED);

        $this->guard([])->guard('https://nowhere.example/client.json');
    }

    public function testRefusesAResolverAnswerThatIsNotAnAddress(): void
    {
        $this->expectExceptionCode(SsrfGuard::EXCEPTION_ADDRESS_PRIVATE);

        $this->guard(['not-an-address'])->guard('https://claude.ai/client.json');
    }

    /**
     * @param list<string> $addresses
     */
    private function guard(array $addresses): SsrfGuard
    {
        return new SsrfGuard(static fn (string $host): array => $addresses);
    }
}
