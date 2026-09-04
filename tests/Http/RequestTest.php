<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Tests\Http;

use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use VoltCMS\MCP\Http\Request;

/**
 * The request object the endpoints read. Most of what matters here is what it refuses to do —
 * resolve a host, trust an array where a string belongs — because an endpoint that reads a
 * `client_id` out of `?client_id[]=…` is an endpoint doing type juggling on a credential.
 */
final class RequestTest extends TestCase
{
    public function testUppercasesTheMethod(): void
    {
        $this->assertSame('POST', (new Request('post'))->method);
    }

    public function testRefusesAnEmptyMethod(): void
    {
        $this->expectExceptionCode(Request::EXCEPTION_METHOD_REQUIRED);

        new Request('   ');
    }

    public function testAnswersIsPostForAPost(): void
    {
        $this->assertTrue((new Request('POST'))->isPost());
    }

    public function testFindsAHeaderWhateverItsCase(): void
    {
        $request = new Request('GET', '/', [], [], ['CONTENT-type' => 'application/json']);

        $this->assertSame('application/json', $request->header('Content-Type'));
    }

    public function testReadsAQueryParameter(): void
    {
        $request = new Request('GET', '/authorize?state=xyz', ['state' => 'xyz']);

        $this->assertSame('xyz', $request->query('state'));
    }

    public function testIgnoresAQueryParameterThatArrivedAsAnArray(): void
    {
        $request = new Request('GET', '/authorize', ['client_id' => ['a', 'b']]);

        $this->assertNull($request->query('client_id'));
    }

    public function testIgnoresABodyParameterThatArrivedAsAnArray(): void
    {
        $request = new Request('POST', '/token', [], ['client_secret' => ['a']]);

        $this->assertNull($request->body('client_secret'));
    }

    public function testReadsABearerToken(): void
    {
        $request = new Request('GET', '/mcp', [], [], ['Authorization' => 'Bearer abc.def.ghi']);

        $this->assertSame('abc.def.ghi', $request->bearerToken());
    }

    public function testIgnoresAnAuthorizationHeaderThatIsNotBearer(): void
    {
        $request = new Request('GET', '/mcp', [], [], ['Authorization' => 'Basic abc']);

        $this->assertNull($request->bearerToken());
    }

    public function testDecodesBasicAuthCredentials(): void
    {
        $request = new Request('POST', '/revoke', [], [], [
            'Authorization' => 'Basic ' . base64_encode('client:s3cret'),
        ]);

        $this->assertSame(['client', 's3cret'], $request->basicAuthCredentials());
    }

    public function testFormUrlDecodesBasicAuthCredentialsAsRfc6749Requires(): void
    {
        $request = new Request('POST', '/revoke', [], [], [
            'Authorization' => 'Basic ' . base64_encode('cli%40ent:p%3Ass'),
        ]);

        $this->assertSame(['cli@ent', 'p:ss'], $request->basicAuthCredentials());
    }

    public function testIgnoresABasicHeaderWithNoColon(): void
    {
        $request = new Request('POST', '/revoke', [], [], [
            'Authorization' => 'Basic ' . base64_encode('no-separator'),
        ]);

        $this->assertNull($request->basicAuthCredentials());
    }

    // --- PSR-7 ---

    public function testCarriesTheQueryStringAcrossFromPsr7(): void
    {
        $psr = (new ServerRequest('GET', 'https://example.com/oauth/authorize?state=xyz'))
            ->withQueryParams(['state' => 'xyz']);

        $this->assertSame('/oauth/authorize?state=xyz', Request::fromPsr7($psr)->uri);
    }

    /**
     * The host is deliberately dropped: an endpoint that could see it might build an issuer or an
     * audience out of it, and `Host` is attacker-controlled. See PLAN.md §4.3.
     */
    public function testDoesNotCarryTheHostAcrossFromPsr7(): void
    {
        $psr = new ServerRequest('GET', 'https://attacker.example/oauth/authorize');

        $this->assertStringNotContainsString('attacker.example', Request::fromPsr7($psr)->uri);
    }

    public function testCarriesThePeerAddressAcrossFromPsr7(): void
    {
        $psr = new ServerRequest('GET', 'https://example.com/token', [], null, '1.1', ['REMOTE_ADDR' => '203.0.113.7']);

        $this->assertSame('203.0.113.7', Request::fromPsr7($psr)->clientIp);
    }

    public function testCarriesHeadersAcrossFromPsr7(): void
    {
        $psr = (new ServerRequest('GET', 'https://example.com/mcp'))->withHeader('Authorization', 'Bearer xyz');

        $this->assertSame('xyz', Request::fromPsr7($psr)->bearerToken());
    }
}
