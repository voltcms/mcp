<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Tests\Http;

use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response as Psr7Response;
use PHPUnit\Framework\TestCase;
use VoltCMS\MCP\Http\Response;

/**
 * The response object every handler returns. The point of the class is that it is inert — a value
 * a test can read and a consumer can emit however it likes — so these tests are mostly about it
 * staying that way.
 */
final class ResponseTest extends TestCase
{
    public function testAJsonResponseIsNotCacheable(): void
    {
        $response = Response::json(['error' => 'invalid_request']);

        $this->assertSame('no-store', $response->header('Cache-Control'));
    }

    public function testAJsonResponseDecodesBackToWhatItWasGiven(): void
    {
        $response = Response::json(['error' => 'invalid_request']);

        $this->assertSame(['error' => 'invalid_request'], $response->decodedBody());
    }

    public function testAJsonResponseDoesNotEscapeSlashesInUrls(): void
    {
        $response = Response::json(['issuer' => 'https://example.com/mcp']);

        $this->assertStringContainsString('https://example.com/mcp', $response->body);
    }

    public function testARedirectCarriesItsLocation(): void
    {
        $response = Response::redirect('https://claude.ai/callback?code=abc');

        $this->assertSame(Response::STATUS_FOUND, $response->status);
        $this->assertSame('https://claude.ai/callback?code=abc', $response->header('Location'));
    }

    public function testWithHeaderReplacesAHeaderOfADifferentCaseRatherThanAddingASecond(): void
    {
        $response = (new Response(200, '', ['content-type' => 'text/plain']))
            ->withHeader('Content-Type', 'text/html');

        $this->assertCount(1, $response->headers);
        $this->assertSame('text/html', $response->header('content-type'));
    }

    public function testDecodesABodyThatIsNotJsonAsAnEmptyArray(): void
    {
        $this->assertSame([], Response::html('<p>hello</p>')->decodedBody());
    }

    public function testReadsAPsr7ResponseWhoseBodyHasAlreadyBeenWritten(): void
    {
        $psr = new Psr7Response(201, ['X-Test' => 'yes']);
        $psr->getBody()->write('{"ok":true}');

        $response = Response::fromPsr7($psr);

        $this->assertSame(201, $response->status);
        $this->assertSame('{"ok":true}', $response->body);
        $this->assertSame('yes', $response->header('X-Test'));
    }

    public function testConvertsBackToPsr7(): void
    {
        $psr = Response::json(['ok' => true], 202)->toPsr7(new Psr17Factory());

        $this->assertSame(202, $psr->getStatusCode());
        $this->assertSame('{"ok":true}', (string) $psr->getBody());
        $this->assertSame(Response::CONTENT_TYPE_JSON, $psr->getHeaderLine('Content-Type'));
    }
}
