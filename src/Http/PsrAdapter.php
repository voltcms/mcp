<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Http;

use Http\Discovery\Psr17FactoryDiscovery;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestFactoryInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * The one place this package converts between its own Request / Response and PSR-7.
 *
 * league/oauth2-server takes a PSR-7 request and writes into a PSR-7 response, so an endpoint
 * cannot avoid holding both. Keeping the conversion here means every endpoint stays a
 * `Request in, Response out` function, and a consumer with no PSR-7 of its own never sees one.
 *
 * The factories are discovered rather than required, exactly as `mcp/sdk` discovers its own:
 * `psr/http-factory` ships interfaces only, and a consumer of `mcp/sdk`'s HTTP transport
 * necessarily already has an implementation installed. The failure, if there is none, is a
 * constructor exception naming the fix rather than a fatal error deep inside a grant.
 */
final class PsrAdapter
{
    public const EXCEPTION_NO_PSR17_IMPLEMENTATION = 4101;

    private readonly ServerRequestFactoryInterface $serverRequests;
    private readonly ResponseFactoryInterface $responses;

    /**
     * @throws \RuntimeException if no PSR-17 implementation is installed and none was passed.
     */
    public function __construct(
        ?ServerRequestFactoryInterface $serverRequests = null,
        ?ResponseFactoryInterface $responses = null,
    ) {
        try {
            $this->serverRequests = $serverRequests ?? Psr17FactoryDiscovery::findServerRequestFactory();
            $this->responses      = $responses ?? Psr17FactoryDiscovery::findResponseFactory();
        } catch (\Throwable $exception) {
            throw new \RuntimeException(
                'No PSR-17 factory is installed. Require a PSR-7 implementation — nyholm/psr7 is the '
                . 'recommended one — or pass factories to PsrAdapter explicitly.',
                self::EXCEPTION_NO_PSR17_IMPLEMENTATION,
                $exception,
            );
        }
    }

    /**
     * league reads four things from a server request: the query parameters, the parsed body, the
     * `Authorization` header and the server parameters. All four are carried across; the request
     * target is not a URL, for the reason Request's docblock gives.
     *
     * `$absoluteUri` exists for one caller. `mcp/sdk`'s transport builds its `WWW-Authenticate`
     * challenge from the request's scheme and authority and throws without them, so the MCP
     * endpoint has to hand over an absolute URL. It must be the CONFIGURED resource URL and never
     * one assembled from a request header — that is the whole of PLAN.md §4.3 — which is why this
     * is a parameter the caller supplies rather than something this method could work out.
     */
    public function toServerRequest(Request $request, ?string $absoluteUri = null): ServerRequestInterface
    {
        $psrRequest = $this->serverRequests
            ->createServerRequest($request->method, $absoluteUri ?? $request->uri, ['REMOTE_ADDR' => $request->clientIp])
            ->withQueryParams($request->queryParams)
            ->withParsedBody($request->parsedBody);

        foreach ($request->headers as $name => $value) {
            $psrRequest = $psrRequest->withHeader($name, $value);
        }

        // mcp/sdk reads the JSON-RPC envelope off the body stream, not out of the parsed body, so
        // a request that carried only the parsed form would reach it as a parse error.
        if ($request->rawBody !== '') {
            $psrRequest->getBody()->write($request->rawBody);
            $psrRequest->getBody()->rewind();
        }

        return $psrRequest;
    }

    /** An empty 200 for league to write its own status, headers and body into. */
    public function blankResponse(): ResponseInterface
    {
        return $this->responses->createResponse();
    }

    public function fromResponse(ResponseInterface $response): Response
    {
        return Response::fromPsr7($response);
    }

    public function responseFactory(): ResponseFactoryInterface
    {
        return $this->responses;
    }
}
