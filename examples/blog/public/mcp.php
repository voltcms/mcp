<?php

declare(strict_types=1);

/**
 * The whole server, in one front controller.
 *
 * Every handler RETURNS a response — nothing in the package echoes, sets a header or exits — so
 * this file is the one place output happens, and it is eleven lines at the bottom. That is what
 * makes the package testable without a web server, and what lets an application keep its own
 * output chokepoint.
 *
 * Route these paths to this file; see the README for the Apache and nginx snippets, and note that
 * `/.well-known/` usually needs a rewrite of its own.
 */

namespace Example\Blog;

use VoltCMS\MCP\Http\Request;
use VoltCMS\MCP\Http\Response;
use VoltCMS\MCP\OAuth\Endpoints\MetadataEndpoint;

/** @var \VoltCMS\MCP\OAuthServer $oauth */
/** @var \VoltCMS\MCP\McpServer $mcp */
require dirname(__DIR__) . '/bootstrap.php';

$request = Request::fromGlobals();
$path    = (string) parse_url($request->uri, PHP_URL_PATH);

$response = match ($path) {
    '/mcp'                            => $mcp->handle($request),
    '/oauth/authorize'                => $oauth->authorize($request),
    '/oauth/token'                    => $oauth->token($request),
    '/oauth/revoke'                   => $oauth->revoke($request),
    '/oauth/jwks'                     => $oauth->jwks($request),
    '/oauth/register'                 => $oauth->register($request),
    MetadataEndpoint::WELL_KNOWN_PATH => $oauth->metadata($request),
    $mcp->resourceMetadataPath()      => $mcp->resourceMetadata(),
    default                           => Response::json(['error' => 'not_found'], Response::STATUS_NOT_FOUND),
};

http_response_code($response->status);

foreach ($response->headers as $name => $value) {
    header($name . ': ' . $value, true);
}

echo $response->body;
