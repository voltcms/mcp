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

/** @var \VoltCMS\MCP\OAuthServer $oauth */
/** @var \VoltCMS\MCP\McpServer $mcp */
require dirname(__DIR__) . '/bootstrap.php';

$request = Request::fromGlobals();
$path    = (string) parse_url($request->uri, PHP_URL_PATH);

/**
 * The two metadata documents are matched against LISTS, not constants. RFC 8414 and RFC 9728 both
 * put a document at a URL derived from the identifier it describes — for `resource:
 * https://example.com/mcp` that is `/.well-known/oauth-protected-resource/mcp`, not the bare path —
 * so where they belong depends on this deployment's configuration. Ask, do not hard-code.
 */
$response = match (true) {
    $path === '/mcp'                                     => $mcp->handle($request),
    $path === '/oauth/authorize'                         => $oauth->authorize($request),
    $path === '/oauth/token'                             => $oauth->token($request),
    $path === '/oauth/revoke'                            => $oauth->revoke($request),
    $path === '/oauth/jwks'                              => $oauth->jwks($request),
    $path === '/oauth/register'                          => $oauth->register($request),
    in_array($path, $oauth->metadataPaths(), true)       => $oauth->metadata($request),
    in_array($path, $mcp->resourceMetadataPaths(), true) => $mcp->resourceMetadata(),
    default                                              => Response::json(
        ['error' => 'not_found'],
        Response::STATUS_NOT_FOUND,
    ),
};

http_response_code($response->status);

foreach ($response->headers as $name => $value) {
    header($name . ': ' . $value, true);
}

echo $response->body;
