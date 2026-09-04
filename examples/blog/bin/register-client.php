<?php

declare(strict_types=1);

/**
 * Registering a client by hand, which for most deployments is the only registration there is.
 *
 *     php bin/register-client.php "Claude Desktop" https://claude.ai/api/mcp/auth_callback
 *
 * A client whose `client_id` is an https URL needs none of this: it serves a Client ID Metadata
 * Document at that URL and this server fetches it. See
 * docs/decisions/0006-who-answers-registration.md.
 */

namespace Example\Blog;

/** @var \VoltCMS\MCP\OAuthServer $oauth */
require dirname(__DIR__) . '/bootstrap.php';

$name         = $argv[1] ?? '';
$redirectUris = array_slice($argv, 2);

if ($name === '' || $redirectUris === []) {
    fwrite(STDERR, "Usage: register-client.php <name> <redirect-uri> [redirect-uri ...]\n");

    exit(1);
}

$client = $oauth->registrations()->registerPublic($name, $redirectUris);

echo "Registered ", $client->getName(), "\n";
echo "  client_id: ", $client->getIdentifier(), "\n";
echo "  This is a public client: it authenticates with PKCE and holds no secret.\n";
