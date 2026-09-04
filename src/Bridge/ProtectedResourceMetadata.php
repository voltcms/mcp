<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Bridge;

use Mcp\Server\Transport\Http\OAuth\ProtectedResourceMetadata as SdkProtectedResourceMetadata;
use VoltCMS\MCP\Configuration;

/**
 * Builds `mcp/sdk`'s RFC 9728 metadata object out of this package's `Configuration`.
 *
 * The SDK owns the document — it ships the class, and its `AuthorizationMiddleware` reads the
 * metadata path out of it to build the `WWW-Authenticate` challenge that tells a client where to
 * go. What it cannot know is which authorization server is answering, and the answer has to be the
 * configured issuer rather than anything from the request: this document is precisely how a client
 * discovers where to send its authorization request, so a value taken from a forged `Host` header
 * would redirect the whole flow to an attacker.
 *
 * A factory rather than a subclass because the SDK's class is `final`, which is the right call on
 * its side and the reason this file exists on ours. Everything here is one call into `mcp/sdk`, in
 * `Bridge/`, so a 0.9 that renames a parameter breaks in one place.
 */
final class ProtectedResourceMetadata
{
    public static function forConfiguration(
        Configuration $configuration,
        ?string $resourceName = null,
        ?string $documentation = null,
    ): SdkProtectedResourceMetadata {
        return new SdkProtectedResourceMetadata(
            authorizationServers: [$configuration->issuer],
            scopesSupported: $configuration->scopes,
            resource: $configuration->resource,
            resourceName: $resourceName,
            resourceDocumentation: $documentation,
        );
    }
}
