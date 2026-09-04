<?php

declare(strict_types=1);

namespace VoltCMS\MCP\OAuth\Endpoints;

use VoltCMS\MCP\Configuration;
use VoltCMS\MCP\Http\PsrAdapter;
use VoltCMS\MCP\Http\Request;
use VoltCMS\MCP\Http\Response;

/**
 * RFC 8414 authorization server metadata — the document a client fetches from
 * `/.well-known/oauth-authorization-server` to find out how to talk to this server at all.
 *
 * league/oauth2-server ships none (verified in the spike), which is a real gap rather than an
 * omission: an MCP client discovers the authorization server from the protected resource's RFC 9728
 * metadata and then reads this to find the authorize and token endpoints. Without it a client has
 * nowhere to start and the flow cannot begin.
 *
 * Every value comes from `Configuration`. **Not one of them is derived from the request**, and that
 * is the point of the class as much as the document is: a metadata endpoint that built its URLs
 * from `$_SERVER['HTTP_HOST']` would publish an attacker's origin as this application's
 * authorization server to anyone who asked with a forged `Host` header, and the client would
 * dutifully send its authorization request there. See PLAN.md §4.3.
 *
 * `code_challenge_methods_supported` lists `S256` and nothing else. That is the §4.1 tightening
 * made visible: a client reading this document is told, before it sends anything, that `plain` is
 * not on offer here.
 */
final class MetadataEndpoint extends Endpoint
{
    /** Where RFC 8414 §3 says this document lives. Routing it is the deployment's job. */
    public const WELL_KNOWN_PATH = '/.well-known/oauth-authorization-server';

    public const CACHE_SECONDS = 3600;

    private const THROTTLE_BUCKET = 'mcp.metadata';

    public function __construct(Configuration $configuration, PsrAdapter $psr)
    {
        parent::__construct($configuration, $psr);
    }

    public function handle(Request $request): Response
    {
        if (!$request->isGet()) {
            return $this->methodNotAllowed('GET');
        }

        return Response::json($this->document(), Response::STATUS_OK, [
            'Cache-Control' => 'public, max-age=' . self::CACHE_SECONDS,
            'Pragma'        => 'cache',
        ]);
    }

    /**
     * The document itself, so a consumer that renders its own `.well-known` route — or a test that
     * wants to assert on it byte for byte — does not have to go through the HTTP shape.
     *
     * @return array<string, mixed>
     */
    public function document(): array
    {
        $document = [
            'issuer'                                => $this->configuration->issuer,
            'authorization_endpoint'                => $this->configuration->authorizationEndpoint,
            'token_endpoint'                        => $this->configuration->tokenEndpoint,
            'jwks_uri'                              => $this->configuration->jwksUri,
            'revocation_endpoint'                   => $this->configuration->revocationEndpoint,
            'scopes_supported'                      => $this->configuration->scopes,
            'response_types_supported'              => ['code'],
            'response_modes_supported'              => ['query'],
            'grant_types_supported'                 => ['authorization_code', 'refresh_token'],
            // `none` first, because the clients this package exists for are public: a desktop
            // application cannot keep a secret, and PKCE is what authenticates it instead.
            'token_endpoint_auth_methods_supported' => ['none', 'client_secret_basic', 'client_secret_post'],
            'revocation_endpoint_auth_methods_supported' => ['none', 'client_secret_basic', 'client_secret_post'],
            'code_challenge_methods_supported'      => ['S256'],
        ];

        if ($this->configuration->registrationEndpoint !== null) {
            $document['registration_endpoint'] = $this->configuration->registrationEndpoint;
        }

        return $document;
    }

    protected function throttleBucket(): string
    {
        return self::THROTTLE_BUCKET;
    }
}
