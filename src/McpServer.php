<?php

declare(strict_types=1);

namespace VoltCMS\MCP;

use Mcp\Server;
use Mcp\Server\Transport\Http\Middleware\AuthorizationMiddleware;
use Mcp\Server\Transport\Http\Middleware\CorsMiddleware;
use Mcp\Server\Transport\Http\Middleware\DnsRebindingProtectionMiddleware;
use Mcp\Server\Transport\Http\OAuth\ProtectedResourceMetadata as SdkProtectedResourceMetadata;
use Mcp\Server\Transport\StreamableHttpTransport;
use Psr\Http\Server\MiddlewareInterface;
use VoltCMS\MCP\Bridge\McpTokenValidator;
use VoltCMS\MCP\Bridge\ProtectedResourceMetadata;
use VoltCMS\MCP\Bridge\SessionStoreFactory;
use VoltCMS\MCP\Contracts\IdentityProviderInterface;
use VoltCMS\MCP\Contracts\ScopePolicyInterface;
use VoltCMS\MCP\Http\PsrAdapter;
use VoltCMS\MCP\Http\Request;
use VoltCMS\MCP\Http\Response;
use VoltCMS\MCP\OAuth\Repositories\AccessTokenRepository;
use VoltCMS\MCP\OAuth\Tokens\AccessTokenVerifier;

/**
 * The MCP endpoint: `mcp/sdk`'s server, behind this package's tokens.
 *
 * Everything here is assembly. The protocol, the transport, both lifecycle eras and the tool
 * dispatch are the SDK's — decision 0001 adopted it precisely so none of that would be written
 * twice — and the one thing the SDK deliberately does not have is a way to validate a token nobody
 * else issued. `McpTokenValidator` is that, and this class is what puts it in front of the
 * transport.
 *
 * ```php
 * $mcp = new McpServer($configuration, $identities, $scopePolicy, $verifier, $accessTokens);
 * $mcp->addTool([$posts, 'read'], name: 'read_post', description: 'Read one post.');
 *
 * $response = $mcp->handle(Request::fromGlobals());   // returns; never echoes
 * ```
 *
 * The SDK's default middleware is kept, with two changes it needs in order to work anywhere but
 * `localhost`. `DnsRebindingProtectionMiddleware` defaults to an allowlist of localhost variants
 * only, so a server deployed at a real hostname would answer every request with 403 — it is rebuilt
 * here around the configured resource host, which is the only host this server should ever be
 * reached at anyway. And `AuthorizationMiddleware` runs AFTER the CORS middleware, so a browser's
 * preflight `OPTIONS` is answered rather than refused for carrying no bearer token.
 */
final class McpServer
{
    public const DEFAULT_SERVER_NAME    = 'voltcms-mcp';
    public const DEFAULT_SERVER_VERSION = '0.1.0';

    private readonly Server\Builder $builder;
    private readonly McpTokenValidator $validator;
    private readonly SdkProtectedResourceMetadata $resourceMetadata;
    private readonly SessionStoreFactory $sessions;
    private readonly PsrAdapter $psr;

    /**
     * @param list<string>                    $requiredScopes Scopes every MCP request must carry.
     * @param list<MiddlewareInterface>|null  $middleware     Replaces the stack described above, whole.
     */
    public function __construct(
        private readonly Configuration $configuration,
        IdentityProviderInterface $identities,
        ScopePolicyInterface $scopePolicy,
        AccessTokenVerifier $verifier,
        AccessTokenRepository $accessTokens,
        array $requiredScopes = [],
        ?string $serverName = null,
        ?string $serverVersion = null,
        ?PsrAdapter $psr = null,
        ?SessionStoreFactory $sessions = null,
        private readonly ?array $customMiddleware = null,
    ) {
        $this->psr       = $psr ?? new PsrAdapter();
        $this->sessions  = $sessions ?? new SessionStoreFactory($configuration);
        $this->validator = new McpTokenValidator($verifier, $accessTokens, $identities, $scopePolicy, $requiredScopes);

        $this->resourceMetadata = ProtectedResourceMetadata::forConfiguration($configuration);

        $this->builder = Server::builder()
            ->setServerInfo($serverName ?? self::DEFAULT_SERVER_NAME, $serverVersion ?? self::DEFAULT_SERVER_VERSION)
            ->setSession($this->sessions->create());
    }

    /**
     * Register a tool. The signature mirrors `mcp/sdk`'s builder because there is nothing this
     * package can usefully add to it, and a wrapper that dropped a parameter would only be in the
     * way when the SDK grew one.
     *
     * @param callable|array{0: object|string, 1: string}|string $handler
     * @param array<string, mixed>|null                          $inputSchema
     */
    public function addTool(
        callable|array|string $handler,
        ?string $name = null,
        ?string $title = null,
        ?string $description = null,
        ?array $inputSchema = null,
    ): self {
        $this->builder->addTool($handler, $name, $title, $description, inputSchema: $inputSchema);

        return $this;
    }

    /**
     * The RFC 9728 protected resource metadata, for the `.well-known` route the README shows.
     * Rendered here; routed by the deployment.
     */
    public function resourceMetadata(): Response
    {
        return Response::json(
            $this->resourceMetadata->jsonSerialize(),
            Response::STATUS_OK,
            ['Cache-Control' => 'public, max-age=3600', 'Pragma' => 'cache'],
        );
    }

    /** Where the RFC 9728 document must be served from. */
    public function resourceMetadataPath(): string
    {
        return $this->resourceMetadata->getPrimaryMetadataPath();
    }

    public function tokenValidator(): McpTokenValidator
    {
        return $this->validator;
    }

    public function sessions(): SessionStoreFactory
    {
        return $this->sessions;
    }

    /**
     * Handle one MCP request and RETURN the response. Nothing is emitted.
     *
     * The transport is built per request because it takes the request as a constructor argument —
     * the SDK's design, and a reasonable one for a share-nothing PHP process.
     */
    public function handle(Request $request): Response
    {
        return $this->psr->fromResponse(
            $this->builder->build()->run(new StreamableHttpTransport(
                $this->psr->toServerRequest($request, $this->endpointUrl($request)),
                middleware: $this->middleware(),
            )),
        );
    }

    /**
     * The configured resource URL, carrying whatever query string the request arrived with. The
     * host is Configuration's, never the request's: `AuthorizationMiddleware` publishes this
     * authority in the `WWW-Authenticate` challenge that tells a client where to authenticate, so a
     * value taken from a forged `Host` would send the client somewhere else entirely.
     */
    private function endpointUrl(Request $request): string
    {
        $query = (string) parse_url($request->uri, PHP_URL_QUERY);

        return $query === '' ? $this->configuration->resource : $this->configuration->resource . '?' . $query;
    }

    /**
     * @return list<MiddlewareInterface>
     */
    private function middleware(): array
    {
        if ($this->customMiddleware !== null) {
            return array_values($this->customMiddleware);
        }

        return [
            new CorsMiddleware(),
            new DnsRebindingProtectionMiddleware(
                [$this->resourceHost()],
                $this->psr->responseFactory(),
            ),
            new AuthorizationMiddleware($this->validator, $this->resourceMetadata, $this->psr->responseFactory()),
        ];
    }

    /** The host of the configured resource URL, bracketed for IPv6 exactly as `parse_url` returns it. */
    private function resourceHost(): string
    {
        return (string) parse_url($this->configuration->resource, PHP_URL_HOST);
    }
}
