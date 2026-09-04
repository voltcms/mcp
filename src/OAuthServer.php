<?php

declare(strict_types=1);

namespace VoltCMS\MCP;

use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Grant\AuthCodeGrant;
use League\OAuth2\Server\Grant\RefreshTokenGrant;
use VoltCMS\MCP\Contracts\ConsentViewInterface;
use VoltCMS\MCP\Contracts\IdentityProviderInterface;
use VoltCMS\MCP\Contracts\LoginRedirectorInterface;
use VoltCMS\MCP\Contracts\ScopePolicyInterface;
use VoltCMS\MCP\Http\PsrAdapter;
use VoltCMS\MCP\Http\Request;
use VoltCMS\MCP\Http\Response;
use VoltCMS\MCP\OAuth\Clients\ClientIdMetadataFetcherInterface;
use VoltCMS\MCP\OAuth\Clients\ClientIdMetadataResolver;
use VoltCMS\MCP\OAuth\Clients\ManualRegistration;
use VoltCMS\MCP\OAuth\Consent\ConsentTicketSigner;
use VoltCMS\MCP\OAuth\Endpoints\AuthorizeEndpoint;
use VoltCMS\MCP\OAuth\Endpoints\MetadataEndpoint;
use VoltCMS\MCP\OAuth\Endpoints\RegisterEndpoint;
use VoltCMS\MCP\OAuth\Endpoints\RevokeEndpoint;
use VoltCMS\MCP\OAuth\Endpoints\TokenEndpoint;
use VoltCMS\MCP\OAuth\Keys\JwksEndpoint;
use VoltCMS\MCP\OAuth\Keys\KeyManager;
use VoltCMS\MCP\OAuth\Repositories\AccessTokenRepository;
use VoltCMS\MCP\OAuth\Repositories\AuthCodeRepository;
use VoltCMS\MCP\OAuth\Repositories\ClientRepository;
use VoltCMS\MCP\OAuth\Repositories\RefreshTokenRepository;
use VoltCMS\MCP\OAuth\Repositories\ScopeRepository;
use VoltCMS\MCP\OAuth\Tokens\AccessTokenVerifier;
use VoltCMS\UserAccess\AuditLog;
use VoltCMS\UserAccess\LoginThrottle;

/**
 * The whole authorization server, assembled: five endpoints, six repositories, two league grants
 * and a keypair, from a Configuration and the two seams a consuming application fills.
 *
 * Nothing here is new behaviour — every guarantee lives in the class that implements it. What this
 * saves a consumer is the thirty lines of wiring in between, which are the lines where an
 * integration quietly goes wrong: a grant enabled with the wrong TTL, a repository built against a
 * different storage directory, a token verifier pointed at a key the server does not sign with.
 * Assembling them once, here, is the difference between a package and a tutorial.
 *
 * Every method is `Request` in, `Response` out. Nothing is emitted; route to these and emit the
 * result however the application already emits.
 *
 * ```php
 * $oauth = new OAuthServer($configuration, $identities, $scopePolicy, $consentView, $login);
 *
 * match ($path) {
 *     '/oauth/authorize' => $oauth->authorize($request),
 *     '/oauth/token'     => $oauth->token($request),
 *     '/oauth/revoke'    => $oauth->revoke($request),
 *     '/oauth/jwks'      => $oauth->jwks($request),
 *     MetadataEndpoint::WELL_KNOWN_PATH => $oauth->metadata($request),
 * };
 * ```
 */
final class OAuthServer
{
    private readonly AuthorizationServer $server;
    private readonly KeyManager $keyManager;
    private readonly ClientRepository $clientRepository;
    private readonly AccessTokenRepository $accessTokenRepository;
    private readonly RefreshTokenRepository $refreshTokenRepository;

    private readonly AuthorizeEndpoint $authorizeEndpoint;
    private readonly TokenEndpoint $tokenEndpoint;
    private readonly RevokeEndpoint $revokeEndpoint;
    private readonly MetadataEndpoint $metadataEndpoint;
    private readonly JwksEndpoint $jwksEndpoint;
    private readonly ?RegisterEndpoint $registerEndpoint;
    private readonly ClientIdMetadataResolver $clientMetadata;

    public function __construct(
        private readonly Configuration $configuration,
        IdentityProviderInterface $identities,
        ScopePolicyInterface $scopePolicy,
        ConsentViewInterface $consentView,
        LoginRedirectorInterface $loginRedirector,
        ?AuditLog $auditLog = null,
        ?LoginThrottle $throttle = null,
        ?KeyManager $keyManager = null,
        ?PsrAdapter $psr = null,
        ?ClientIdMetadataFetcherInterface $clientMetadataFetcher = null,
    ) {
        $psr = $psr ?? new PsrAdapter();

        $this->keyManager = $keyManager ?? new KeyManager($configuration);
        $this->keyManager->ensureKeyPair();

        $this->clientMetadata         = new ClientIdMetadataResolver($configuration, $clientMetadataFetcher, $auditLog);
        $this->clientRepository       = new ClientRepository($configuration, $auditLog, $this->clientMetadata);
        $this->accessTokenRepository  = new AccessTokenRepository($configuration, $auditLog, $this->keyManager);
        $this->refreshTokenRepository = new RefreshTokenRepository($configuration, $auditLog);

        $this->server = new AuthorizationServer(
            $this->clientRepository,
            $this->accessTokenRepository,
            new ScopeRepository($configuration),
            $this->keyManager->privateKey(),
            $configuration->encryptionKey,
        );

        // Both grants get the configured TTLs explicitly. league defaults the refresh token to one
        // month inside AuthCodeGrant's constructor, which is not necessarily what was configured.
        $authCodeGrant = new AuthCodeGrant(
            new AuthCodeRepository($configuration, $auditLog),
            $this->refreshTokenRepository,
            $configuration->authorizationCodeTtl,
        );
        $authCodeGrant->setRefreshTokenTTL($configuration->refreshTokenTtl);
        $this->server->enableGrantType($authCodeGrant, $configuration->accessTokenTtl);

        $refreshGrant = new RefreshTokenGrant($this->refreshTokenRepository);
        $refreshGrant->setRefreshTokenTTL($configuration->refreshTokenTtl);
        $this->server->enableGrantType($refreshGrant, $configuration->accessTokenTtl);

        $this->authorizeEndpoint = new AuthorizeEndpoint(
            $this->server,
            $configuration,
            $identities,
            $scopePolicy,
            $consentView,
            $loginRedirector,
            new ConsentTicketSigner($configuration->encryptionKey),
            $psr,
            $auditLog,
            $throttle,
        );

        $this->tokenEndpoint = new TokenEndpoint($this->server, $configuration, $psr, $auditLog, $throttle);

        $this->revokeEndpoint = new RevokeEndpoint(
            $configuration,
            $this->clientRepository,
            $this->accessTokenRepository,
            $this->refreshTokenRepository,
            $this->accessTokenVerifier(),
            $psr,
            $auditLog,
            $throttle,
        );

        $this->metadataEndpoint = new MetadataEndpoint($configuration, $psr);
        $this->jwksEndpoint     = new JwksEndpoint($configuration, $this->keyManager, $psr);

        // Built only when the deployment configured a registration URL. Nothing advertises the
        // endpoint otherwise, and `register()` answers as if it were not routed — which it is not.
        $this->registerEndpoint = $configuration->registrationEndpoint === null
            ? null
            : new RegisterEndpoint($configuration, $this->registrations(), $psr, $auditLog, $throttle);
    }

    // --- Endpoints ---

    public function authorize(Request $request): Response
    {
        return $this->authorizeEndpoint->handle($request);
    }

    public function token(Request $request): Response
    {
        return $this->tokenEndpoint->handle($request);
    }

    public function revoke(Request $request): Response
    {
        return $this->revokeEndpoint->handle($request);
    }

    /** RFC 8414, served at `MetadataEndpoint::WELL_KNOWN_PATH`. */
    public function metadata(Request $request): Response
    {
        return $this->metadataEndpoint->handle($request);
    }

    public function jwks(Request $request): Response
    {
        return $this->jwksEndpoint->handle($request);
    }

    /**
     * RFC 7591 dynamic registration, if this deployment asked for it. If it did not, this answers
     * exactly as an unrouted path would — there is no endpoint here, and saying so is the honest
     * response to a client that guessed the URL.
     */
    public function register(Request $request): Response
    {
        return $this->registerEndpoint?->handle($request) ?? Response::json([
            'error'             => 'invalid_request',
            'error_description' => 'This server does not offer dynamic client registration.',
        ], Response::STATUS_NOT_FOUND);
    }

    // --- Collaborators ---

    /**
     * Register or deactivate clients. Until dynamic registration lands, this is how a client gets
     * into the store.
     */
    public function clients(): ClientRepository
    {
        return $this->clientRepository;
    }

    public function keys(): KeyManager
    {
        return $this->keyManager;
    }

    /** Register or deactivate a client from a script, which for most deployments is all that is needed. */
    public function registrations(): ManualRegistration
    {
        return new ManualRegistration($this->clientRepository);
    }

    /** The Client ID Metadata Document cache, for a deployment that wants to drop an entry. */
    public function clientMetadata(): ClientIdMetadataResolver
    {
        return $this->clientMetadata;
    }

    /**
     * A verifier pointed at the keys this server actually signs with, for the MCP side of the
     * application. Built fresh so a rotation between requests is picked up.
     */
    public function accessTokenVerifier(): AccessTokenVerifier
    {
        return new AccessTokenVerifier(
            $this->configuration->issuer,
            $this->configuration->resource,
            $this->keyManager->verificationKeys(),
        );
    }

    public function accessTokens(): AccessTokenRepository
    {
        return $this->accessTokenRepository;
    }

    public function refreshTokens(): RefreshTokenRepository
    {
        return $this->refreshTokenRepository;
    }

    /**
     * Delete expired records from every collection. Nothing calls this on a schedule — a flat-file
     * deployment has no daemon — so a consumer runs it from cron, or occasionally on write.
     *
     * @return int Number of records deleted.
     */
    public function purgeExpired(?\DateTimeImmutable $now = null): int
    {
        $now = $now ?? new \DateTimeImmutable();

        return $this->accessTokenRepository->purgeExpired($now)
            + $this->refreshTokenRepository->purgeExpired($now)
            + (new AuthCodeRepository($this->configuration))->purgeExpired($now)
            + $this->clientMetadata->purgeExpired($now)
            + $this->keyManager->purgeRetiredKeys($now);
    }
}
