<?php

declare(strict_types=1);

namespace VoltCMS\MCP\OAuth\Endpoints;

use VoltCMS\MCP\Configuration;
use VoltCMS\MCP\Http\PsrAdapter;
use VoltCMS\MCP\Http\Request;
use VoltCMS\MCP\Http\Response;
use VoltCMS\MCP\OAuth\Clients\ClientIdMetadataDocument;
use VoltCMS\MCP\OAuth\Clients\ManualRegistration;
use VoltCMS\UserAccess\AuditLog;
use VoltCMS\UserAccess\LoginThrottle;

/**
 * RFC 7591 dynamic client registration — off unless a deployment asks for it.
 *
 * Two things about this endpoint are unusual, and both are deliberate.
 *
 * **It is opt-in.** `EndpointUrls::below()` does not give it a URL, `Configuration` leaves
 * `registrationEndpoint` null, the RFC 8414 metadata does not advertise it, and `OAuthServer`
 * answers 404 for it. An open registration endpoint is an unauthenticated write endpoint on a
 * personal site's credential store: anyone who can reach it can fill the disk with clients, and
 * nothing about the flat-file design makes that cheap to survive. Client ID Metadata Documents do
 * the same job — accepting a client this server has never met — without one. See
 * docs/decisions/0006-who-answers-registration.md.
 *
 * **`mcp/sdk` also ships a registration middleware, and it is not installed.** Exactly one thing
 * may answer, and the SDK's belongs to its OAuth-proxy story: it registers a client with an
 * UPSTREAM identity provider and rewrites the authorization-server metadata document on the way
 * out. Here there is no upstream — this package is the authorization server — and the metadata
 * document is rendered from `Configuration` by `MetadataEndpoint`. Installing both would give one
 * document two authors.
 *
 * Every client registered here is public and secret-less, for the same reason a CIMD client is: a
 * secret handed out to whoever asked is not a secret, and PKCE is what authenticates these clients.
 */
final class RegisterEndpoint extends Endpoint
{
    public const EXCEPTION_INVALID_METADATA = 10401;

    public const ERROR_INVALID_METADATA = 'invalid_client_metadata';

    public const STATUS_CREATED = 201;

    /** RFC 7591 §2: the fields this server reads. Anything else in the request is ignored, not refused. */
    public const FIELD_REDIRECT_URIS = 'redirect_uris';
    public const FIELD_CLIENT_NAME   = 'client_name';

    private const THROTTLE_BUCKET = 'mcp.register';

    public function __construct(
        Configuration $configuration,
        private readonly ManualRegistration $registration,
        PsrAdapter $psr,
        ?AuditLog $auditLog = null,
        ?LoginThrottle $throttle = null,
    ) {
        parent::__construct($configuration, $psr, $auditLog, $throttle);
    }

    public function handle(Request $request): Response
    {
        if (!$request->isPost()) {
            return $this->methodNotAllowed('POST');
        }

        // Keyed on the peer alone: there is no client yet, which is the whole problem with this
        // endpoint and the reason the throttle matters more here than anywhere else.
        if ($this->isThrottled($request, '')) {
            return $this->tooManyRequests();
        }

        try {
            $metadata = $this->metadata($request);
            $client   = $this->registration->registerPublic(
                is_string($metadata[self::FIELD_CLIENT_NAME] ?? null) ? $metadata[self::FIELD_CLIENT_NAME] : '',
                $this->redirectUris($metadata),
            );
        } catch (\InvalidArgumentException $exception) {
            $this->registerThrottleFailure($request, '');

            return $this->invalidMetadata($exception->getMessage());
        } catch (\Throwable) {
            return $this->serverError();
        }

        $this->audit('client.registered', ['client_id' => $client->getIdentifier(), 'source' => 'dcr']);

        // RFC 7591 §3.2.1: 201, the issued identifier, and every metadata field the server settled.
        return Response::json([
            'client_id'                  => $client->getIdentifier(),
            'client_id_issued_at'        => time(),
            'client_name'                => $client->getName(),
            'redirect_uris'              => $client->getRedirectUri(),
            'grant_types'                => $client->grantTypes(),
            'response_types'             => ['code'],
            'token_endpoint_auth_method' => ClientIdMetadataDocument::AUTH_METHOD,
        ], self::STATUS_CREATED);
    }

    protected function throttleBucket(): string
    {
        return self::THROTTLE_BUCKET;
    }

    // --- Input ---

    /**
     * @return array<string, mixed>
     */
    private function metadata(Request $request): array
    {
        if ($request->rawBody !== '') {
            $decoded = json_decode($request->rawBody, true, 16);

            if (!is_array($decoded)) {
                throw new \InvalidArgumentException('The registration request must be a JSON object.');
            }

            return $decoded;
        }

        return $request->parsedBody;
    }

    /**
     * Validated through `ClientIdMetadataDocument`, so a registered client and a client identified
     * by a metadata document are held to exactly the same rules — https, no fragment, loopback http
     * only. Two sets of rules would be two chances to get one of them wrong.
     *
     * @param array<string, mixed> $metadata
     *
     * @return list<string>
     */
    private function redirectUris(array $metadata): array
    {
        $identifier = 'urn:voltcms:mcp:registration';

        return ClientIdMetadataDocument::fromDocument([
            'client_id'     => $identifier,
            'redirect_uris' => $metadata[self::FIELD_REDIRECT_URIS] ?? null,
        ], $identifier)->redirectUris;
    }

    private function invalidMetadata(string $description): Response
    {
        return Response::json([
            'error'             => self::ERROR_INVALID_METADATA,
            'error_description' => $description,
        ], Response::STATUS_BAD_REQUEST);
    }
}
