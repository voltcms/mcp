<?php

declare(strict_types=1);

namespace VoltCMS\MCP\OAuth\Endpoints;

use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\RequestTypes\AuthorizationRequestInterface;
use Psr\Http\Message\ServerRequestInterface;
use VoltCMS\MCP\Configuration;
use VoltCMS\MCP\Contracts\ConsentViewInterface;
use VoltCMS\MCP\Contracts\IdentityProviderInterface;
use VoltCMS\MCP\Contracts\LoginRedirectorInterface;
use VoltCMS\MCP\Contracts\ScopePolicyInterface;
use VoltCMS\MCP\Http\PsrAdapter;
use VoltCMS\MCP\Http\Request;
use VoltCMS\MCP\Http\Response;
use VoltCMS\MCP\Identity\Identity;
use VoltCMS\MCP\OAuth\Consent\ConsentRequest;
use VoltCMS\MCP\OAuth\Consent\ConsentTicketSigner;
use VoltCMS\MCP\OAuth\Entities\Scope;
use VoltCMS\MCP\OAuth\Entities\User;
use VoltCMS\UserAccess\AuditLog;
use VoltCMS\UserAccess\LoginThrottle;

/**
 * The authorization endpoint: the S256-only guard, the login seam and the consent seam.
 *
 * ## Why the PKCE guard is here and not left to league
 *
 * `AuthCodeGrant::__construct()` registers a `PlainVerifier` next to the `S256Verifier`,
 * `private array $codeChallengeVerifiers` is unreachable from a subclass, and the only PKCE-related
 * public method — `disableRequireCodeChallengeForPublicClients()` — *weakens* the requirement.
 * Worse, `validateAuthorizationRequest()` reads the method with a default:
 *
 *     $codeChallengeMethod = $this->getQueryStringParameter('code_challenge_method', $request, 'plain');
 *
 * so a challenge sent with no method at all is treated as `plain`, and a `plain` challenge was
 * **accepted** in the spike. `plain` puts the verifier on the wire in the authorization request,
 * which is exactly what PKCE exists to avoid.
 *
 * This endpoint therefore refuses anything but `S256`, and refuses a missing challenge outright —
 * league only requires one for public clients, while OAuth 2.1 and the MCP specification require
 * it of every client. Both checks run BEFORE the request is handed to league, so no code is ever
 * minted from a challenge league would have accepted. See PLAN.md §4.1.
 *
 * **Do not simplify this away**, and do not relax its tests: they are the tripwire that fires if a
 * league upgrade changes the constructor underneath us.
 *
 * ## The seams
 *
 * Not logged in goes to `LoginRedirectorInterface`; a request that needs approving goes to
 * `ConsentViewInterface`. Neither interface is about security — the package decides when to ask
 * and what is being asked, and binds the answer with a signed ticket (see `ConsentTicketSigner`).
 *
 * The scopes shown and granted are the requested ones narrowed to what the user's roles support,
 * never the requested ones as sent: a consent screen that offers more than the token will carry
 * asks the user to approve a fiction.
 */
final class AuthorizeEndpoint extends Endpoint
{
    public const PARAM_CODE_CHALLENGE        = 'code_challenge';
    public const PARAM_CODE_CHALLENGE_METHOD = 'code_challenge_method';

    /** The only code challenge method this server will accept. There is no second entry. */
    public const CODE_CHALLENGE_METHOD = 'S256';

    private const THROTTLE_BUCKET = 'mcp.authorize';

    public function __construct(
        private readonly AuthorizationServer $server,
        Configuration $configuration,
        private readonly IdentityProviderInterface $identities,
        private readonly ScopePolicyInterface $scopePolicy,
        private readonly ConsentViewInterface $consentView,
        private readonly LoginRedirectorInterface $loginRedirector,
        private readonly ConsentTicketSigner $tickets,
        PsrAdapter $psr,
        ?AuditLog $auditLog = null,
        ?LoginThrottle $throttle = null,
    ) {
        parent::__construct($configuration, $psr, $auditLog, $throttle);
    }

    public function handle(Request $request): Response
    {
        $psrRequest = $this->psr->toServerRequest($request);
        $clientId   = $request->query('client_id') ?? '';

        if ($this->isThrottled($request, $clientId)) {
            return $this->tooManyRequests();
        }

        try {
            return $this->authorize($request, $psrRequest);
        } catch (OAuthServerException $exception) {
            $this->registerThrottleFailure($request, $clientId);
            $this->audit('authorize.refused', [
                'client_id' => $clientId,
                'error'     => $exception->getErrorType(),
            ]);

            return $this->oauthError($exception, $psrRequest);
        } catch (\Throwable) {
            return $this->serverError();
        }
    }

    protected function throttleBucket(): string
    {
        return self::THROTTLE_BUCKET;
    }

    // --- The flow ---

    /**
     * @throws OAuthServerException
     */
    private function authorize(Request $request, ServerRequestInterface $psrRequest): Response
    {
        $this->guardCodeChallenge($request);
        $this->resourceIndicator->guard($request->queryParams);

        $authRequest = $this->server->validateAuthorizationRequest($psrRequest);

        $identity = $this->identities->currentUser($request);

        if ($identity === null) {
            // Not an error: the visitor has simply not logged in yet. The consumer sends them to
            // its own login page and brings them back to this same URL, query string intact.
            return $this->loginRedirector->redirectToLogin($request);
        }

        $granted = $this->grantableScopes($authRequest, $identity);

        $authRequest->setUser(new User($identity->identifier));
        $authRequest->setScopes(array_map(static fn (string $scope): Scope => new Scope($scope), $granted));

        $binding  = $this->binding($authRequest, $identity, $granted);
        $decision = $this->decision($request, $binding);

        if ($decision === null) {
            return $this->consentView->render($this->consentRequest($request, $authRequest, $identity, $granted, $binding));
        }

        $authRequest->setAuthorizationApproved($decision);

        $this->audit($decision ? 'authorize.approved' : 'authorize.denied', [
            'client_id' => $authRequest->getClient()->getIdentifier(),
            'user_id'   => $identity->identifier,
            'scopes'    => implode(' ', $granted),
        ]);

        $this->resetThrottle($request, $authRequest->getClient()->getIdentifier());

        // A denial throws accessDenied carrying the client's redirect URI, which handle() renders
        // as the redirect RFC 6749 §4.1.2.1 asks for.
        return $this->psr->fromResponse(
            $this->server->completeAuthorizationRequest($authRequest, $this->psr->blankResponse()),
        );
    }

    // --- The S256 guard ---

    /**
     * @throws OAuthServerException
     */
    private function guardCodeChallenge(Request $request): void
    {
        $challenge = $request->query(self::PARAM_CODE_CHALLENGE);

        if ($challenge === null || $challenge === '') {
            throw OAuthServerException::invalidRequest(
                self::PARAM_CODE_CHALLENGE,
                'PKCE is required for every client, confidential ones included.',
            );
        }

        $method = $request->query(self::PARAM_CODE_CHALLENGE_METHOD);

        if ($method === null || $method === '') {
            // RFC 7636 §4.3 defaults an absent method to `plain`, and league implements that
            // default. Requiring the parameter is what stops the default from being reached.
            throw OAuthServerException::invalidRequest(
                self::PARAM_CODE_CHALLENGE_METHOD,
                'code_challenge_method must be sent explicitly, and must be S256.',
            );
        }

        if ($method !== self::CODE_CHALLENGE_METHOD) {
            throw OAuthServerException::invalidRequest(
                self::PARAM_CODE_CHALLENGE_METHOD,
                'S256 is the only code challenge method this server accepts.',
            );
        }
    }

    // --- Scopes ---

    /**
     * The requested scopes, narrowed to what this user's roles support.
     *
     * A client that names no scope is treated as asking for everything it could have, which is
     * what league's `defaultScope` would do less visibly.
     *
     * @return list<string>
     *
     * @throws OAuthServerException if nothing is left to grant.
     */
    private function grantableScopes(AuthorizationRequestInterface $authRequest, Identity $identity): array
    {
        $requested = array_map(
            static fn (ScopeEntityInterface $scope): string => $scope->getIdentifier(),
            $authRequest->getScopes(),
        );

        $grantable = $this->scopePolicy->grantableFor($identity);

        if ($requested === []) {
            $requested = $grantable;
        }

        $granted = array_values(array_filter(
            $requested,
            fn (string $scope): bool => in_array($scope, $grantable, true) && $this->configuration->scopeIsSupported($scope),
        ));

        if ($granted === []) {
            throw OAuthServerException::invalidScope(
                implode(' ', $requested),
                $this->redirectUriWithState($authRequest),
            );
        }

        return $granted;
    }

    // --- Consent ---

    /**
     * The value the consent ticket is signed over. Every field is one an attacker would have to
     * change to turn an approval of something harmless into an approval of something else.
     *
     * @param list<string> $granted
     *
     * @return array<string, mixed>
     */
    private function binding(AuthorizationRequestInterface $authRequest, Identity $identity, array $granted): array
    {
        return [
            'client_id'      => $authRequest->getClient()->getIdentifier(),
            'code_challenge' => $authRequest->getCodeChallenge(),
            'redirect_uri'   => $authRequest->getRedirectUri(),
            'resource'       => $this->configuration->resource,
            'scopes'         => $granted,
            'state'          => $authRequest->getState(),
            'user_id'        => $identity->identifier,
        ];
    }

    /**
     * Null means "nobody has answered yet, show the form". A POST whose ticket does not verify is
     * deliberately treated the same way: an expired ticket and a forged cross-site submission are
     * indistinguishable from here, and re-rendering the form is the right answer to both.
     *
     * @param array<string, mixed> $binding
     */
    private function decision(Request $request, array $binding): ?bool
    {
        if (!$request->isPost()) {
            return null;
        }

        $ticket = $request->body(ConsentRequest::FIELD_TICKET);

        if ($ticket === null || !$this->tickets->verify($ticket, $binding)) {
            return null;
        }

        return $request->body(ConsentRequest::FIELD_DECISION) === ConsentRequest::DECISION_APPROVE;
    }

    /**
     * @param list<string>         $granted
     * @param array<string, mixed> $binding
     */
    private function consentRequest(
        Request $request,
        AuthorizationRequestInterface $authRequest,
        Identity $identity,
        array $granted,
        array $binding,
    ): ConsentRequest {
        $client = $authRequest->getClient();

        return new ConsentRequest(
            $client->getIdentifier(),
            $client->getName(),
            $authRequest->getRedirectUri() ?? $this->registeredRedirectUri($authRequest) ?? '',
            $granted,
            $identity,
            $this->formAction($request),
            [ConsentRequest::FIELD_TICKET => $this->tickets->issue($binding)],
        );
    }

    /**
     * The configured authorize URL carrying this authorization request in its query string, so the
     * form needs no hidden field per parameter and the POST re-validates from the same input the
     * GET did. The host comes from Configuration and never from the request. See PLAN.md §4.3.
     */
    private function formAction(Request $request): string
    {
        $query = http_build_query($request->queryParams, '', '&', PHP_QUERY_RFC3986);

        return $query === ''
            ? $this->configuration->authorizationEndpoint
            : $this->configuration->authorizationEndpoint . '?' . $query;
    }

    // --- Helpers ---

    /** The redirect URI an error should go back to, with `state` already attached. */
    private function redirectUriWithState(AuthorizationRequestInterface $authRequest): ?string
    {
        $redirectUri = $authRequest->getRedirectUri() ?? $this->registeredRedirectUri($authRequest);
        $state       = $authRequest->getState();

        if ($redirectUri === null || $state === null) {
            return $redirectUri;
        }

        return $redirectUri . (str_contains($redirectUri, '?') ? '&' : '?') . http_build_query(['state' => $state]);
    }

    private function registeredRedirectUri(AuthorizationRequestInterface $authRequest): ?string
    {
        $registered = $authRequest->getClient()->getRedirectUri();

        if (is_string($registered)) {
            return $registered === '' ? null : $registered;
        }

        return $registered[0] ?? null;
    }
}
