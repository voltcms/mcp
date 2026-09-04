<?php

declare(strict_types=1);

namespace VoltCMS\MCP\OAuth\Endpoints;

use League\OAuth2\Server\Exception\OAuthServerException;
use Psr\Http\Message\ServerRequestInterface;
use VoltCMS\MCP\Configuration;
use VoltCMS\MCP\Http\PsrAdapter;
use VoltCMS\MCP\Http\Request;
use VoltCMS\MCP\Http\Response;
use VoltCMS\MCP\OAuth\ResourceIndicator;
use VoltCMS\UserAccess\AuditLog;
use VoltCMS\UserAccess\LoginThrottle;

/**
 * What the three OAuth endpoints share: how a failure becomes a response, and how a probe becomes
 * a lockout.
 *
 * The error rendering is here rather than in each endpoint because getting it wrong is a
 * disclosure bug rather than a cosmetic one. `OAuthServerException` already knows whether its
 * error belongs in a JSON body or in a redirect back to the client, so it renders itself; every
 * OTHER throwable becomes a fixed `server_error` with no message, because an exception from the
 * store, the filesystem or a dependency says things about this deployment that an unauthenticated
 * caller has no business reading.
 *
 * Throttling is bucketed per endpoint so that probing the token endpoint cannot lock a user out of
 * authorizing, and keyed by identifier and peer address through `LoginThrottle` — the same
 * lockout voltcms/useraccess already uses for logins, rather than a second one with its own bugs.
 */
abstract class Endpoint
{
    protected readonly ResourceIndicator $resourceIndicator;

    public function __construct(
        protected readonly Configuration $configuration,
        protected readonly PsrAdapter $psr,
        protected readonly ?AuditLog $auditLog = null,
        protected readonly ?LoginThrottle $throttle = null,
    ) {
        $this->resourceIndicator = new ResourceIndicator($configuration);
    }

    /** Every endpoint is a function from a request to a response. Nothing is emitted. */
    abstract public function handle(Request $request): Response;

    /** The throttle bucket for this endpoint, so one endpoint's failures cannot lock another. */
    abstract protected function throttleBucket(): string;

    // --- Failure rendering ---

    /**
     * league decides the shape: a redirect back to the client when it has a validated redirect
     * URI, a JSON error body when it does not.
     */
    protected function oauthError(OAuthServerException $exception, ServerRequestInterface $psrRequest): Response
    {
        $exception->setServerRequest($psrRequest);

        return $this->psr->fromResponse($exception->generateHttpResponse($this->psr->blankResponse()));
    }

    /**
     * A fixed body. The caught exception is deliberately not consulted: `Never leak an internal
     * message to a client verbatim` is a coding standard here because the alternative publishes
     * store paths and dependency internals to anyone who can reach the endpoint.
     */
    protected function serverError(): Response
    {
        return Response::json([
            'error'             => 'server_error',
            'error_description' => 'The authorization server encountered an unexpected condition.',
        ], Response::STATUS_INTERNAL_ERROR);
    }

    protected function methodNotAllowed(string $allowed): Response
    {
        return Response::json([
            'error'             => 'invalid_request',
            'error_description' => 'This endpoint accepts ' . $allowed . ' only.',
        ], Response::STATUS_METHOD_NOT_ALLOWED, ['Allow' => $allowed]);
    }

    /**
     * RFC 6749 has no status for "too many attempts", so this is 429 carrying the closest error it
     * does define. A client that retries on a schedule gets `Retry-After` to obey.
     */
    protected function tooManyRequests(): Response
    {
        return Response::json([
            'error'             => 'temporarily_unavailable',
            'error_description' => 'Too many failed attempts. Try again later.',
        ], Response::STATUS_TOO_MANY_REQUESTS, ['Retry-After' => '900']);
    }

    // --- Throttling ---

    protected function isThrottled(Request $request, string $identifier): bool
    {
        return $this->throttle?->isLocked($this->throttleKey($request, $identifier)) === true;
    }

    protected function registerThrottleFailure(Request $request, string $identifier): void
    {
        $this->throttle?->registerFailure($this->throttleKey($request, $identifier));
    }

    protected function resetThrottle(Request $request, string $identifier): void
    {
        $this->throttle?->reset($this->throttleKey($request, $identifier));
    }

    private function throttleKey(Request $request, string $identifier): string
    {
        return $this->throttleBucket() . ':' . strtolower(trim($identifier)) . '|' . $request->clientIp;
    }

    // --- Audit ---

    /**
     * @param array<string, scalar|null> $context
     */
    protected function audit(string $event, array $context = []): void
    {
        $this->auditLog?->record(array_merge(['event' => $event], $context));
    }
}
