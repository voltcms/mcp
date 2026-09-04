<?php

declare(strict_types=1);

namespace VoltCMS\MCP\OAuth\Endpoints;

use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Exception\OAuthServerException;
use VoltCMS\MCP\Configuration;
use VoltCMS\MCP\Http\PsrAdapter;
use VoltCMS\MCP\Http\Request;
use VoltCMS\MCP\Http\Response;
use VoltCMS\UserAccess\AuditLog;
use VoltCMS\UserAccess\LoginThrottle;

/**
 * The token endpoint: code for token, and refresh for token.
 *
 * Almost all of this is league's — PKCE verification, single-use codes, refresh rotation, exact
 * redirect URI matching — and deliberately so; PLAN.md §4.7 lists what league already gets right
 * and this package must not undo. What is added here is the frame around it: the method guard, the
 * RFC 8707 target check league knows nothing about, the throttle on repeated failures, the audit
 * record, and the promise that no internal exception message reaches the client.
 *
 * The token this returns is a `ResourceBoundAccessToken`, so its `aud` is the MCP endpoint rather
 * than the client id. That is arranged in `AccessTokenRepository::getNewToken()`; nothing here has
 * to know about it, which is the point.
 */
final class TokenEndpoint extends Endpoint
{
    private const THROTTLE_BUCKET = 'mcp.token';

    public function __construct(
        private readonly AuthorizationServer $server,
        Configuration $configuration,
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

        $psrRequest = $this->psr->toServerRequest($request);
        $clientId   = $request->body('client_id') ?? ($request->basicAuthCredentials()[0] ?? '');

        if ($this->isThrottled($request, $clientId)) {
            return $this->tooManyRequests();
        }

        try {
            $this->resourceIndicator->guard($request->parsedBody);

            $response = $this->psr->fromResponse(
                $this->server->respondToAccessTokenRequest($psrRequest, $this->psr->blankResponse()),
            );

            $this->resetThrottle($request, $clientId);
            $this->audit('token.issued', [
                'client_id'  => $clientId,
                'grant_type' => $request->body('grant_type'),
            ]);

            return $response;
        } catch (OAuthServerException $exception) {
            // Every failure here is a credential failure of some kind — a wrong secret, a replayed
            // code, a verifier that does not match the challenge — so every one counts against the
            // lockout.
            $this->registerThrottleFailure($request, $clientId);
            $this->audit('token.refused', [
                'client_id'  => $clientId,
                'grant_type' => $request->body('grant_type'),
                'error'      => $exception->getErrorType(),
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
}
