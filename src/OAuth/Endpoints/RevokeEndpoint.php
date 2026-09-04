<?php

declare(strict_types=1);

namespace VoltCMS\MCP\OAuth\Endpoints;

use League\OAuth2\Server\CryptTrait;
use League\OAuth2\Server\Exception\OAuthServerException;
use VoltCMS\MCP\Configuration;
use VoltCMS\MCP\Http\PsrAdapter;
use VoltCMS\MCP\Http\Request;
use VoltCMS\MCP\Http\Response;
use VoltCMS\MCP\OAuth\Repositories\AccessTokenRepository;
use VoltCMS\MCP\OAuth\Repositories\ClientRepository;
use VoltCMS\MCP\OAuth\Repositories\RefreshTokenRepository;
use VoltCMS\MCP\OAuth\Tokens\AccessTokenVerifier;
use VoltCMS\UserAccess\AuditLog;
use VoltCMS\UserAccess\LoginThrottle;

/**
 * RFC 7009 token revocation — the control SECURITY.md points at, made reachable.
 *
 * league/oauth2-server ships no revocation endpoint, and without one the only way to end a grant
 * is to edit the store by hand. That matters more here than it would elsewhere: access tokens are
 * self-contained JWTs that are not looked up on every request, so the refresh token is the thing
 * whose revocation is immediate. Revoking either end therefore revokes both — see
 * `RefreshTokenRepository::revokeForAccessToken()`.
 *
 * ## Two deliberate deviations from RFC 7009
 *
 * 1. A token that belongs to a DIFFERENT client is answered with 200 and not revoked, where §2.1
 *    would have the request refused. Refusing turns the endpoint into an oracle: an authenticated
 *    client could ask "does this token exist and belong to someone else?" and read the answer off
 *    the status code. Nothing is revoked either way, so the only thing the error would carry is
 *    that fact.
 * 2. `token_type_hint` is read but never trusted. §2.1 allows a server to try the hinted type
 *    first and fall back; this endpoint always tries both, because a wrong hint from a client
 *    would otherwise silently fail to revoke a live credential.
 *
 * The refresh token is decrypted through league's own `CryptTrait` rather than through
 * defuse/php-encryption directly: the ciphertext is league's format, so league should own reading
 * it, and an upgrade that changes the format cannot leave a second decoder behind.
 */
final class RevokeEndpoint extends Endpoint
{
    use CryptTrait;

    public const PARAM_TOKEN = 'token';

    private const THROTTLE_BUCKET = 'mcp.revoke';

    public function __construct(
        Configuration $configuration,
        private readonly ClientRepository $clients,
        private readonly AccessTokenRepository $accessTokens,
        private readonly RefreshTokenRepository $refreshTokens,
        private readonly AccessTokenVerifier $verifier,
        PsrAdapter $psr,
        ?AuditLog $auditLog = null,
        ?LoginThrottle $throttle = null,
    ) {
        parent::__construct($configuration, $psr, $auditLog, $throttle);

        $this->setEncryptionKey($configuration->encryptionKey);
    }

    public function handle(Request $request): Response
    {
        if (!$request->isPost()) {
            return $this->methodNotAllowed('POST');
        }

        $psrRequest = $this->psr->toServerRequest($request);
        [$clientId, $clientSecret] = $this->credentials($request);

        if ($this->isThrottled($request, $clientId)) {
            return $this->tooManyRequests();
        }

        try {
            if ($clientId === '' || !$this->clients->validateClient($clientId, $clientSecret, null)) {
                $this->registerThrottleFailure($request, $clientId);

                throw OAuthServerException::invalidClient($psrRequest);
            }

            $this->resetThrottle($request, $clientId);

            $token = $request->body(self::PARAM_TOKEN);

            if ($token === null || $token === '') {
                throw OAuthServerException::invalidRequest(self::PARAM_TOKEN);
            }

            $this->revoke($token, $clientId);

            // RFC 7009 §2.2: an invalid token is not an error. The client wanted the token gone,
            // and it is gone; saying which of the several reasons applies would only tell a caller
            // things about tokens it does not hold.
            return new Response(Response::STATUS_OK);
        } catch (OAuthServerException $exception) {
            return $this->oauthError($exception, $psrRequest);
        } catch (\Throwable) {
            return $this->serverError();
        }
    }

    protected function throttleBucket(): string
    {
        return self::THROTTLE_BUCKET;
    }

    // --- Revocation ---

    private function revoke(string $token, string $clientId): void
    {
        if ($this->revokeAsRefreshToken($token, $clientId)) {
            return;
        }

        $this->revokeAsAccessToken($token, $clientId);
    }

    /**
     * league's refresh token is a Defuse ciphertext over a JSON payload naming both token
     * identifiers and the client. Decrypting it is the only way to learn any of that.
     */
    private function revokeAsRefreshToken(string $token, string $clientId): bool
    {
        try {
            $payload = json_decode($this->decrypt($token), true, 8, JSON_THROW_ON_ERROR);
        } catch (\Throwable) {
            return false;
        }

        if (!is_array($payload) || !is_string($payload['refresh_token_id'] ?? null)) {
            return false;
        }

        if (!is_string($payload['client_id'] ?? null) || !hash_equals($payload['client_id'], $clientId)) {
            // Somebody else's token. Answered 200 and not revoked; see the class docblock.
            return true;
        }

        $this->refreshTokens->revokeRefreshToken($payload['refresh_token_id']);

        if (is_string($payload['access_token_id'] ?? null)) {
            $this->accessTokens->revokeAccessToken($payload['access_token_id']);
        }

        $this->audit('grant.revoked', [
            'client_id' => $clientId,
            'token_id'  => $payload['refresh_token_id'],
            'presented' => 'refresh_token',
        ]);

        return true;
    }

    private function revokeAsAccessToken(string $token, string $clientId): void
    {
        $claims = $this->verifier->verify($token);

        if ($claims === null || !hash_equals($claims->clientId, $clientId)) {
            return;
        }

        $this->accessTokens->revokeAccessToken($claims->identifier);
        $this->refreshTokens->revokeForAccessToken($claims->identifier);

        $this->audit('grant.revoked', [
            'client_id' => $clientId,
            'token_id'  => $claims->identifier,
            'presented' => 'access_token',
        ]);
    }

    // --- Client authentication ---

    /**
     * @return array{0: string, 1: string|null}
     */
    private function credentials(Request $request): array
    {
        $basic = $request->basicAuthCredentials();

        if ($basic !== null) {
            return [$basic[0], $basic[1]];
        }

        return [$request->body('client_id') ?? '', $request->body('client_secret')];
    }
}
