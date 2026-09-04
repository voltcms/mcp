<?php

declare(strict_types=1);

namespace VoltCMS\MCP;

/**
 * Every value this package needs to issue and validate tokens, stated explicitly and never
 * inferred.
 *
 * The issuer and resource URLs exist here rather than being derived from the incoming request
 * because `$_SERVER['HTTP_HOST']` is attacker-controlled: a forged `Host` header on a request
 * for the RFC 8414 metadata document would otherwise publish an attacker's origin as this
 * application's authorization server, and a resource claim derived the same way would let a
 * token be minted for an audience of the attacker's choosing. This object therefore refuses to
 * construct without both, rather than guessing either. See PLAN.md §4.3.
 *
 * Immutable: build one at the edge of the application and pass it down.
 */
final class Configuration
{
    // --- Defaults ---

    /** Short, because a code is exchanged immediately or not at all. */
    public const DEFAULT_AUTHORIZATION_CODE_TTL = 'PT10M';

    /**
     * One hour, deliberately. Access tokens are self-contained JWTs, so revoking one before it
     * expires is not instant; a short life is what bounds the damage. Revoking the grant kills
     * the refresh path immediately, which is the control that matters. See SECURITY.md.
     */
    public const DEFAULT_ACCESS_TOKEN_TTL = 'PT1H';

    public const DEFAULT_REFRESH_TOKEN_TTL = 'P30D';

    /** A base64-encoded 32-byte key is 44 characters; anything shorter is a typo or a placeholder. */
    public const MINIMUM_ENCRYPTION_KEY_LENGTH = 32;

    // --- Failure codes ---

    public const EXCEPTION_ISSUER_REQUIRED          = 1001;
    public const EXCEPTION_ISSUER_MALFORMED         = 1002;
    public const EXCEPTION_ISSUER_INSECURE          = 1003;
    public const EXCEPTION_RESOURCE_REQUIRED        = 1004;
    public const EXCEPTION_RESOURCE_MALFORMED       = 1005;
    public const EXCEPTION_RESOURCE_INSECURE        = 1006;
    public const EXCEPTION_PATH_REQUIRED            = 1007;
    public const EXCEPTION_PATH_NOT_ABSOLUTE        = 1008;
    public const EXCEPTION_ENCRYPTION_KEY_REQUIRED  = 1009;
    public const EXCEPTION_ENCRYPTION_KEY_TOO_SHORT = 1010;
    public const EXCEPTION_SCOPES_REQUIRED          = 1011;
    public const EXCEPTION_SCOPE_MALFORMED          = 1012;
    public const EXCEPTION_SCOPE_DUPLICATED         = 1013;
    public const EXCEPTION_ENDPOINT_REQUIRED        = 1014;
    public const EXCEPTION_ENDPOINT_MALFORMED       = 1015;
    public const EXCEPTION_ENDPOINT_INSECURE        = 1016;

    /** Hosts for which plain HTTP is tolerated, because there is no transport to secure. */
    private const LOOPBACK_HOSTS = ['localhost', '127.0.0.1', '::1', '[::1]'];

    // --- State ---

    /** Authorization server identifier, without a trailing slash. */
    public readonly string $issuer;

    /** Canonical MCP endpoint URL. This is the `aud` of every access token (RFC 8707). */
    public readonly string $resource;

    /** Root of the flat-file store. Belongs outside the web root. */
    public readonly string $storageDirectory;

    public readonly string $privateKeyPath;
    public readonly string $publicKeyPath;

    /** Passed to league/oauth2-server, which encrypts authorization codes and refresh tokens with it. */
    public readonly string $encryptionKey;

    /** @var list<string> Every scope this server is willing to grant. */
    public readonly array $scopes;

    public readonly \DateInterval $authorizationCodeTtl;
    public readonly \DateInterval $accessTokenTtl;
    public readonly \DateInterval $refreshTokenTtl;

    /** Absolute URL of the authorize endpoint; also the action of the consent form. */
    public readonly string $authorizationEndpoint;

    public readonly string $tokenEndpoint;
    public readonly string $revocationEndpoint;
    public readonly string $jwksUri;

    /** Null when this server does not answer dynamic client registration. See PLAN.md §4.4. */
    public readonly ?string $registrationEndpoint;

    /**
     * @param list<string> $scopes
     *
     * @throws \InvalidArgumentException with one of the EXCEPTION_* codes above.
     */
    public function __construct(
        string $issuer,
        string $resource,
        string $storageDirectory,
        string $privateKeyPath,
        string $publicKeyPath,
        string $encryptionKey,
        array $scopes,
        ?\DateInterval $authorizationCodeTtl = null,
        ?\DateInterval $accessTokenTtl = null,
        ?\DateInterval $refreshTokenTtl = null,
        ?EndpointUrls $endpoints = null,
    ) {
        $this->issuer   = $this->normaliseUrl(
            $issuer,
            self::EXCEPTION_ISSUER_REQUIRED,
            self::EXCEPTION_ISSUER_MALFORMED,
            self::EXCEPTION_ISSUER_INSECURE,
            'Issuer',
        );
        $this->resource = $this->normaliseUrl(
            $resource,
            self::EXCEPTION_RESOURCE_REQUIRED,
            self::EXCEPTION_RESOURCE_MALFORMED,
            self::EXCEPTION_RESOURCE_INSECURE,
            'Resource',
        );

        $this->storageDirectory = $this->normalisePath($storageDirectory, 'Storage directory');
        $this->privateKeyPath   = $this->normalisePath($privateKeyPath, 'Private key path');
        $this->publicKeyPath    = $this->normalisePath($publicKeyPath, 'Public key path');
        $this->encryptionKey    = $this->validateEncryptionKey($encryptionKey);
        $this->scopes           = $this->validateScopes($scopes);

        $this->authorizationCodeTtl = $authorizationCodeTtl ?? new \DateInterval(self::DEFAULT_AUTHORIZATION_CODE_TTL);
        $this->accessTokenTtl       = $accessTokenTtl ?? new \DateInterval(self::DEFAULT_ACCESS_TOKEN_TTL);
        $this->refreshTokenTtl      = $refreshTokenTtl ?? new \DateInterval(self::DEFAULT_REFRESH_TOKEN_TTL);

        $endpoints = $endpoints ?? EndpointUrls::below($this->issuer);

        $this->authorizationEndpoint = $this->normaliseEndpoint($endpoints->authorization, 'Authorization endpoint');
        $this->tokenEndpoint         = $this->normaliseEndpoint($endpoints->token, 'Token endpoint');
        $this->revocationEndpoint    = $this->normaliseEndpoint($endpoints->revocation, 'Revocation endpoint');
        $this->jwksUri               = $this->normaliseEndpoint($endpoints->jwks, 'JWKS URI');
        $this->registrationEndpoint  = $endpoints->registration === null
            ? null
            : $this->normaliseEndpoint($endpoints->registration, 'Registration endpoint');
    }

    public function scopeIsSupported(string $scope): bool
    {
        return in_array($scope, $this->scopes, true);
    }

    // --- Validation ---

    /** Endpoint URLs answer to the same rules as the issuer; only the failure codes differ. */
    private function normaliseEndpoint(string $url, string $label): string
    {
        return $this->normaliseUrl(
            $url,
            self::EXCEPTION_ENDPOINT_REQUIRED,
            self::EXCEPTION_ENDPOINT_MALFORMED,
            self::EXCEPTION_ENDPOINT_INSECURE,
            $label,
        );
    }

    /**
     * An absolute https URL with no credentials, query or fragment, and no trailing slash.
     *
     * Plain http is accepted only for loopback hosts, where there is no network to intercept
     * and requiring a certificate would make local development impossible.
     */
    private function normaliseUrl(
        string $url,
        int $requiredCode,
        int $malformedCode,
        int $insecureCode,
        string $label,
    ): string {
        $url = trim($url);

        if ($url === '') {
            throw new \InvalidArgumentException(
                $label . ' URL is required and must be configured explicitly, never derived from a request header.',
                $requiredCode,
            );
        }

        $parts = parse_url($url);

        if ($parts === false || !isset($parts['scheme'], $parts['host']) || $parts['host'] === '') {
            throw new \InvalidArgumentException(
                $label . ' URL must be absolute and include a scheme and a host.',
                $malformedCode,
            );
        }

        if (isset($parts['user']) || isset($parts['pass']) || isset($parts['query']) || isset($parts['fragment'])) {
            throw new \InvalidArgumentException(
                $label . ' URL must not carry credentials, a query string or a fragment.',
                $malformedCode,
            );
        }

        $scheme = strtolower($parts['scheme']);

        if ($scheme !== 'https' && !($scheme === 'http' && $this->isLoopback($parts['host']))) {
            throw new \InvalidArgumentException(
                $label . ' URL must use https; plain http is accepted only for loopback hosts.',
                $insecureCode,
            );
        }

        return rtrim($url, '/');
    }

    private function isLoopback(string $host): bool
    {
        return in_array(strtolower($host), self::LOOPBACK_HOSTS, true);
    }

    /**
     * Absolute filesystem paths only: a relative path resolves against the working directory,
     * which differs between the web entry point and the command line, and a store that moves
     * with the working directory is a store that silently loses grants.
     */
    private function normalisePath(string $path, string $label): string
    {
        $path = trim($path);

        if ($path === '') {
            throw new \InvalidArgumentException($label . ' is required.', self::EXCEPTION_PATH_REQUIRED);
        }

        if (!str_starts_with($path, '/') && preg_match('#^[A-Za-z]:[\\\\/]#', $path) !== 1) {
            throw new \InvalidArgumentException(
                $label . ' must be an absolute filesystem path.',
                self::EXCEPTION_PATH_NOT_ABSOLUTE,
            );
        }

        return rtrim($path, '/\\') === '' ? $path : rtrim($path, '/\\');
    }

    private function validateEncryptionKey(string $encryptionKey): string
    {
        if ($encryptionKey === '') {
            throw new \InvalidArgumentException(
                'An encryption key is required; league/oauth2-server encrypts authorization codes with it.',
                self::EXCEPTION_ENCRYPTION_KEY_REQUIRED,
            );
        }

        if (strlen($encryptionKey) < self::MINIMUM_ENCRYPTION_KEY_LENGTH) {
            throw new \InvalidArgumentException(
                'The encryption key is too short; use a base64-encoded 32-byte key.',
                self::EXCEPTION_ENCRYPTION_KEY_TOO_SHORT,
            );
        }

        return $encryptionKey;
    }

    /**
     * @param list<string> $scopes
     *
     * @return list<string>
     */
    private function validateScopes(array $scopes): array
    {
        if ($scopes === []) {
            throw new \InvalidArgumentException(
                'At least one scope must be configured; a server that grants nothing cannot be consented to.',
                self::EXCEPTION_SCOPES_REQUIRED,
            );
        }

        $validated = [];

        foreach ($scopes as $scope) {
            // RFC 6749 scope-token: printable ASCII without space, double quote or backslash.
            if (!is_string($scope) || preg_match('/^[\x21\x23-\x5B\x5D-\x7E]+$/', $scope) !== 1) {
                throw new \InvalidArgumentException(
                    'Scope names must be non-empty printable ASCII without spaces, quotes or backslashes.',
                    self::EXCEPTION_SCOPE_MALFORMED,
                );
            }

            if (in_array($scope, $validated, true)) {
                throw new \InvalidArgumentException(
                    'Scope "' . $scope . '" is configured more than once.',
                    self::EXCEPTION_SCOPE_DUPLICATED,
                );
            }

            $validated[] = $scope;
        }

        return $validated;
    }
}
