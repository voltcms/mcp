<?php

declare(strict_types=1);

namespace VoltCMS\MCP;

/**
 * Where this server's OAuth endpoints answer, as absolute URLs.
 *
 * They are needed twice over: the RFC 8414 metadata document publishes them, and the consent
 * form has to POST somewhere. Both are absolute, and neither may be derived from the request —
 * a forged `Host` would publish an attacker's origin as the token endpoint, which is the whole
 * of PLAN.md §4.3 applied one level down.
 *
 * This is a carrier, not a validator: `Configuration` canonicalises every URL below through the
 * same rules it applies to the issuer, so there is one definition of "an acceptable URL" in the
 * package rather than two that can drift.
 *
 * Immutable.
 */
final class EndpointUrls
{
    public const DEFAULT_PREFIX = '/oauth';

    public readonly string $authorization;
    public readonly string $token;
    public readonly string $revocation;
    public readonly string $jwks;

    /** Null when this server does not answer dynamic client registration. See PLAN.md §4.4. */
    public readonly ?string $registration;

    public function __construct(
        string $authorization,
        string $token,
        string $revocation,
        string $jwks,
        ?string $registration = null,
    ) {
        $this->authorization = $authorization;
        $this->token         = $token;
        $this->revocation    = $revocation;
        $this->jwks          = $jwks;
        $this->registration  = $registration;
    }

    /**
     * The conventional layout: every endpoint under one prefix on the issuer's origin. A
     * deployment that routes differently constructs this class directly instead.
     *
     * Registration is off unless asked for, and the default is the interesting part. An open
     * registration endpoint is an unauthenticated write endpoint on the credential store, and
     * Client ID Metadata Documents do the same job — accepting a client this server has never met
     * — without one. A deployment that has a reason for dynamic registration passes
     * `withRegistration: true` and takes that on knowingly. See
     * docs/decisions/0006-who-answers-registration.md.
     */
    public static function below(
        string $issuer,
        string $prefix = self::DEFAULT_PREFIX,
        bool $withRegistration = false,
    ): self {
        $base = rtrim($issuer, '/') . '/' . trim($prefix, '/');

        return new self(
            $base . '/authorize',
            $base . '/token',
            $base . '/revoke',
            $base . '/jwks',
            $withRegistration ? $base . '/register' : null,
        );
    }
}
