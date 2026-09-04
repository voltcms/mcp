<?php

declare(strict_types=1);

namespace VoltCMS\MCP\OAuth\Consent;

/**
 * Binds a consent decision to the request it was shown for, without a session and without a store.
 *
 * The problem this solves is ordinary CSRF, with an unusually bad outcome: the authorize endpoint
 * completes on a POST, so any page the user visits while logged in could auto-submit an approval
 * and walk away with an authorization code. A per-form token is the usual answer, but it needs
 * somewhere to live, and this package has no session of its own and no daemon to expire one.
 *
 * So the ticket carries no state: it is an expiry and an HMAC over the binding — the user, the
 * client, the redirect URI, the granted scopes, the code challenge and the state. The endpoint
 * recomputes that binding from the request it is actually handling and compares. A ticket
 * therefore approves exactly one authorization request for exactly one user, expires on its own,
 * and cannot be minted by anyone who does not hold the signing key.
 *
 * The key is the configured encryption key, which league already uses to protect authorization
 * codes: a deployment that leaks it has lost more than consent. See docs/decisions/0003.
 */
final class ConsentTicketSigner
{
    public const EXCEPTION_SECRET_REQUIRED = 6001;

    /**
     * Long enough to read a consent screen and think about it, short enough that a ticket found in
     * a browser's back button or a proxy log is worthless.
     */
    public const DEFAULT_TTL_SECONDS = 900;

    private const ALGORITHM = 'sha256';

    private readonly string $secret;
    private readonly int $ttlSeconds;

    /**
     * @throws \InvalidArgumentException if the secret is empty.
     */
    public function __construct(
        #[\SensitiveParameter]
        string $secret,
        int $ttlSeconds = self::DEFAULT_TTL_SECONDS,
    ) {
        if ($secret === '') {
            throw new \InvalidArgumentException(
                'A signing secret is required; an unsigned consent ticket binds nothing.',
                self::EXCEPTION_SECRET_REQUIRED,
            );
        }

        $this->secret     = $secret;
        $this->ttlSeconds = max(1, $ttlSeconds);
    }

    /**
     * @param array<string, mixed> $binding Everything the approval is being bound to.
     */
    public function issue(array $binding, ?\DateTimeImmutable $now = null): string
    {
        $expiry = ($now ?? new \DateTimeImmutable())->getTimestamp() + $this->ttlSeconds;

        return $expiry . '.' . $this->sign($binding, $expiry);
    }

    /**
     * @param array<string, mixed> $binding
     */
    public function verify(string $ticket, array $binding, ?\DateTimeImmutable $now = null): bool
    {
        if (preg_match('/^([0-9]{1,12})\.([0-9a-f]{64})$/', $ticket, $matches) !== 1) {
            return false;
        }

        $expiry = (int) $matches[1];

        if ($expiry <= ($now ?? new \DateTimeImmutable())->getTimestamp()) {
            return false;
        }

        return hash_equals($this->sign($binding, $expiry), $matches[2]);
    }

    /**
     * @param array<string, mixed> $binding
     */
    private function sign(array $binding, int $expiry): string
    {
        // ksort so a caller cannot change the signature by reordering the binding it passes, and
        // JSON_THROW_ON_ERROR so an unencodable binding fails loudly rather than signing "false".
        ksort($binding);

        $payload = $expiry . '|' . json_encode($binding, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);

        return hash_hmac(self::ALGORITHM, $payload, $this->secret);
    }
}
