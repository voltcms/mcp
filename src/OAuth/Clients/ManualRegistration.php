<?php

declare(strict_types=1);

namespace VoltCMS\MCP\OAuth\Clients;

use VoltCMS\MCP\OAuth\Entities\Client;
use VoltCMS\MCP\OAuth\Repositories\ClientRepository;

/**
 * Registering a client by hand, which for most deployments is the only registration there is.
 *
 * A personal site has one or two clients — a desktop application, maybe a second machine — and
 * adding them is a two-line script run once, not an endpoint standing open on the internet. This
 * class is that script's API: it generates the identifier and, for a confidential client, the
 * secret, so the two values that must be unguessable are not left to whoever is writing the script
 * at the time.
 *
 * The secret is returned exactly once, from `registerConfidential()`, because `ClientRepository`
 * stores only its hash. There is nowhere to read it back from, which is the point.
 */
final class ManualRegistration
{
    public const EXCEPTION_REDIRECT_URIS_REQUIRED = 10301;

    /** 32 bytes of randomness, base64url — the same shape as the tokens this server issues. */
    public const SECRET_BYTES = 32;

    public const IDENTIFIER_BYTES = 16;

    public function __construct(private readonly ClientRepository $clients)
    {
    }

    /**
     * A public client: a desktop application, a CLI, anything that runs where a user can read it.
     * It authenticates with PKCE and nothing else, which is what OAuth 2.1 expects of it.
     *
     * @param list<string> $redirectUris
     */
    public function registerPublic(string $name, array $redirectUris, ?string $clientId = null): Client
    {
        $client = new Client($this->identifier($clientId), $name, $this->validate($redirectUris), false);

        $this->clients->save($client);

        return $client;
    }

    /**
     * A confidential client: something running on a server, where a secret can actually be kept.
     *
     * @param list<string> $redirectUris
     *
     * @return array{0: Client, 1: string} The client, and its secret — shown once and never again.
     */
    public function registerConfidential(string $name, array $redirectUris, ?string $clientId = null): array
    {
        $client = new Client($this->identifier($clientId), $name, $this->validate($redirectUris), true);
        $secret = self::randomString(self::SECRET_BYTES);

        $this->clients->save($client, $secret);

        return [$client, $secret];
    }

    /**
     * Stop a client working. Its grants are refused at the next authorization or token request;
     * access tokens already issued run out their hour (see SECURITY.md).
     */
    public function deactivate(string $clientId): void
    {
        $this->clients->deactivate($clientId);
    }

    // --- Helpers ---

    /**
     * @param list<string> $redirectUris
     *
     * @return list<string>
     */
    private function validate(array $redirectUris): array
    {
        $valid = array_values(array_filter(
            $redirectUris,
            static fn (mixed $uri): bool => is_string($uri) && trim($uri) !== '',
        ));

        if ($valid === []) {
            throw new \InvalidArgumentException(
                'A client needs at least one redirect URI; league matches it exactly and refuses a request without one.',
                self::EXCEPTION_REDIRECT_URIS_REQUIRED,
            );
        }

        return $valid;
    }

    private function identifier(?string $clientId): string
    {
        return $clientId === null || trim($clientId) === ''
            ? self::randomString(self::IDENTIFIER_BYTES)
            : trim($clientId);
    }

    private static function randomString(int $bytes): string
    {
        return rtrim(strtr(base64_encode(random_bytes($bytes)), '+/', '-_'), '=');
    }
}
