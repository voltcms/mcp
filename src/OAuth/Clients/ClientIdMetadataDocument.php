<?php

declare(strict_types=1);

namespace VoltCMS\MCP\OAuth\Clients;

use VoltCMS\MCP\OAuth\Entities\Client;

/**
 * A Client ID Metadata Document, validated.
 *
 * CIMD is how the 2026-07-28 MCP specification would rather clients be identified: instead of
 * registering, a client's `client_id` IS an https URL, and the document served there describes it.
 * That suits this package unusually well — a personal site that has to accept a client it has
 * never heard of can do so without an unauthenticated write endpoint, which is what dynamic
 * registration is (see docs/decisions/0006-who-answers-registration.md).
 *
 * Everything below is refusal. The document arrives from a host an unauthenticated caller chose,
 * so nothing in it is trusted until it has been checked, and the check that matters most is the
 * first: **the document's own `client_id` must equal the URL it was fetched from.** Without it,
 * `https://attacker.example/client.json` could serve a document claiming to be
 * `https://claude.ai/client.json`, and a user's consent screen would name Claude while the code
 * went somewhere else.
 *
 * Immutable.
 */
final class ClientIdMetadataDocument
{
    // --- Failure codes ---

    public const EXCEPTION_CLIENT_ID_MISMATCH     = 10101;
    public const EXCEPTION_REDIRECT_URIS_MISSING  = 10102;
    public const EXCEPTION_REDIRECT_URI_INSECURE  = 10103;
    public const EXCEPTION_AUTH_METHOD_REFUSED    = 10104;
    public const EXCEPTION_GRANT_TYPE_REFUSED     = 10105;
    public const EXCEPTION_NAME_MALFORMED         = 10106;

    /** A CIMD client never registered, so it holds no secret and can only authenticate as a public client. */
    public const AUTH_METHOD = 'none';

    public const MAXIMUM_REDIRECT_URIS = 8;
    public const MAXIMUM_NAME_LENGTH   = 120;

    private const SUPPORTED_GRANT_TYPES = [Client::GRANT_AUTHORIZATION_CODE, Client::GRANT_REFRESH_TOKEN];
    private const LOOPBACK_HOSTS        = ['localhost', '127.0.0.1', '::1'];

    public readonly string $clientId;
    public readonly string $clientName;

    /** @var list<string> */
    public readonly array $redirectUris;

    /** @var list<string> */
    public readonly array $grantTypes;

    /**
     * @param list<string> $redirectUris
     * @param list<string> $grantTypes
     */
    private function __construct(string $clientId, string $clientName, array $redirectUris, array $grantTypes)
    {
        $this->clientId     = $clientId;
        $this->clientName   = $clientName;
        $this->redirectUris = $redirectUris;
        $this->grantTypes   = $grantTypes;
    }

    /**
     * @param array<string, mixed> $document As decoded from the fetched JSON.
     * @param string               $url      The URL it was fetched from; also the client identifier.
     *
     * @throws \InvalidArgumentException with one of the EXCEPTION_* codes above.
     */
    public static function fromDocument(array $document, string $url): self
    {
        $claimed = $document['client_id'] ?? null;

        if (!is_string($claimed) || !hash_equals($url, $claimed)) {
            throw new \InvalidArgumentException(
                'The client metadata document does not claim the URL it was served from.',
                self::EXCEPTION_CLIENT_ID_MISMATCH,
            );
        }

        self::guardAuthMethod($document);

        return new self(
            $url,
            self::name($document, $url),
            self::redirectUris($document),
            self::grantTypes($document),
        );
    }

    /** The league entity, public and secret-less, exactly as its `token_endpoint_auth_method` says. */
    public function toClient(): Client
    {
        return new Client($this->clientId, $this->clientName, $this->redirectUris, false, $this->grantTypes);
    }

    // --- Validation ---

    /**
     * @param array<string, mixed> $document
     *
     * @return list<string>
     */
    private static function redirectUris(array $document): array
    {
        $uris  = $document['redirect_uris'] ?? null;
        $valid = [];

        if (!is_array($uris) || $uris === []) {
            throw new \InvalidArgumentException(
                'A client metadata document must list at least one redirect URI.',
                self::EXCEPTION_REDIRECT_URIS_MISSING,
            );
        }

        foreach (array_slice(array_values($uris), 0, self::MAXIMUM_REDIRECT_URIS) as $uri) {
            if (!is_string($uri) || !self::redirectUriIsAcceptable($uri)) {
                throw new \InvalidArgumentException(
                    'Redirect URIs must be absolute https URLs without a fragment; plain http is accepted only for loopback.',
                    self::EXCEPTION_REDIRECT_URI_INSECURE,
                );
            }

            $valid[] = $uri;
        }

        return $valid;
    }

    /**
     * Loopback http is allowed because that is how a desktop client receives its callback — the
     * `http://127.0.0.1:<random port>/callback` of RFC 8252 §7.3 — and there is no transport there
     * to secure. Everything else must be https, and nothing may carry a fragment, which the
     * authorization response would silently overwrite.
     */
    private static function redirectUriIsAcceptable(string $uri): bool
    {
        $parts = parse_url(trim($uri));

        if ($parts === false || !isset($parts['scheme'], $parts['host']) || isset($parts['fragment'])) {
            return false;
        }

        $scheme = strtolower($parts['scheme']);

        if ($scheme === 'https') {
            return true;
        }

        return $scheme === 'http' && in_array(strtolower(trim($parts['host'], '[]')), self::LOOPBACK_HOSTS, true);
    }

    /**
     * @param array<string, mixed> $document
     */
    private static function guardAuthMethod(array $document): void
    {
        if (($document['token_endpoint_auth_method'] ?? self::AUTH_METHOD) !== self::AUTH_METHOD) {
            throw new \InvalidArgumentException(
                'A client identified by a metadata document has no registered secret and must authenticate as a public client.',
                self::EXCEPTION_AUTH_METHOD_REFUSED,
            );
        }
    }

    /**
     * @param array<string, mixed> $document
     *
     * @return list<string>
     */
    private static function grantTypes(array $document): array
    {
        $requested = $document['grant_types'] ?? self::SUPPORTED_GRANT_TYPES;

        if (!is_array($requested) || $requested === []) {
            throw new \InvalidArgumentException(
                'A client metadata document must request at least one grant type.',
                self::EXCEPTION_GRANT_TYPE_REFUSED,
            );
        }

        $granted = [];

        foreach ($requested as $grantType) {
            if (!is_string($grantType) || !in_array($grantType, self::SUPPORTED_GRANT_TYPES, true)) {
                throw new \InvalidArgumentException(
                    'This server supports the authorization_code and refresh_token grants only.',
                    self::EXCEPTION_GRANT_TYPE_REFUSED,
                );
            }

            if (!in_array($grantType, $granted, true)) {
                $granted[] = $grantType;
            }
        }

        return $granted;
    }

    /**
     * The name a consent screen will show, so it is bounded, valid UTF-8, and stripped of control
     * characters — a client whose name contains a newline is a client shaping a consent screen.
     * Escaping is still the view's job; this only refuses the obvious. An over-long name is
     * refused rather than truncated: cutting a name in half is a worse thing to show a user than
     * declining the client.
     *
     * @param array<string, mixed> $document
     */
    private static function name(array $document, string $url): string
    {
        $name = $document['client_name'] ?? '';

        if (!is_string($name) || strlen($name) > self::MAXIMUM_NAME_LENGTH || preg_match('//u', $name) !== 1) {
            throw new \InvalidArgumentException(
                'A client name must be valid UTF-8 of at most ' . self::MAXIMUM_NAME_LENGTH . ' bytes.',
                self::EXCEPTION_NAME_MALFORMED,
            );
        }

        $name = trim((string) preg_replace('/[\x00-\x1F\x7F]+/u', ' ', $name));

        return $name === '' ? $url : $name;
    }
}
