<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Http;

use Psr\Http\Message\ServerRequestInterface;

/**
 * The incoming request, reduced to what an authorization server actually reads.
 *
 * This exists so a flat-file application with no framework and no PSR-7 implementation can still
 * call an endpoint: `fromGlobals()` is the whole integration. An application that already speaks
 * PSR-7 hands its own object to `fromPsr7()` instead, and loses nothing.
 *
 * Note what is NOT here: a host. `$_SERVER['HTTP_HOST']` is attacker-controlled, so a request
 * carrying one would invite an endpoint to build an issuer, an audience or a redirect target out
 * of it. `$uri` is the request target only — path and query — and every absolute URL this package
 * emits comes from Configuration. See PLAN.md §4.3.
 *
 * Immutable.
 */
final class Request
{
    // --- Failure codes ---

    public const EXCEPTION_METHOD_REQUIRED = 4001;

    // --- State ---

    /** Uppercased HTTP method. */
    public readonly string $method;

    /** Request target: path, and query string if there was one. Never a host. */
    public readonly string $uri;

    /** @var array<string, mixed> Decoded query string. */
    public readonly array $queryParams;

    /** @var array<string, mixed> Decoded form body, empty for requests that have none. */
    public readonly array $parsedBody;

    /**
     * The body exactly as it arrived.
     *
     * Both are here because both are needed and neither can be derived from the other. The OAuth
     * endpoints read `parsedBody`, because a token request is a form post; MCP reads this, because
     * a JSON-RPC envelope is `application/json` and PHP never puts one in `$_POST`. A request
     * object that carried only the parsed form would make the MCP endpoint impossible to build on.
     */
    public readonly string $rawBody;

    /** @var array<string, string> Header names as given; look up through `header()`, not directly. */
    public readonly array $headers;

    /**
     * The peer address, for throttle keys. Deliberately `REMOTE_ADDR` and never `X-Forwarded-For`:
     * a forgeable header would let one client hold as many throttle buckets as it liked.
     */
    public readonly string $clientIp;

    /**
     * @param array<string, mixed>  $queryParams
     * @param array<string, mixed>  $parsedBody
     * @param array<string, string> $headers
     *
     * @throws \InvalidArgumentException with one of the EXCEPTION_* codes above.
     */
    public function __construct(
        string $method,
        string $uri = '/',
        array $queryParams = [],
        array $parsedBody = [],
        array $headers = [],
        string $clientIp = '',
        string $rawBody = '',
    ) {
        $method = strtoupper(trim($method));

        if ($method === '') {
            throw new \InvalidArgumentException('An HTTP method is required.', self::EXCEPTION_METHOD_REQUIRED);
        }

        $this->method      = $method;
        $this->uri         = $uri === '' ? '/' : $uri;
        $this->queryParams = $queryParams;
        $this->parsedBody  = $parsedBody;
        $this->headers     = $headers;
        $this->clientIp    = $clientIp;
        $this->rawBody     = $rawBody;
    }

    // --- Construction ---

    /**
     * Build from the superglobals, for an application with no HTTP abstraction of its own.
     *
     * The query string is re-parsed from `REQUEST_URI` rather than read from `$_GET`, because a
     * host that runs with `register_globals`-era `variables_order` or an `.htaccess` rewrite can
     * leave `$_GET` holding something other than what the client actually sent.
     *
     * The raw body is read from `php://input`, which is where a JSON-RPC envelope lives — PHP fills
     * `$_POST` only for form encodings. It reads empty for a form post on most SAPIs, which is
     * exactly right: `$_POST` already has that.
     */
    public static function fromGlobals(): self
    {
        /** @var array<string, mixed> $server */
        $server = $_SERVER;

        $target = is_string($server['REQUEST_URI'] ?? null) ? $server['REQUEST_URI'] : '/';
        $query  = [];

        parse_str((string) parse_url($target, PHP_URL_QUERY), $query);

        /** @var array<string, mixed> $body */
        $body = is_array($_POST) ? $_POST : [];

        return new self(
            is_string($server['REQUEST_METHOD'] ?? null) ? $server['REQUEST_METHOD'] : 'GET',
            $target,
            $query,
            $body,
            self::headersFromServer($server),
            is_string($server['REMOTE_ADDR'] ?? null) ? $server['REMOTE_ADDR'] : '',
            (string) @file_get_contents('php://input'),
        );
    }

    public static function fromPsr7(ServerRequestInterface $request): self
    {
        $headers = [];

        foreach ($request->getHeaders() as $name => $values) {
            $headers[(string) $name] = implode(', ', $values);
        }

        $body  = $request->getParsedBody();
        $uri   = $request->getUri()->getPath();
        $query = $request->getUri()->getQuery();
        $raw   = $request->getBody();

        if ($raw->isSeekable()) {
            $raw->rewind();
        }

        /** @var array<string, mixed> $serverParams */
        $serverParams = $request->getServerParams();

        return new self(
            $request->getMethod(),
            $query === '' ? $uri : $uri . '?' . $query,
            $request->getQueryParams(),
            is_array($body) ? $body : [],
            $headers,
            is_string($serverParams['REMOTE_ADDR'] ?? null) ? $serverParams['REMOTE_ADDR'] : '',
            $raw->getContents(),
        );
    }

    // --- Reads ---

    public function isGet(): bool
    {
        return $this->method === 'GET';
    }

    public function isPost(): bool
    {
        return $this->method === 'POST';
    }

    /** Case-insensitive header lookup, as HTTP requires. */
    public function header(string $name): ?string
    {
        foreach ($this->headers as $candidate => $value) {
            if (strcasecmp($candidate, $name) === 0) {
                return $value;
            }
        }

        return null;
    }

    /** A query parameter, but only when it is a single string: `?scope[]=a` is not a scope. */
    public function query(string $name): ?string
    {
        $value = $this->queryParams[$name] ?? null;

        return is_string($value) ? $value : null;
    }

    /** A body parameter, but only when it is a single string. */
    public function body(string $name): ?string
    {
        $value = $this->parsedBody[$name] ?? null;

        return is_string($value) ? $value : null;
    }

    /** The token from an `Authorization: Bearer` header, if there is one. */
    public function bearerToken(): ?string
    {
        $header = $this->header('Authorization');

        if ($header === null || preg_match('/^Bearer\s+(\S+)$/i', $header, $matches) !== 1) {
            return null;
        }

        return $matches[1];
    }

    /**
     * The credentials from an `Authorization: Basic` header, if there is one.
     *
     * @return array{0: string, 1: string}|null Client identifier and secret.
     */
    public function basicAuthCredentials(): ?array
    {
        $header = $this->header('Authorization');

        if ($header === null || preg_match('/^Basic\s+(\S+)$/i', $header, $matches) !== 1) {
            return null;
        }

        $decoded = base64_decode($matches[1], true);

        if ($decoded === false || !str_contains($decoded, ':')) {
            return null;
        }

        [$identifier, $secret] = explode(':', $decoded, 2);

        // RFC 6749 §2.3.1: both halves are form-urlencoded before they are base64-encoded.
        return [urldecode($identifier), urldecode($secret)];
    }

    // --- Helpers ---

    /**
     * @param array<string, mixed> $server
     *
     * @return array<string, string>
     */
    private static function headersFromServer(array $server): array
    {
        $headers = [];

        foreach ($server as $name => $value) {
            if (!is_string($value) || !str_starts_with((string) $name, 'HTTP_')) {
                continue;
            }

            $header = str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr((string) $name, 5)))));

            $headers[$header] = $value;
        }

        // mod_php and FastCGI both hide the Authorization header behind a different key, and a
        // bearer token that never arrives looks exactly like one that was never sent.
        foreach (['PHP_AUTH_DIGEST', 'REDIRECT_HTTP_AUTHORIZATION'] as $fallback) {
            if (!isset($headers['Authorization']) && is_string($server[$fallback] ?? null)) {
                $headers['Authorization'] = $server[$fallback];
            }
        }

        if (!isset($headers['Authorization']) && is_string($server['PHP_AUTH_USER'] ?? null)) {
            $password = is_string($server['PHP_AUTH_PW'] ?? null) ? $server['PHP_AUTH_PW'] : '';

            $headers['Authorization'] = 'Basic ' . base64_encode($server['PHP_AUTH_USER'] . ':' . $password);
        }

        return $headers;
    }
}
