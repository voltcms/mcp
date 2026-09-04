<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Http;

use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * What every handler in this package returns, and the reason the package is testable without a
 * web server.
 *
 * Nothing here writes to the output buffer: no `echo`, no `header()`, no `exit`. The consuming
 * application emits this object through whatever channel it already uses — its own emitter, a
 * PSR-7 bridge, a framework response — and a test simply inspects it. `mcp/sdk` returns rather
 * than emits for the same reason, which is why the two compose at all.
 *
 * Immutable: the `with…` methods return a new instance.
 */
final class Response
{
    // --- Statuses this package emits ---

    public const STATUS_OK                  = 200;
    public const STATUS_FOUND               = 302;
    public const STATUS_BAD_REQUEST         = 400;
    public const STATUS_UNAUTHORIZED        = 401;
    public const STATUS_NOT_FOUND           = 404;
    public const STATUS_METHOD_NOT_ALLOWED  = 405;
    public const STATUS_TOO_MANY_REQUESTS   = 429;
    public const STATUS_INTERNAL_ERROR      = 500;

    public const CONTENT_TYPE_JSON = 'application/json; charset=UTF-8';
    public const CONTENT_TYPE_HTML = 'text/html; charset=UTF-8';

    // --- State ---

    public readonly int $status;

    /** @var array<string, string> Header names as given; look up through `header()`. */
    public readonly array $headers;

    public readonly string $body;

    /**
     * @param array<string, string> $headers
     */
    public function __construct(int $status = self::STATUS_OK, string $body = '', array $headers = [])
    {
        $this->status  = $status;
        $this->body    = $body;
        $this->headers = $headers;
    }

    // --- Construction ---

    /**
     * @param array<string, mixed>  $payload
     * @param array<string, string> $headers
     */
    public static function json(array $payload, int $status = self::STATUS_OK, array $headers = []): self
    {
        $encoded = json_encode($payload, JSON_UNESCAPED_SLASHES);

        return new self(
            $status,
            $encoded === false ? '{}' : $encoded,
            array_merge([
                'Content-Type'  => self::CONTENT_TYPE_JSON,
                'Cache-Control' => 'no-store',
                'Pragma'        => 'no-cache',
            ], $headers),
        );
    }

    /**
     * @param array<string, string> $headers
     */
    public static function html(string $body, int $status = self::STATUS_OK, array $headers = []): self
    {
        return new self($status, $body, array_merge(['Content-Type' => self::CONTENT_TYPE_HTML], $headers));
    }

    /**
     * @param array<string, string> $headers
     */
    public static function redirect(string $location, int $status = self::STATUS_FOUND, array $headers = []): self
    {
        return new self($status, '', array_merge(['Location' => $location], $headers));
    }

    public static function fromPsr7(ResponseInterface $response): self
    {
        $headers = [];

        foreach ($response->getHeaders() as $name => $values) {
            $headers[(string) $name] = implode(', ', $values);
        }

        $body = $response->getBody();

        if ($body->isSeekable()) {
            $body->rewind();
        }

        return new self($response->getStatusCode(), $body->getContents(), $headers);
    }

    // --- Reads ---

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

    /**
     * The decoded body of a JSON response, or an empty array when it is not JSON.
     *
     * @return array<string, mixed>
     */
    public function decodedBody(): array
    {
        $decoded = json_decode($this->body, true);

        return is_array($decoded) ? $decoded : [];
    }

    // --- Derivation ---

    /** Replaces a header of the same name whatever its case, so a response never carries two. */
    public function withHeader(string $name, string $value): self
    {
        $headers = [];

        foreach ($this->headers as $candidate => $existing) {
            if (strcasecmp($candidate, $name) !== 0) {
                $headers[$candidate] = $existing;
            }
        }

        $headers[$name] = $value;

        return new self($this->status, $this->body, $headers);
    }

    public function withStatus(int $status): self
    {
        return new self($status, $this->body, $this->headers);
    }

    /**
     * Hand back to an application that speaks PSR-7. The factory is a parameter rather than a
     * dependency so this class stays a value object: nothing here needs a PSR-17 implementation
     * unless the consumer asks for one.
     */
    public function toPsr7(ResponseFactoryInterface $factory): ResponseInterface
    {
        $response = $factory->createResponse($this->status);

        foreach ($this->headers as $name => $value) {
            $response = $response->withHeader($name, $value);
        }

        if ($this->body !== '') {
            $response->getBody()->write($this->body);
        }

        return $response;
    }
}
