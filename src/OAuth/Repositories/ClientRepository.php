<?php

declare(strict_types=1);

namespace VoltCMS\MCP\OAuth\Repositories;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use VoltCMS\MCP\OAuth\Entities\Client;

/**
 * Registered clients, stored flat.
 *
 * Note what league does and does not ask of this class: `validateClient()` is only reached for
 * clients that report themselves confidential, so it is `getClientEntity()` returning null — for
 * an unknown client, and for one that has been deactivated — that turns away everyone else. Both
 * paths matter, and both are tested.
 */
final class ClientRepository extends FileDbRepository implements ClientRepositoryInterface
{
    public const FIELD_NAME            = 'name';
    public const FIELD_REDIRECT_URIS   = 'redirect_uris';
    public const FIELD_IS_CONFIDENTIAL = 'is_confidential';
    public const FIELD_GRANT_TYPES     = 'grant_types';
    public const FIELD_SECRET_HASH     = 'secret_hash';

    /**
     * A valid bcrypt hash of a random string nobody holds. Verifying an unknown client's secret
     * against it spends the same time a real verification would, so a wrong client id and a
     * wrong secret are not distinguishable by how long the answer takes.
     */
    private const DECOY_HASH = '$2y$12$s04y0HBbcQVm33PFj4SGEO3ACsZxp4qTfTVXMa0A81Eg.bb.GFywe';

    protected function collection(): string
    {
        return 'clients';
    }

    public function getClientEntity(string $clientIdentifier): ?ClientEntityInterface
    {
        $record = $this->find($clientIdentifier);

        if ($record === null || ($record[self::FIELD_REVOKED] ?? false) === true) {
            return null;
        }

        return $this->toEntity($record);
    }

    public function validateClient(string $clientIdentifier, ?string $clientSecret, ?string $grantType): bool
    {
        $record = $this->find($clientIdentifier);

        if ($record === null || ($record[self::FIELD_REVOKED] ?? false) === true) {
            password_verify((string) $clientSecret, self::DECOY_HASH);

            return false;
        }

        if ($grantType !== null && !$this->toEntity($record)->supportsGrantType($grantType)) {
            return false;
        }

        if (($record[self::FIELD_IS_CONFIDENTIAL] ?? false) !== true) {
            // A public client authenticates by identity alone; presenting a secret is a sign the
            // caller thinks it is something it is not.
            return $clientSecret === null || $clientSecret === '';
        }

        $hash = $record[self::FIELD_SECRET_HASH] ?? '';

        if (!is_string($hash) || $hash === '' || $clientSecret === null || $clientSecret === '') {
            return false;
        }

        return password_verify($clientSecret, $hash);
    }

    /**
     * Register a client. The secret is stored only as a hash, and only for confidential clients;
     * a public client must not have one, because a secret shipped inside a desktop application
     * or a browser is not a secret.
     */
    public function save(Client $client, #[\SensitiveParameter] ?string $secret = null): void
    {
        $redirectUri = $client->getRedirectUri();

        $this->insert([
            self::FIELD_OAUTH_ID        => $client->getIdentifier(),
            self::FIELD_NAME            => $client->getName(),
            self::FIELD_REDIRECT_URIS   => is_array($redirectUri) ? array_values($redirectUri) : [$redirectUri],
            self::FIELD_IS_CONFIDENTIAL => $client->isConfidential(),
            self::FIELD_GRANT_TYPES     => $client->grantTypes(),
            self::FIELD_SECRET_HASH     => $client->isConfidential() && $secret !== null && $secret !== ''
                ? password_hash($secret, PASSWORD_DEFAULT)
                : '',
            self::FIELD_REVOKED         => false,
        ]);

        $this->audit('client.registered', [
            'client_id'    => $client->getIdentifier(),
            'confidential' => $client->isConfidential(),
        ]);
    }

    /**
     * Deactivate a client by flagging the shared `revoked` field every collection in this store
     * uses. Its grants stop being usable at the next authorization or token request;
     * already-issued access tokens still run out their hour (see SECURITY.md).
     */
    public function deactivate(string $clientIdentifier): void
    {
        $this->revoke($clientIdentifier);
        $this->audit('client.deactivated', ['client_id' => $clientIdentifier]);
    }

    /**
     * @param array<string, mixed> $record
     */
    private function toEntity(array $record): Client
    {
        /** @var list<string> $redirectUris */
        $redirectUris = is_array($record[self::FIELD_REDIRECT_URIS] ?? null)
            ? array_values($record[self::FIELD_REDIRECT_URIS])
            : [];

        /** @var list<string> $grantTypes */
        $grantTypes = is_array($record[self::FIELD_GRANT_TYPES] ?? null)
            ? array_values($record[self::FIELD_GRANT_TYPES])
            : [];

        return new Client(
            (string) $record[self::FIELD_OAUTH_ID],
            (string) ($record[self::FIELD_NAME] ?? ''),
            $redirectUris,
            ($record[self::FIELD_IS_CONFIDENTIAL] ?? false) === true,
            $grantTypes,
        );
    }
}
