<?php

declare(strict_types=1);

/**
 * Everything this example needs, built once. Both entry points require this file and nothing else.
 *
 * Note what is NOT here: any use of `$_SERVER['HTTP_HOST']`. The issuer and the resource are
 * configured, because a forged `Host` header would otherwise publish an attacker's origin as this
 * site's authorization server. That is the single most important line in the file.
 */

namespace Example\Blog;

use VoltCMS\MCP\Configuration;
use VoltCMS\MCP\Identity\ScopePolicy;
use VoltCMS\MCP\Identity\UserAccessIdentityProvider;
use VoltCMS\MCP\McpServer;
use VoltCMS\MCP\OAuthServer;
use VoltCMS\UserAccess\AuditLog;
use VoltCMS\UserAccess\GroupProvider;
use VoltCMS\UserAccess\LoginThrottle;
use VoltCMS\UserAccess\UserProvider;

require __DIR__ . '/../../vendor/autoload.php';

spl_autoload_register(static function (string $class): void {
    if (str_starts_with($class, 'Example\\Blog\\')) {
        require __DIR__ . '/src/' . substr($class, strlen('Example\\Blog\\')) . '.php';
    }
});

/**
 * Outside the web root. On shared hosting that usually means a sibling of `public_html/`, not a
 * subdirectory of it — the deny-all files this package writes are defence in depth, not a
 * substitute (see SECURITY.md).
 */
$private = getenv('MCP_STORAGE') ?: dirname(__DIR__, 3) . '/private/example-blog';

/**
 * From the environment, with a documented default — the same place the encryption key comes from.
 *
 * Reading these from the environment is not a softening of "the issuer is configuration, never a
 * header". The environment is configuration: it is set by whoever deploys the site, once, and an
 * incoming request cannot influence it. What must never happen is deriving either from
 * `$_SERVER['HTTP_HOST']`, and nothing here does.
 *
 * They have to be the PUBLIC URLs. Behind a tunnel that means the tunnel's hostname, not
 * `localhost` — a client discovers this server through these values and will go wherever they say.
 */
$issuer   = getenv('MCP_ISSUER') ?: 'https://example.com';
$resource = getenv('MCP_RESOURCE') ?: $issuer . '/mcp';

$configuration = new Configuration(
    issuer:           $issuer,
    resource:         $resource,
    storageDirectory: $private . '/oauth',
    privateKeyPath:   $private . '/keys/private.key',
    publicKeyPath:    $private . '/keys/public.key',
    // Never a constant in a PHP file. `base64_encode(random_bytes(32))`, once, kept out of the
    // codebase — losing it invalidates every live grant.
    encryptionKey:    (string) getenv('MCP_ENCRYPTION_KEY'),
    scopes:           ['mcp:read', 'mcp:write'],
);

$users  = UserProvider::getInstance(['directory' => $private . '/users']);
$groups = GroupProvider::getInstance(['directory' => $private . '/groups']);

$identities = new UserAccessIdentityProvider($users, $groups, new Session());

/**
 * Roles are group names. `editors` may write; everyone who can log in may read.
 *
 * A single-account site can say `ScopePolicy::everyoneMay(['mcp:read', 'mcp:write'])` instead —
 * correct while there is one account, and wrong the moment there are two, which is why it has to be
 * asked for by name.
 */
$scopePolicy = new ScopePolicy(
    byRole:      ['editors' => ['mcp:read', 'mcp:write']],
    forEveryone: ['mcp:read'],
);

$auditLog = new AuditLog($private . '/audit');
$throttle = new LoginThrottle($private . '/throttle');

$oauth = new OAuthServer(
    $configuration,
    $identities,
    $scopePolicy,
    new ConsentView(),
    new LoginRedirector(),
    $auditLog,
    $throttle,
);

$posts = new Posts(__DIR__ . '/content');

$mcp = new McpServer(
    $configuration,
    $identities,
    $scopePolicy,
    $oauth->accessTokenVerifier(),
    $oauth->accessTokens(),
    requiredScopes: ['mcp:read'],
    serverName:     'example-blog',
    serverVersion:  '1.0.0',
);

$mcp->addTool([$posts, 'list'], name: 'list_posts', description: 'List the posts on this site, newest first.');
$mcp->addTool([$posts, 'read'], name: 'read_post', description: 'Read one post by slug.');
$mcp->addTool([$posts, 'write'], name: 'write_post', description: 'Replace the body of one post.');
