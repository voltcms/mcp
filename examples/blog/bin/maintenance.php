<?php

declare(strict_types=1);

/**
 * The cron entry. Nothing in this package runs on a schedule — there is no daemon, which is most of
 * the point — so sweeping expired records is the deployment's job.
 *
 *     17 3 * * * php /path/to/examples/blog/bin/maintenance.php
 *
 * Left unrun, the token collections grow without bound and every lookup slows with them; see
 * docs/decisions/0005-validation-reads-the-store.md for what that costs and when it starts to
 * matter.
 */

namespace Example\Blog;

/** @var \VoltCMS\MCP\OAuthServer $oauth */
/** @var \VoltCMS\MCP\McpServer $mcp */
require dirname(__DIR__) . '/bootstrap.php';

$records  = $oauth->purgeExpired();
$sessions = $mcp->sessions()->purge();

echo 'Purged ', $records, " expired OAuth records and ", $sessions, " MCP sessions.\n";
