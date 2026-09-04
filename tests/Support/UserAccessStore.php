<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Tests\Support;

use VoltCMS\UserAccess\Group;
use VoltCMS\UserAccess\GroupProvider;
use VoltCMS\UserAccess\User;
use VoltCMS\UserAccess\UserProvider;

/**
 * Real `voltcms/useraccess` providers, on a fresh directory, per test.
 *
 * `UserProvider` and `GroupProvider` are process-wide singletons whose directory is fixed by the
 * first `getInstance()` call, so without resetting them every test after the first would silently
 * write into the first one's temp directory — and then read the wrong records back, or none. The
 * reset below is reflection into `private static $instance`, which is exactly as unpleasant as it
 * looks and still better than testing `UserAccessIdentityProvider` against a fake of the store it
 * exists to talk to.
 */
final class UserAccessStore
{
    public readonly UserProvider $users;
    public readonly GroupProvider $groups;

    public function __construct(string $root)
    {
        self::reset(UserProvider::class);
        self::reset(GroupProvider::class);

        $this->users  = UserProvider::getInstance(['directory' => $root . '/users']);
        $this->groups = GroupProvider::getInstance(['directory' => $root . '/groups']);
    }

    /**
     * @param list<string> $groups Display names of groups to put the user in, created if absent.
     */
    public function createUser(string $userName, string $displayName = '', array $groups = [], bool $active = true): User
    {
        $user = new User();
        $user->setUserName($userName);
        $user->setDisplayName($displayName === '' ? $userName : $displayName);
        $user->setActive($active);

        $created = $this->users->create($user);

        foreach ($groups as $name) {
            $this->addToGroup($created->getId(), $name);
        }

        return $created;
    }

    public function addToGroup(string $userId, string $groupName): Group
    {
        if ($this->groups->exists('displayName', $groupName)) {
            $group = $this->groups->read('displayName', $groupName);
        } else {
            $group = new Group();
            $group->setDisplayName($groupName);
            $group = $this->groups->create($group);
        }

        $group->addMember($userId);

        return $this->groups->update($group);
    }

    public function removeFromGroup(string $userId, string $groupName): void
    {
        $group = $this->groups->read('displayName', $groupName);
        $group->removeMember($userId);

        $this->groups->update($group);
    }

    public function deactivate(string $userId): void
    {
        $user = $this->users->read('id', $userId);
        $user->setActive(false);

        $this->users->update($user);
    }

    /**
     * @param class-string $provider
     */
    private static function reset(string $provider): void
    {
        $instance = new \ReflectionProperty($provider, 'instance');
        $instance->setValue(null, null);
    }
}
