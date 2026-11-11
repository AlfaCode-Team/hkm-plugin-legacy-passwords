<?php

declare(strict_types=1);

namespace Tests\Plugins\LegacyPasswords\Support;

use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\HashingPort;

/**
 * A `HashingPort` that records what it was asked to hash.
 *
 * Real bcrypt, at the lowest cost PHP allows, because the point of these tests
 * is that `upgrade()` delegates rather than that bcrypt works. Cost 4 keeps a
 * suite that calls it a dozen times in milliseconds; cost 12 would add a
 * second.
 *
 * It RECORDS the plaintext deliberately — a test needs to prove that the
 * password reaching the hasher is the one that was verified, and not, say, a
 * normalised or truncated version of it. That makes this object unfit for
 * anything but a test, which is why it lives under tests/.
 */
final class RecordingHasher implements HashingPort
{
    /** @var list<string> */
    public array $hashed = [];

    public function __construct(private readonly int $cost = 4) {}

    public function make(string $value, array $options = []): string
    {
        $this->hashed[] = $value;

        return password_hash($value, \PASSWORD_BCRYPT, ['cost' => $options['cost'] ?? $this->cost]);
    }

    public function check(string $value, string $hashedValue): bool
    {
        return password_verify($value, $hashedValue);
    }

    public function needsRehash(string $hashedValue, array $options = []): bool
    {
        return password_needs_rehash($hashedValue, \PASSWORD_BCRYPT, [
            'cost' => $options['cost'] ?? $this->cost,
        ]);
    }
}
