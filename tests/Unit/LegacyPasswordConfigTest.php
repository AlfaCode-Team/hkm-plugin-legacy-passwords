<?php

declare(strict_types=1);

namespace Tests\Plugins\LegacyPasswords\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Plugins\LegacyPasswords\Infrastructure\Config\LegacyPasswordConfig;

final class LegacyPasswordConfigTest extends TestCase
{
    /** @var array<string, mixed> */
    private array $savedEnv = [];

    protected function setUp(): void
    {
        foreach (self::keys() as $key) {
            $this->savedEnv[$key] = $_ENV[$key] ?? null;
        }
    }

    protected function tearDown(): void
    {
        foreach ($this->savedEnv as $key => $value) {
            if ($value === null) {
                unset($_ENV[$key]);

                continue;
            }

            $_ENV[$key] = $value;
        }
    }

    /** @return list<string> */
    private static function keys(): array
    {
        return [
            'LEGACY_PASSWORD_MAX_BCRYPT_COST',
            'LEGACY_PASSWORD_MAX_ARGON2_MEMORY',
            'LEGACY_PASSWORD_MAX_ITERATIONS',
            'LEGACY_PASSWORD_ALLOW_PLAINTEXT',
        ];
    }

    public function test_the_defaults_are_the_documented_ones(): void
    {
        $config = LegacyPasswordConfig::of();

        self::assertSame(15, $config->maxBcryptCost);
        self::assertSame(1_048_576, $config->maxArgon2MemoryKib);
        self::assertSame(1_000_000, $config->maxIterations);
        self::assertFalse($config->allowPlaintext, 'plaintext must be off unless deliberately enabled');
    }

    /**
     * `of()` MUST NOT bypass the clamps.
     *
     * This exact bug was found in a sibling plugin, where all the validation
     * lived in `fromEnv()` and `of()` walked straight past it — so a
     * nonsensical value was reachable through the constructor the route filter
     * and every test used. Here the clamping lives in the private constructor
     * and both named constructors go through it; this test is what pins that.
     */
    #[DataProvider('clamped')]
    public function test_normalisation_is_not_bypassable_through_of(
        string $property,
        int|bool $given,
        int|bool $expected,
    ): void {
        $config = LegacyPasswordConfig::of(...[$property => $given]);

        self::assertSame($expected, $config->{$property});
    }

    /** @return iterable<string, array{string, int|bool, int|bool}> */
    public static function clamped(): iterable
    {
        yield 'bcrypt cost below bcrypt\'s own minimum' => ['maxBcryptCost', 0, 4];
        yield 'negative bcrypt cost' => ['maxBcryptCost', -5, 4];
        yield 'bcrypt cost above bcrypt\'s own maximum' => ['maxBcryptCost', 99, 31];

        // Argon2's own minimum is 8 KiB. A zero would make every Argon2 hash
        // unverifiable — the ceiling would refuse all of them.
        yield 'argon2 memory of zero' => ['maxArgon2MemoryKib', 0, 8];
        yield 'negative argon2 memory' => ['maxArgon2MemoryKib', -1, 8];

        // The floor is 8192 — WordPress's default phpass count. A ceiling
        // below it would refuse every WordPress hash in existence, which is
        // the opposite of what this plugin is for.
        yield 'iterations below WordPress\'s default' => ['maxIterations', 1, 8192];
        yield 'zero iterations' => ['maxIterations', 0, 8192];
        yield 'negative iterations' => ['maxIterations', -100, 8192];
    }

    public function test_a_value_within_range_is_left_alone(): void
    {
        $config = LegacyPasswordConfig::of(
            maxBcryptCost:      12,
            maxArgon2MemoryKib: 65536,
            maxIterations:      500_000,
            allowPlaintext:     true,
        );

        self::assertSame(12, $config->maxBcryptCost);
        self::assertSame(65536, $config->maxArgon2MemoryKib);
        self::assertSame(500_000, $config->maxIterations);
        self::assertTrue($config->allowPlaintext);
    }

    public function test_from_env_reads_the_declared_keys(): void
    {
        $_ENV['LEGACY_PASSWORD_MAX_BCRYPT_COST']   = '10';
        $_ENV['LEGACY_PASSWORD_MAX_ARGON2_MEMORY'] = '32768';
        $_ENV['LEGACY_PASSWORD_MAX_ITERATIONS']    = '250000';
        $_ENV['LEGACY_PASSWORD_ALLOW_PLAINTEXT']   = 'true';

        $config = LegacyPasswordConfig::fromEnv();

        self::assertSame(10, $config->maxBcryptCost);
        self::assertSame(32768, $config->maxArgon2MemoryKib);
        self::assertSame(250_000, $config->maxIterations);
        self::assertTrue($config->allowPlaintext);
    }

    /**
     * `fromEnv()` goes through the same clamps as `of()`.
     *
     * An operator's typo is the most likely source of an out-of-range value,
     * so this is the path that most needs the clamp — and the one where
     * skipping it would be least visible.
     */
    public function test_from_env_is_clamped_too(): void
    {
        $_ENV['LEGACY_PASSWORD_MAX_BCRYPT_COST'] = '999';
        $_ENV['LEGACY_PASSWORD_MAX_ITERATIONS']  = '1';

        $config = LegacyPasswordConfig::fromEnv();

        self::assertSame(31, $config->maxBcryptCost);
        self::assertSame(8192, $config->maxIterations);
    }

    /**
     * Plaintext stays off for every value that is not deliberately truthy.
     *
     * The empty string matters most: an optional variable written as `KEY=`
     * reads as `''`, and `''` must not be the value that switches plaintext
     * verification on.
     */
    #[DataProvider('plaintextValues')]
    public function test_plaintext_only_turns_on_for_a_deliberate_truthy_value(
        ?string $value,
        bool $expected,
    ): void {
        if ($value === null) {
            unset($_ENV['LEGACY_PASSWORD_ALLOW_PLAINTEXT']);
        } else {
            $_ENV['LEGACY_PASSWORD_ALLOW_PLAINTEXT'] = $value;
        }

        self::assertSame($expected, LegacyPasswordConfig::fromEnv()->allowPlaintext);
    }

    /** @return iterable<string, array{?string, bool}> */
    public static function plaintextValues(): iterable
    {
        yield 'absent' => [null, false];
        yield 'empty string' => ['', false];
        yield 'the word false' => ['false', false];
        yield 'zero' => ['0', false];
        yield 'off' => ['off', false];
        yield 'no' => ['no', false];
        yield 'nonsense' => ['maybe', false];

        yield 'true' => ['true', true];
        yield 'one' => ['1', true];
        yield 'on' => ['on', true];
        yield 'yes' => ['yes', true];
    }

    public function test_describe_reports_the_effective_values(): void
    {
        $described = LegacyPasswordConfig::of(maxArgon2MemoryKib: 65536)->describe();

        self::assertSame(15, $described['max_bcrypt_cost']);
        self::assertSame(64, $described['max_argon2_mb'], 'reported in MB for a human');
        self::assertFalse($described['allow_plaintext']);
    }
}
