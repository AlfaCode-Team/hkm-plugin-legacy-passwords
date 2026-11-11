<?php

declare(strict_types=1);

namespace Plugins\LegacyPasswords\Infrastructure\Config;

/**
 * Configuration for legacy password verification.
 *
 * ════════════════════════════════════════════════════════════════════════════
 * WHY THERE ARE WORK-FACTOR CEILINGS AT ALL
 * ════════════════════════════════════════════════════════════════════════════
 *
 * A self-describing hash carries its own cost, and the cost is attacker-
 * controlled in exactly one realistic situation that matters: an IMPORT FILE
 * FROM OUTSIDE. A CSV or JSON export handed over by the system being migrated
 * away from is not trusted input, and a single row containing
 *
 *     $2y$31$................................
 *
 * is a bcrypt hash with 2^31 rounds — hours of CPU for one verification.
 * Planting it costs nothing, it passes every format check because it is a
 * perfectly valid hash, and from then on every login attempt against that
 * account occupies a PHP worker until the request times out. A handful of
 * those rows is a denial of service that needs no traffic to trigger.
 *
 * So the ceilings turn that into a refusal with a reason. They are generous
 * enough that nothing met in practice comes near them: WordPress ships
 * phpass at 8,192 iterations, Django's PBKDF2 default is in the hundreds of
 * thousands, and bcrypt above cost 14 is already a second per login.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * ALL NORMALISATION HAPPENS IN THE PRIVATE CONSTRUCTOR
 * ────────────────────────────────────────────────────────────────────────────
 *
 * Both named constructors go through it, so there is no way to reach a config
 * with the clamps skipped. This is not hypothetical tidiness — the same class
 * of bug was found in a sibling plugin, where validation lived in `fromEnv()`
 * and `of()` walked straight past it, making a nonsensical value reachable
 * through the path every test used.
 */
final readonly class LegacyPasswordConfig
{
    /** 2^15 bcrypt rounds is already tens of seconds. */
    public const DEFAULT_MAX_BCRYPT_COST = 15;

    public const MIN_BCRYPT_COST = 4;

    public const MAX_BCRYPT_COST = 31;

    /** 1 GiB. Argon2's memory cost is in KiB, and it is allocated for real. */
    public const DEFAULT_MAX_ARGON2_MEMORY_KIB = 1_048_576;

    /**
     * Covers phpass's iteration count, PBKDF2's, and crypt(3)'s `rounds=`.
     *
     * One number for three schemes because it means the same thing in all
     * three — how many times a cheap primitive is repeated — and three
     * separate knobs would be three chances to set one wrong.
     */
    public const DEFAULT_MAX_ITERATIONS = 1_000_000;

    public int $maxBcryptCost;

    public int $maxArgon2MemoryKib;

    public int $maxIterations;

    public bool $allowPlaintext;

    /**
     * The parameters are deliberately NOT promoted.
     *
     * A promoted readonly property is already initialised by the promotion, so
     * assigning to it in the body raises `Cannot modify readonly property` —
     * every construction would have thrown. Declaring the properties and
     * taking plain parameters is what lets the clamping live in the one place
     * both named constructors must pass through.
     */
    private function __construct(
        int $maxBcryptCost,
        int $maxArgon2MemoryKib,
        int $maxIterations,
        bool $allowPlaintext,
    ) {
        // Clamped, not rejected. A ceiling is an operational safety limit, and
        // refusing to boot over a mistyped one would take the application down
        // to protect it from a slow login.
        $this->maxBcryptCost = max(
            self::MIN_BCRYPT_COST,
            min(self::MAX_BCRYPT_COST, $maxBcryptCost),
        );

        // Floor at 8 KiB, which is Argon2's own minimum, so a zero or negative
        // value cannot make every Argon2 hash unverifiable.
        $this->maxArgon2MemoryKib = max(8, $maxArgon2MemoryKib);

        // Floor at 8192 — WordPress's default phpass count. A ceiling below it
        // would refuse every WordPress hash in existence, which is the
        // opposite of what this plugin is for.
        $this->maxIterations = max(8192, $maxIterations);

        $this->allowPlaintext = $allowPlaintext;
    }

    public static function of(
        int $maxBcryptCost = self::DEFAULT_MAX_BCRYPT_COST,
        int $maxArgon2MemoryKib = self::DEFAULT_MAX_ARGON2_MEMORY_KIB,
        int $maxIterations = self::DEFAULT_MAX_ITERATIONS,
        bool $allowPlaintext = false,
    ): self {
        return new self(
            maxBcryptCost:      $maxBcryptCost,
            maxArgon2MemoryKib: $maxArgon2MemoryKib,
            maxIterations:      $maxIterations,
            allowPlaintext:     $allowPlaintext,
        );
    }

    public static function fromEnv(): self
    {
        return new self(
            maxBcryptCost:      (int) (env('LEGACY_PASSWORD_MAX_BCRYPT_COST')
                ?: self::DEFAULT_MAX_BCRYPT_COST),
            maxArgon2MemoryKib: (int) (env('LEGACY_PASSWORD_MAX_ARGON2_MEMORY')
                ?: self::DEFAULT_MAX_ARGON2_MEMORY_KIB),
            maxIterations:      (int) (env('LEGACY_PASSWORD_MAX_ITERATIONS')
                ?: self::DEFAULT_MAX_ITERATIONS),
            // Default FALSE, and it has to be turned on deliberately. A
            // plaintext password column means the breach has already happened;
            // reading one should be a decision somebody made, with a date on
            // it, not a default that nobody noticed.
            //
            // `env()` and never `getenv()` — $_ENV is this project's source of
            // truth and putenv() is not called, so getenv() would return false
            // for a variable that is plainly set in .env.
            allowPlaintext:     filter_var(
                env('LEGACY_PASSWORD_ALLOW_PLAINTEXT') ?? false,
                \FILTER_VALIDATE_BOOL,
            ),
        );
    }

    /**
     * Status output.
     *
     * @return array<string, int|string|bool>
     */
    public function describe(): array
    {
        return [
            'max_bcrypt_cost'   => $this->maxBcryptCost,
            'max_argon2_mb'     => (int) round($this->maxArgon2MemoryKib / 1024),
            'max_iterations'    => $this->maxIterations,
            'allow_plaintext'   => $this->allowPlaintext,
        ];
    }
}
