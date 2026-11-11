<?php

declare(strict_types=1);

namespace Plugins\LegacyPasswords\Domain\Algorithms;

/**
 * Django's PBKDF2 format — `pbkdf2_sha256$iterations$salt$base64digest`.
 *
 * ════════════════════════════════════════════════════════════════════════════
 * SELF-DESCRIBING, WHICH MAKES IT THE EASY ONE
 * ════════════════════════════════════════════════════════════════════════════
 *
 *     pbkdf2_sha256$260000$aBcDeFgHiJkL$hi4yngU53R23HHl8EG6Z0i8eA7KCLIaegHx21tD6Sqs=
 *     └─────┬─────┘ └──┬─┘ └────┬────┘ └──────────────────┬───────────────────────┘
 *       algorithm  iterations  salt           base64 of the derived key
 *
 * Everything needed is in the string, so no out-of-band parameters and no
 * guessing. Django is where this format comes from, and several other
 * frameworks copied it verbatim.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * THE DERIVED LENGTH IS THE DIGEST SIZE, AND IT IS NOT WRITTEN DOWN
 * ────────────────────────────────────────────────────────────────────────────
 *
 * PBKDF2 can produce any output length, and the format does not record which
 * was used. Django always asks for exactly the underlying hash's digest size —
 * 32 bytes for SHA-256, 20 for SHA-1 — so that is what this derives.
 *
 * It is also CHECKED rather than assumed: the stored base64 is decoded and its
 * length compared to the digest size, and a mismatch is reported as a
 * malformed hash. Without that check, a hash from some other tool that asked
 * for 64 bytes would be derived at 32, compared against 64, and every user
 * would be told their password was wrong.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * THE SALT IS TEXT, NOT BYTES
 * ────────────────────────────────────────────────────────────────────────────
 *
 * Django generates an alphanumeric salt string and passes it to PBKDF2 as
 * those characters. It is not hex, not base64, and must not be decoded — a
 * salt of `aBcDeFgHiJkL` is twelve bytes of ASCII. This is the opposite
 * convention from the scrypt and Firebase paths, where the salt genuinely is
 * encoded bytes, and getting them the wrong way round is the most likely way
 * to break either.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * VERIFIED AGAINST PYTHON
 * ────────────────────────────────────────────────────────────────────────────
 *
 * The test vectors were produced by Python's `hashlib.pbkdf2_hmac` assembled
 * into Django's string format, at three iteration counts and for both SHA-256
 * and SHA-1.
 */
final class Pbkdf2Hash
{
    /**
     * Digests this will accept, and their output length in bytes.
     *
     * An allowlist rather than anything `hash_hmac_algos()` offers, for the
     * same reason as the plain-digest family: `pbkdf2_crc32b$…` is a string
     * somebody could put in a column, and PBKDF2 over a 32-bit checksum is
     * not an authentication check.
     */
    public const DIGESTS = [
        'sha1'   => 20,
        'sha256' => 32,
        'sha512' => 64,
    ];

    /**
     * An iteration ceiling, so a mistyped count cannot pin a worker.
     *
     * Django's default has climbed over the years and is in the hundreds of
     * thousands; a million is about half a second of PBKDF2-SHA256 here, and
     * anything above this is a typo rather than a configuration. The service
     * applies its own, tighter, configurable ceiling on top of this one.
     */
    public const MAX_ITERATIONS = 10_000_000;

    private function __construct(
        public readonly string $digest,
        public readonly int $iterations,
        public readonly string $salt,
        /** The stored derived key, RAW bytes, already base64-decoded. */
        private readonly string $derived,
    ) {}

    /**
     * Parse a stored string, or null if it is not a well-formed PBKDF2 hash.
     *
     * Null means MALFORMED, which the caller must report as an operational
     * problem rather than as a wrong password — every row of that shape will
     * fail, so it is a broken import and not a forgotten passphrase.
     */
    public static function parse(string $stored): ?self
    {
        // Four parts, with the last absorbing any remaining `$`. This mirrors
        // Django's own `encoded.split("$", 3)`: a base64 digest never contains
        // `$`, so the only way a fourth separator appears is a salt that has
        // one, and Django's salts are alphanumeric.
        $parts = explode('$', $stored, 4);

        if (\count($parts) !== 4) {
            return null;
        }

        [$algorithm, $iterations, $salt, $encoded] = $parts;

        if (!str_starts_with($algorithm, 'pbkdf2_')) {
            return null;
        }

        $digest = substr($algorithm, \strlen('pbkdf2_'));

        if (!isset(self::DIGESTS[$digest])) {
            return null;
        }

        // `ctype_digit` and not `(int)`: `(int) '260000x'` is 260000, and
        // `(int) '1e6'` is 1 — both would parse a corrupt field into a
        // plausible number and hash with the wrong cost.
        if ($iterations === '' || !ctype_digit($iterations)) {
            return null;
        }

        $count = (int) $iterations;

        if ($count < 1 || $count > self::MAX_ITERATIONS) {
            return null;
        }

        if ($salt === '') {
            return null;
        }

        // Strict base64. The lenient default silently drops characters it does
        // not recognise, so a corrupted field would decode to something
        // shorter and the length check below would be the only thing standing
        // between that and a universal verification failure.
        $derived = base64_decode($encoded, true);

        if ($derived === false || \strlen($derived) !== self::DIGESTS[$digest]) {
            return null;
        }

        return new self(digest: $digest, iterations: $count, salt: $salt, derived: $derived);
    }

    /** The derived key this password produces, RAW bytes. */
    public function recompute(#[\SensitiveParameter] string $password): string
    {
        return hash_pbkdf2(
            $this->digest,
            $password,
            // Text, not decoded bytes. See the class docblock.
            $this->salt,
            $this->iterations,
            self::DIGESTS[$this->digest],
            true,
        );
    }

    /** The stored derived key, RAW bytes, for the caller's `hash_equals`. */
    public function derived(): string
    {
        return $this->derived;
    }
}
