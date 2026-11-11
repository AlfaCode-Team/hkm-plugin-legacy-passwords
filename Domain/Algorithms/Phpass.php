<?php

declare(strict_types=1);

namespace Plugins\LegacyPasswords\Domain\Algorithms;

/**
 * phpass "portable" hashes — `$P$` (WordPress, Drupal 6) and `$H$` (phpBB3).
 *
 * ════════════════════════════════════════════════════════════════════════════
 * THE FORMAT
 * ════════════════════════════════════════════════════════════════════════════
 *
 *     $P$B eF39vipN M3QIErUZ.CevixuseSbRo0
 *     └┬─┘ │        └──────────┬──────────┘
 *      │   │  └── 8-char salt  │
 *      │   └── iteration count, as an index into the itoa64 alphabet
 *      └── `$P$` or `$H$` — identical algorithms, different prefix
 *
 * and the hash itself is:
 *
 *     h = md5(salt ‖ password)                     // raw, 16 bytes
 *     repeat `count` times:  h = md5(h ‖ password) // raw
 *     output = first 12 chars of the setting ‖ itoa64(h)
 *
 * `count` is `1 << index`, where `index` is the POSITION of the fourth
 * character in phpass's own base-64 alphabet. WordPress's default is `B`,
 * which is index 13, which is 8192 iterations of MD5.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * THE ALPHABET IS NOT BASE64, AND ITS ORDER IS NOT MIME'S
 * ────────────────────────────────────────────────────────────────────────────
 *
 *     ./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz
 *
 * Digits before upper-case before lower-case, led by `.` and `/`. This is the
 * crypt(3) tradition, and it is NOT the same as the `./ABC…XYZabc…xyz012…9`
 * order the very same phpass file uses for its BLOWFISH salts — the library
 * carries both alphabets, with different orders, a few lines apart.
 *
 * Using the wrong one produces a hash of exactly the right length and shape
 * whose every character is wrong, and encode64 is also not base64: it packs
 * three bytes into four characters LITTLE-ENDIAN-first and emits no padding,
 * so `base64_encode()` with a translated alphabet does not substitute for it.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * THIS IS CHECKED AGAINST A DIFFERENT IMPLEMENTATION
 * ────────────────────────────────────────────────────────────────────────────
 *
 * The tests verify hashes produced by Appwrite's own `Utopia\Auth\Hashes\
 * PHPass`, run on this machine, including a `$H$`-prefixed one — so the
 * expected values come from somebody else's code rather than from this code
 * agreeing with itself.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * WHAT IS NOT HANDLED, AND WHY THAT IS SAFE
 * ────────────────────────────────────────────────────────────────────────────
 *
 * phpass has a second mode: when the host supports it, `hash()` returns a
 * BCRYPT hash (`$2a$…`) instead of a portable one, and a WordPress database
 * can contain both. That case is not handled here, because it does not need to
 * be — a `$2a$` hash is bcrypt, it is detected as bcrypt, and
 * `password_verify()` checks it. Routing it through this class would mean
 * re-implementing bcrypt, which would be strictly worse.
 *
 * Drupal 7's `$S$` is phpass with SHA-512 and a truncated output. It is NOT
 * implemented — see {@see \Plugins\LegacyPasswords\Domain\LegacyAlgorithm} for
 * why an unverifiable crypto path is worse than an absent one.
 */
final class Phpass
{
    /**
     * phpass's own base-64 alphabet. Order is load-bearing — see the docblock.
     */
    public const ITOA64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

    /** `$P$` is WordPress and Drupal 6; `$H$` is phpBB3. Same algorithm. */
    public const PREFIXES = ['$P$', '$H$'];

    /** 3 for the prefix, 1 for the count, 8 for the salt, 22 for the hash. */
    public const LENGTH = 34;

    /** The count character's alphabet index must land in this range. */
    public const MIN_COUNT_LOG2 = 7;

    public const MAX_COUNT_LOG2 = 30;

    private const SALT_OFFSET = 4;

    private const SALT_LENGTH = 8;

    /** Prefix + count + salt: the part of the string the output reproduces. */
    private const SETTING_LENGTH = 12;

    /**
     * Recompute the stored hash from a password and the stored string.
     *
     * Returns null when the stored string is not a well-formed portable phpass
     * hash — which the caller must report as MALFORMED rather than as a wrong
     * password, because it means the column was truncated or holds something
     * else entirely, for every affected row.
     *
     * The comparison is NOT done here. This returns the recomputed string and
     * the caller runs the one `hash_equals` in the plugin, so there is a single
     * place where constant-time comparison has to be got right.
     */
    public static function recompute(#[\SensitiveParameter] string $password, string $stored): ?string
    {
        if (!self::isWellFormed($stored)) {
            return null;
        }

        $countLog2 = strpos(self::ITOA64, $stored[3]);

        // strpos() returns false for a character outside the alphabet, which
        // in a numeric comparison would silently become 0 and then
        // `1 << 0` = one iteration — a hash computed with a work factor of
        // ONE, that still has the right shape. isWellFormed() rejects that
        // case; this is the belt-and-braces check that it did.
        if ($countLog2 === false
            || $countLog2 < self::MIN_COUNT_LOG2
            || $countLog2 > self::MAX_COUNT_LOG2
        ) {
            return null;
        }

        $salt = substr($stored, self::SALT_OFFSET, self::SALT_LENGTH);
        $hash = md5($salt . $password, true);

        // `1 << 30` iterations of MD5 would be about an hour. The ceiling on
        // countLog2 is what bounds it; MAX_COUNT_LOG2 is phpass's own limit,
        // and the service applies a tighter configurable one on top.
        $iterations = 1 << $countLog2;

        for ($i = 0; $i < $iterations; $i++) {
            $hash = md5($hash . $password, true);
        }

        return substr($stored, 0, self::SETTING_LENGTH) . self::encode64($hash);
    }

    /**
     * The iteration count a stored hash declares, or null if malformed.
     *
     * Exposed so the service can refuse an absurd work factor BEFORE spending
     * it, and so a migration report can say what it is up against.
     */
    public static function iterations(string $stored): ?int
    {
        if (!self::isWellFormed($stored)) {
            return null;
        }

        $countLog2 = strpos(self::ITOA64, $stored[3]);

        if ($countLog2 === false
            || $countLog2 < self::MIN_COUNT_LOG2
            || $countLog2 > self::MAX_COUNT_LOG2
        ) {
            return null;
        }

        return 1 << $countLog2;
    }

    /** Whether a string is shaped like a portable phpass hash. */
    public static function isWellFormed(string $stored): bool
    {
        if (\strlen($stored) !== self::LENGTH) {
            return false;
        }

        if (!\in_array(substr($stored, 0, 3), self::PREFIXES, true)) {
            return false;
        }

        $countLog2 = strpos(self::ITOA64, $stored[3]);

        if ($countLog2 === false
            || $countLog2 < self::MIN_COUNT_LOG2
            || $countLog2 > self::MAX_COUNT_LOG2
        ) {
            return false;
        }

        // Every remaining character must be in the alphabet. Without this a
        // string of the right length and prefix but with, say, a `+` in the
        // salt would be accepted, hashed, and reported as a wrong password.
        $rest = substr($stored, self::SALT_OFFSET);

        return strspn($rest, self::ITOA64) === \strlen($rest);
    }

    /**
     * phpass's encode64 — three bytes to four characters, low bits first.
     *
     * Not `base64_encode()` with a substituted alphabet. Two differences:
     * the six-bit groups are taken from the LOW end of each little-endian
     * 24-bit group, and there is no `=` padding, so a 16-byte digest becomes
     * 22 characters rather than 24.
     *
     * The loop's shape is dictated by that 16 is not a multiple of 3: the
     * final group holds one byte and emits two characters, which is why the
     * length checks are inside the loop rather than being a clean `for`.
     */
    private static function encode64(string $input): string
    {
        $count  = \strlen($input);
        $output = '';
        $i      = 0;

        do {
            $value = \ord($input[$i++]);
            $output .= self::ITOA64[$value & 0x3F];

            if ($i < $count) {
                $value |= \ord($input[$i]) << 8;
            }

            $output .= self::ITOA64[($value >> 6) & 0x3F];

            if ($i++ >= $count) {
                break;
            }

            if ($i < $count) {
                $value |= \ord($input[$i]) << 16;
            }

            $output .= self::ITOA64[($value >> 12) & 0x3F];

            if ($i++ >= $count) {
                break;
            }

            $output .= self::ITOA64[($value >> 18) & 0x3F];
        } while ($i < $count);

        return $output;
    }
}
