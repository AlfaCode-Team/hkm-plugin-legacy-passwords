<?php

declare(strict_types=1);

namespace Plugins\LegacyPasswords\Domain\Algorithms;

/**
 * Parses an Argon2 PHC string, because `password_get_info()` does not.
 *
 * ════════════════════════════════════════════════════════════════════════════
 * WHY THIS CLASS EXISTS AT ALL
 * ════════════════════════════════════════════════════════════════════════════
 *
 * `password_get_info()` is the obvious tool, and it gets the EASY case right:
 * for a well-formed hash it does report the declared `m`, `t` and `p`. That
 * was checked, after an earlier draft of this file claimed otherwise on the
 * strength of a test whose hash declared `m=65536` — which is also PHP's
 * default, so the experiment could not tell "parsed" from "defaulted".
 *
 * What it does NOT do is fail on a hash that is not one. Measured:
 *
 *     password_get_info('$argon2id$')
 *       → algo 'argon2id', options {m: 65536, t: 4, p: 1}
 *     password_get_info('$argon2id$v=19$m=8192,t=2,p=1')     // no salt, no hash
 *       → algo 'argon2id', options {m: 8192,  t: 2, p: 1}
 *     password_get_info('$argon2id$v=19$m=zzz,t=2,p=1$c2FsdA$aaaa')
 *       → algo 'argon2id', options {m: 65536, t: 4, p: 1}    // DEFAULTS, silently
 *
 * It recognises Argon2 by PREFIX alone, requires neither a salt nor a hash to
 * be present, and when the parameter field is unparseable it substitutes PHP's
 * own defaults rather than reporting a problem. So three things this class
 * provides are genuinely absent there:
 *
 *  1. A TRUNCATED ARGON2 HASH LOOKS WELL FORMED. A corrupted import is then
 *     reported as "wrong password" for every affected user, instead of as the
 *     broken import it is — which is the single most expensive way for a
 *     migration to fail, because it is indistinguishable from the thing it is
 *     supposed to detect.
 *  2. A GARBLED COST FIELD READS AS THE DEFAULT. A ceiling that consulted
 *     `password_get_info()` for `m=zzz` would compare 65536 — a number from
 *     this machine's configuration, not from the hash — and wave through a row
 *     whose real cost is unknown.
 *  3. argon2d IS REPORTED AS `algo => null`, so leaning on PHP's answer calls
 *     a valid hash malformed. See below.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * THE FORMAT
 * ────────────────────────────────────────────────────────────────────────────
 *
 *     $argon2id$v=19$m=65536,t=4,p=1$ZG4zL1U3NkFaRnRMTERuRw$nUEvyl…
 *     └───┬───┘ └─┬─┘ └──────┬─────┘ └─────────┬──────────┘ └──┬──┘
 *      variant  version   parameters          salt            hash
 *
 * The salt and hash are base64 WITHOUT padding — `=` never appears, which is
 * why the decode below strips nothing and pads instead.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * argon2d IS PARSED AND REPORTED UNSUPPORTED, NOT MALFORMED
 * ────────────────────────────────────────────────────────────────────────────
 *
 * PHP cannot verify argon2d: `password_get_info('$argon2d$…')` returns
 * `algo => null` and `password_verify()` returns false for a hash that is
 * perfectly valid. Leaning on PHP's answer would therefore report a good hash
 * as corrupt, and send an operator looking for an import bug that is not
 * there. The hash is fine; this build simply cannot check it, and those are
 * different sentences.
 */
final class Argon2Hash
{
    /** The variants that exist. Only two of them are verifiable by PHP. */
    public const VARIANTS = ['argon2i', 'argon2id', 'argon2d'];

    /** The only version in the wild. 0x13 = 19. */
    public const VERSION = 19;

    private function __construct(
        public readonly string $variant,
        public readonly int $version,
        /** Memory cost in KiB — `m` in the string. */
        public readonly int $memoryCost,
        /** Iterations — `t`. */
        public readonly int $timeCost,
        /** Lanes — `p`. */
        public readonly int $parallelism,
        public readonly int $saltBytes,
        public readonly int $hashBytes,
    ) {}

    /**
     * Parse, or null when the string is not a well-formed Argon2 hash.
     *
     * Null means MALFORMED — a truncated or corrupted column, which affects
     * every row of the same shape and is an operational problem rather than a
     * wrong password.
     */
    public static function parse(string $stored): ?self
    {
        // Anchored with /D so a trailing newline cannot slip through: PCRE's
        // `$` also matches immediately BEFORE a final newline, so without the
        // modifier a hash ending in "\n" would parse as valid.
        $pattern = '/^\$(argon2id|argon2i|argon2d)\$v=(\d+)\$m=(\d+),t=(\d+),p=(\d+)\$'
            . '([A-Za-z0-9+\/]+)\$([A-Za-z0-9+\/]+)$/D';

        if (preg_match($pattern, $stored, $matches) !== 1) {
            return null;
        }

        [, $variant, $version, $memory, $time, $parallelism, $salt, $hash] = $matches;

        // Only v19 exists. Accepting an unknown version would mean claiming to
        // understand parameters whose meaning might differ.
        if ((int) $version !== self::VERSION) {
            return null;
        }

        $saltBytes = self::decodedLength($salt);
        $hashBytes = self::decodedLength($hash);

        // Argon2's own minimums: 8 bytes of salt, 4 bytes of output. A shorter
        // one is a truncated column, not a configuration.
        if ($saltBytes < 8 || $hashBytes < 4) {
            return null;
        }

        return new self(
            variant:     $variant,
            version:     (int) $version,
            memoryCost:  (int) $memory,
            timeCost:    (int) $time,
            parallelism: (int) $parallelism,
            saltBytes:   $saltBytes,
            hashBytes:   $hashBytes,
        );
    }

    /**
     * Whether PHP on this build can verify this variant.
     *
     * argon2d is never verifiable — PHP exposes only argon2i and argon2id — so
     * this is the check that turns a valid-but-uncheckable hash into
     * "unsupported" rather than "malformed".
     */
    public function verifiableHere(): bool
    {
        return \in_array($this->variant, password_algos(), true);
    }

    /**
     * The decoded byte length of unpadded base64, without decoding it.
     *
     * The bytes themselves are never needed — only their count, to reject a
     * truncated field. Four base64 characters carry three bytes, and the
     * remainder of 2 or 3 characters carries 1 or 2.
     */
    private static function decodedLength(string $encoded): int
    {
        $length    = \strlen($encoded);
        $whole     = intdiv($length, 4) * 3;
        $remainder = $length % 4;

        return match ($remainder) {
            0 => $whole,
            2 => $whole + 1,
            3 => $whole + 2,
            // A remainder of 1 is impossible in valid base64 — no number of
            // bytes encodes to 4n+1 characters — so it is a corrupted field.
            default => 0,
        };
    }
}
