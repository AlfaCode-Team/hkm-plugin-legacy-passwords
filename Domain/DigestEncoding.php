<?php

declare(strict_types=1);

namespace Plugins\LegacyPasswords\Domain;

/**
 * How a bare digest was written into the column.
 *
 * The same 16 bytes appear as 32 lower-case hex characters, 32 upper-case ones,
 * or 24 characters of base64. Declaring the wrong one fails every verification,
 * so it is declared rather than sniffed — with one exception, below.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * WHY CASE IS NOT SNIFFED AND LENGTH IS NOT EITHER
 * ────────────────────────────────────────────────────────────────────────────
 *
 * Case LOOKS sniffable: a lower-case hex digest is unambiguous. But a digest
 * of all digits — which happens about once in 1.2 million for MD5, so several
 * times in a large user table — is valid in both cases and valid base64 too,
 * and a sniffer would silently pick whichever branch it tested first for
 * exactly those users.
 *
 * The verifier therefore {@see encode()}s the digest it computed with the
 * DECLARED encoding and compares that against the stored string verbatim,
 * rather than trying to recognise what the stored string is. A mistake in the
 * declaration then fails loudly for everybody, instead of quietly for the
 * handful of users whose digest happened to be ambiguous.
 */
enum DigestEncoding: string
{
    case HexLower = 'hex_lower';

    case HexUpper = 'hex_upper';

    case Base64 = 'base64';

    /** Encode raw digest bytes the way the source system wrote them. */
    public function encode(string $raw): string
    {
        return match ($this) {
            self::HexLower => bin2hex($raw),
            self::HexUpper => strtoupper(bin2hex($raw)),
            self::Base64   => base64_encode($raw),
        };
    }

    /**
     * The expected string length for a digest of `$bytes` raw bytes.
     *
     * Used to reject a truncated column BEFORE spending the hash — a 31-char
     * MD5 is an import that lost a character, not a wrong password, and the
     * two deserve different reports.
     */
    public function lengthFor(int $bytes): int
    {
        return match ($this) {
            self::HexLower, self::HexUpper => $bytes * 2,
            // 4 characters per 3 bytes, padded up.
            self::Base64 => (int) (4 * ceil($bytes / 3)),
        };
    }
}
