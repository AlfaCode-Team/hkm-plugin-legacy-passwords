<?php

declare(strict_types=1);

namespace Plugins\LegacyPasswords\Domain;

/**
 * What a second or later digest round is fed.
 *
 * `md5(md5($password))` is ambiguous across languages, and the ambiguity is
 * not subtle — the two readings share no output bytes at all:
 *
 *     PHP:    md5(md5($pw))                 → hashes the 32-char HEX STRING
 *     Python: md5(md5(pw).digest())         → hashes the 16 RAW BYTES
 *     Python: md5(md5(pw).hexdigest())      → hashes the hex, like PHP
 *
 * Which one a legacy column holds depends on what wrote it, and there is no
 * way to tell from the stored value. So it is declared.
 *
 * {@see Hex} is the default because this whole family of hashes is largely
 * PHP's legacy and PHP's `md5()`/`sha1()` return hex by default — the
 * double-hash idiom in a 2005 PHP login page is almost always the hex one.
 */
enum DigestRoundInput: string
{
    /** Re-feed the lower-case hex of the previous digest. PHP's `md5(md5($x))`. */
    case Hex = 'hex';

    /** Re-feed the previous digest's raw bytes. Most other languages. */
    case Raw = 'raw';
}
