<?php

declare(strict_types=1);

namespace Tests\Plugins\LegacyPasswords\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Plugins\LegacyPasswords\Domain\Algorithms\Argon2Hash;

final class Argon2HashTest extends TestCase
{
    /**
     * THE REASON THIS CLASS EXISTS, pinned as a test — and it is narrower than
     * an earlier draft of it claimed.
     *
     * `password_get_info()` DOES read the declared `m`, `t` and `p` out of a
     * well-formed hash. The first version of this test asserted otherwise, on
     * the strength of a hash declaring `m=65536` — which is also PHP's default,
     * so the experiment could not distinguish "parsed" from "defaulted". It is
     * asserted here, positively, so the record is right.
     *
     * What `password_get_info()` cannot do is FAIL. It recognises Argon2 by
     * prefix, needs neither a salt nor a hash to be present, and silently
     * substitutes PHP's defaults for a parameter field it cannot read. Those
     * are the three things asserted below, and they are what a ceiling and a
     * malformed-versus-wrong-password distinction actually rest on.
     */
    public function test_password_get_info_cannot_fail_on_a_hash_that_is_not_one(): void
    {
        // It DOES parse real parameters. Non-default values, so this means
        // something.
        $huge = '$argon2id$v=19$m=4194304,t=8,p=4$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNo';

        self::assertSame(4194304, password_get_info($huge)['options']['memory_cost'] ?? null);
        self::assertSame(4194304, Argon2Hash::parse($huge)?->memoryCost, 'and so does the parser');

        // 1. A bare prefix is reported as a valid argon2id hash.
        self::assertSame('argon2id', password_get_info('$argon2id$')['algo']);
        self::assertNull(Argon2Hash::parse('$argon2id$'), 'the parser must reject a bare prefix');

        // 2. So is a hash truncated after its parameters — no salt, no digest.
        $truncated = '$argon2id$v=19$m=8192,t=2,p=1';
        self::assertSame('argon2id', password_get_info($truncated)['algo']);
        self::assertNull(Argon2Hash::parse($truncated), 'the parser must reject a truncated hash');

        // 3. An unparseable cost field reads back as PHP's OWN DEFAULT rather
        //    than as a failure, so a ceiling consulting it would compare a
        //    number that came from this machine's configuration and not from
        //    the hash — and wave through a row whose real cost is unknown.
        $garbled = '$argon2id$v=19$m=zzz,t=2,p=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2g';
        self::assertSame(65536, password_get_info($garbled)['options']['memory_cost'] ?? null);
        self::assertNull(Argon2Hash::parse($garbled), 'the parser must reject an unreadable cost');
    }

    public function test_it_parses_a_real_hash_php_produced(): void
    {
        $hash = password_hash('secret', \PASSWORD_ARGON2ID, [
            'memory_cost' => 8192,
            'time_cost'   => 2,
            'threads'     => 1,
        ]);

        $parsed = Argon2Hash::parse($hash);

        self::assertNotNull($parsed);
        self::assertSame('argon2id', $parsed->variant);
        self::assertSame(19, $parsed->version);
        self::assertSame(8192, $parsed->memoryCost);
        self::assertSame(2, $parsed->timeCost);
        self::assertSame(1, $parsed->parallelism);
        self::assertTrue($parsed->verifiableHere());

        // The salt and hash lengths are computed from unpadded base64 without
        // decoding. PHP uses a 16-byte salt and a 32-byte output by default.
        self::assertSame(16, $parsed->saltBytes);
        self::assertSame(32, $parsed->hashBytes);
    }

    /**
     * argon2d parses, and is reported as unverifiable rather than malformed.
     *
     * The distinction matters operationally: the hash is perfectly valid and
     * this build simply cannot check it. Calling that "malformed" sends an
     * operator looking for a corrupt import that does not exist.
     */
    public function test_argon2d_parses_but_is_not_verifiable_here(): void
    {
        $hash = '$argon2d$v=19$m=65536,t=4,p=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNo';

        $parsed = Argon2Hash::parse($hash);

        self::assertNotNull($parsed, 'argon2d is a valid format and must parse');
        self::assertSame('argon2d', $parsed->variant);
        self::assertFalse($parsed->verifiableHere());

        // PHP's own view, which is where "malformed" would have come from.
        self::assertNull(password_get_info($hash)['algo']);
        self::assertNotContains('argon2d', password_algos());
    }

    #[DataProvider('malformed')]
    public function test_it_refuses_a_malformed_hash(string $stored, string $why): void
    {
        self::assertNull(Argon2Hash::parse($stored), $why);
    }

    /** @return iterable<string, array{string, string}> */
    public static function malformed(): iterable
    {
        yield 'empty' => ['', 'an empty column is not a hash'];
        yield 'prefix only' => ['$argon2id$', 'password_get_info accepts this; the parser must not'];
        yield 'version only' => ['$argon2id$v=19$', 'no parameters, no salt, no hash'];
        yield 'no salt or hash' => ['$argon2id$v=19$m=65536,t=4,p=1', 'truncated after the parameters'];
        yield 'salt but no hash' => [
            '$argon2id$v=19$m=65536,t=4,p=1$c2FsdHNhbHRzYWx0', 'truncated after the salt',
        ];
        yield 'unknown variant' => [
            '$argon2zz$v=19$m=65536,t=4,p=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2g', 'not an Argon2 variant',
        ];
        yield 'unknown version' => [
            '$argon2id$v=16$m=65536,t=4,p=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2g',
            'only v19 exists; accepting another would claim to understand parameters that may differ',
        ];
        yield 'parameters out of order' => [
            '$argon2id$v=19$t=4,m=65536,p=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2g',
            'the PHC order is m,t,p and nothing emits another',
        ];
        yield 'missing a parameter' => [
            '$argon2id$v=19$m=65536,t=4$c2FsdHNhbHRzYWx0$aGFzaGhhc2g', 'p is absent',
        ];
        yield 'salt too short' => [
            '$argon2id$v=19$m=65536,t=4,p=1$c2E$aGFzaGhhc2g',
            'two bytes of salt is below Argon2\'s own minimum of eight',
        ];
        yield 'padded base64' => [
            '$argon2id$v=19$m=65536,t=4,p=1$c2FsdHNhbHQ=$aGFzaGhhc2g=',
            'the PHC format is UNPADDED base64; `=` never appears',
        ];
        // PCRE's `$` also matches immediately before a final newline, so
        // without the /D modifier this would parse as valid — and the memory
        // cost of a hash carrying a newline would then be trusted.
        yield 'trailing newline' => [
            "\$argon2id\$v=19\$m=65536,t=4,p=1\$c2FsdHNhbHRzYWx0\$aGFzaGhhc2g\n",
            'anchored patterns need /D or a trailing newline slips through',
        ];
        yield 'leading whitespace' => [
            ' $argon2id$v=19$m=65536,t=4,p=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2g', 'not anchored at the start',
        ];
        yield 'bcrypt' => [
            '$2y$12$LongEnoughToLookLikeARealBcryptHashxxxxxxxxxxxxxxxxxxxxxx',
            'a different scheme entirely',
        ];
    }

    /**
     * Four base64 characters are three bytes, and a remainder of 1 is
     * impossible.
     *
     * No number of bytes encodes to 4n+1 characters, so a field of that length
     * is corrupted — and returning a plausible length for it would let a
     * truncated salt pass the minimum-length check.
     */
    #[DataProvider('base64Lengths')]
    public function test_the_decoded_length_is_computed_without_decoding(int $bytes): void
    {
        $encoded = rtrim(base64_encode(random_bytes($bytes)), '=');
        $hash    = '$argon2id$v=19$m=8,t=1,p=1$' . rtrim(base64_encode(random_bytes(16)), '=')
            . '$' . $encoded;

        $parsed = Argon2Hash::parse($hash);

        self::assertNotNull($parsed, $bytes . ' bytes of hash should parse');
        self::assertSame($bytes, $parsed->hashBytes);
    }

    /** @return iterable<string, array{int}> */
    public static function base64Lengths(): iterable
    {
        // 4 through 36 covers every remainder class several times over, which
        // is what catches an off-by-one in the 4n+2 / 4n+3 arms.
        foreach ([4, 5, 6, 7, 8, 15, 16, 17, 31, 32, 33, 36] as $bytes) {
            yield $bytes . ' bytes' => [$bytes];
        }
    }
}
