<?php

declare(strict_types=1);

namespace Tests\Plugins\LegacyPasswords\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Plugins\LegacyPasswords\Domain\Algorithms\Phpass;
use Tests\Plugins\LegacyPasswords\Support\Vectors;

final class PhpassTest extends TestCase
{
    /**
     * The known-answer test. Every hash here was produced by Appwrite's
     * `Utopia\Auth\Hashes\PHPass` — a separate implementation by other people
     * — so passing means two independent implementations agree, not that this
     * one agrees with itself.
     */
    #[DataProvider('vectors')]
    public function test_it_reproduces_a_hash_from_another_implementation(string $password, string $hash): void
    {
        self::assertSame($hash, Phpass::recompute($password, $hash));
    }

    /** @return iterable<string, array{string, string}> */
    public static function vectors(): iterable
    {
        foreach (Vectors::phpass() as $i => $vector) {
            yield \sprintf('%s %s', $i, substr($vector['hash'], 0, 4)) => [
                $vector['password'],
                $vector['hash'],
            ];
        }
    }

    #[DataProvider('vectors')]
    public function test_a_wrong_password_does_not_reproduce_the_hash(string $password, string $hash): void
    {
        self::assertNotSame($hash, Phpass::recompute($password . 'x', $hash));
    }

    /**
     * `$P$` and `$H$` are the same algorithm with different prefixes, and the
     * output carries the prefix it was GIVEN rather than a canonical one.
     *
     * This is the property that lets one implementation serve WordPress and
     * phpBB3. If `recompute()` hard-coded `$P$`, a phpBB3 hash would come back
     * differing in exactly one character and every phpBB3 user would be told
     * their password was wrong.
     */
    public function test_the_prefix_is_preserved_rather_than_canonicalised(): void
    {
        $wordpress = '$P$Be.39vipNM3QIErUZ.CevixuseSbRo0';
        $phpbb     = '$H$' . substr($wordpress, 3);

        self::assertSame($wordpress, Phpass::recompute('secret', $wordpress));
        self::assertSame($phpbb, Phpass::recompute('secret', $phpbb));

        // And the two differ only in that character — so the test above is
        // genuinely about the prefix and not about two unrelated hashes.
        self::assertSame(substr($wordpress, 3), substr($phpbb, 3));
    }

    /**
     * The iteration count is `1 << index-in-itoa64`, and the alphabet's ORDER
     * is load-bearing.
     *
     * phpass's own file carries TWO base-64 alphabets a few lines apart, in
     * different orders — this one (`./0123456789ABC…`) for portable hashes and
     * `./ABC…XYZabc…012…9` for blowfish salts. Using the wrong one yields a
     * hash of exactly the right shape with every character wrong, so the
     * mapping is pinned explicitly.
     */
    #[DataProvider('iterationCounts')]
    public function test_the_count_character_decodes_to_a_power_of_two(string $character, int $expected): void
    {
        $hash = '$P$' . $character . 'e.39vipNM3QIErUZ.CevixuseSbRo0';

        self::assertSame($expected, Phpass::iterations($hash));
    }

    /** @return iterable<string, array{string, int}> */
    public static function iterationCounts(): iterable
    {
        // 'B' is index 13 — WordPress's default, and 8192 iterations.
        yield 'B is WordPress default' => ['B', 8192];
        yield 'E' => ['E', 65536];
        yield 'J' => ['J', 2097152];
        // '5' is index 7 — the alphabet starts `.`, `/`, `0`, so the digits
        // are offset by two and `5` lands on 7, not 8. That makes it exactly
        // MIN_COUNT_LOG2, so this row is the lower boundary: one character
        // earlier ('4', index 6) is refused, and this one must be accepted.
        yield '5 is the lowest accepted count' => ['5', 128];
    }

    /**
     * A count character below phpass's own floor is refused.
     *
     * `strpos()` returns FALSE for a character outside the alphabet, and false
     * in an arithmetic context is 0 — so `1 << strpos(...)` would be ONE
     * iteration. A hash verified with a work factor of one, that still has
     * exactly the right shape.
     */
    #[DataProvider('badCountCharacters')]
    public function test_a_count_outside_the_allowed_range_is_refused(string $character): void
    {
        $hash = '$P$' . $character . 'e.39vipNM3QIErUZ.CevixuseSbRo0';

        self::assertFalse(Phpass::isWellFormed($hash));
        self::assertNull(Phpass::iterations($hash));
        self::assertNull(Phpass::recompute('secret', $hash));
    }

    /** @return iterable<string, array{string}> */
    public static function badCountCharacters(): iterable
    {
        // '.' is index 0 and '/' is 1 — both below MIN_COUNT_LOG2 of 7.
        yield 'index 0 would mean one iteration' => ['.'];
        yield 'index 1' => ['/'];
        // '4' is index 6, one below the floor.
        yield 'index 6, one below the floor' => ['4'];
        // Outside the alphabet entirely, which is what makes strpos() false.
        yield 'not in the alphabet at all' => ['+'];
        yield 'also not in the alphabet' => ['$'];
    }

    #[DataProvider('malformed')]
    public function test_a_malformed_hash_is_refused_rather_than_hashed(string $stored): void
    {
        self::assertFalse(Phpass::isWellFormed($stored));
        self::assertNull(Phpass::recompute('secret', $stored));
    }

    /** @return iterable<string, array{string}> */
    public static function malformed(): iterable
    {
        yield 'empty' => [''];
        yield 'prefix only' => ['$P$'];
        yield 'one character short' => ['$P$Be.39vipNM3QIErUZ.CevixuseSbRo'];
        yield 'one character long' => ['$P$Be.39vipNM3QIErUZ.CevixuseSbRo00'];
        yield 'wrong prefix' => ['$Q$Be.39vipNM3QIErUZ.CevixuseSbRo0'];
        yield 'bcrypt, which is a different scheme' => ['$2y$12$e.39vipNM3QIErUZ.Cevixuse'];
        // Right length and prefix, but a character the alphabet does not hold.
        // Without the strspn() check this would be hashed and reported as a
        // wrong password.
        yield 'illegal character in the salt' => ['$P$Be+39vipNM3QIErUZ.CevixuseSbRo0'];
        yield 'illegal character in the digest' => ['$P$Be.39vipNM3QIErUZ.CevixuseSbR=0'];
    }

    /**
     * An empty STORED hash must never be treated as a hash.
     *
     * A null or blank password column is ordinary in an import — users who
     * never set one, or rows where the column did not come across — and this
     * is the first thing that has to refuse it.
     */
    public function test_an_empty_stored_value_is_not_a_hash(): void
    {
        self::assertNull(Phpass::recompute('', ''));
        self::assertNull(Phpass::recompute('anything', ''));
    }

    /**
     * The salt is read from offset 4 for exactly 8 characters.
     *
     * Pinned by changing ONE salt character and asserting the output moves.
     * An off-by-one in the offset or the length would still produce a valid
     * 34-character hash, so nothing about the shape of the output catches it.
     */
    public function test_every_salt_character_affects_the_result(): void
    {
        $base   = '$P$Be.39vipNM3QIErUZ.CevixuseSbRo0';
        $digest = Phpass::recompute('secret', $base);

        self::assertNotNull($digest);

        for ($position = 4; $position < 12; $position++) {
            $mutated = $base;
            // '.' and 'A' are both in the alphabet, so the mutation stays a
            // well-formed hash and the only thing that changed is the salt.
            $mutated[$position] = $base[$position] === 'A' ? '.' : 'A';

            $other = Phpass::recompute('secret', $mutated);

            self::assertNotNull($other, 'mutation at ' . $position . ' should still be well formed');
            self::assertNotSame(
                substr($digest, 12),
                substr($other, 12),
                'salt character at offset ' . $position . ' did not affect the digest',
            );
        }
    }

    /**
     * encode64 is NOT base64 with a substituted alphabet.
     *
     * Two differences: the six-bit groups come from the LOW end of each
     * little-endian 24-bit group, and there is no padding — so a 16-byte
     * digest becomes 22 characters, not 24. This asserts the length and that
     * a translated `base64_encode` does not match, which is the shortcut
     * somebody will eventually try.
     */
    public function test_the_encoding_is_not_translated_base64(): void
    {
        $hash = Phpass::recompute('secret', '$P$Be.39vipNM3QIErUZ.CevixuseSbRo0');

        self::assertNotNull($hash);

        $encoded = substr($hash, 12);
        self::assertSame(22, \strlen($encoded), 'a 16-byte digest encodes to 22 characters');

        // The same bytes through standard base64, alphabet-translated.
        $salt = substr($hash, 4, 8);
        $raw  = md5($salt . 'secret', true);
        for ($i = 0; $i < 8192; $i++) {
            $raw = md5($raw . 'secret', true);
        }

        $standard = rtrim(strtr(
            base64_encode($raw),
            'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
            Phpass::ITOA64,
        ), '=');

        self::assertNotSame(
            $standard,
            $encoded,
            'translated base64 happened to match — the encodings are not actually different',
        );
    }
}
