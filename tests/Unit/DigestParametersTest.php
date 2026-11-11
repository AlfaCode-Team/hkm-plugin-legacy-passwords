<?php

declare(strict_types=1);

namespace Tests\Plugins\LegacyPasswords\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Plugins\LegacyPasswords\Domain\DigestEncoding;
use Plugins\LegacyPasswords\Domain\DigestParameters;
use Plugins\LegacyPasswords\Domain\DigestRoundInput;
use Plugins\LegacyPasswords\Domain\SaltPlacement;
use Tests\Plugins\LegacyPasswords\Support\Vectors;

final class DigestParametersTest extends TestCase
{
    /**
     * The known-answer test, against digests Python produced.
     *
     * This is the family Appwrite's importer cannot read at all — its `md5`
     * and `sha` algorithms hash the password and nothing else — so these are
     * the vectors that matter most for a real migration off an old PHP
     * application.
     */
    #[DataProvider('vectors')]
    public function test_it_reproduces_a_digest_python_produced(
        string $password,
        string $salt,
        string $algorithm,
        string $placement,
        string $expected,
    ): void {
        $parameters = DigestParameters::of(
            algorithm: $algorithm,
            salt:      $salt,
            placement: SaltPlacement::from($placement),
        );

        self::assertSame($expected, $parameters->compute($password));
    }

    /** @return iterable<string, array{string, string, string, string, string}> */
    public static function vectors(): iterable
    {
        foreach (Vectors::digests() as $vector) {
            yield $vector['algorithm'] . ' ' . $vector['placement'] => [
                $vector['password'],
                $vector['salt'],
                $vector['algorithm'],
                $vector['placement'],
                $vector['hex'],
            ];
        }
    }

    /**
     * Prefix and suffix are DIFFERENT, and nothing can recover which was used.
     *
     * Same password, same salt, same algorithm — two digests sharing no bytes.
     * This is why placement is declared rather than guessed, and it is the
     * single most common way a digest import is got wrong: the declaration
     * looks right, and every user fails.
     */
    public function test_placement_changes_the_digest_completely(): void
    {
        $prefix = DigestParameters::of('md5', 's4lt', SaltPlacement::Prefix);
        $suffix = DigestParameters::of('md5', 's4lt', SaltPlacement::Suffix);

        $a = $prefix->compute('secret');
        $b = $suffix->compute('secret');

        self::assertNotSame($a, $b);
        // Both are valid md5 hex, so neither is distinguishable as "the wrong
        // one" from its shape alone.
        self::assertMatchesRegularExpression('/^[0-9a-f]{32}$/D', $a);
        self::assertMatchesRegularExpression('/^[0-9a-f]{32}$/D', $b);
    }

    /**
     * A salt with placement None would be silently ignored, so it is refused.
     *
     * That configuration LOOKS correct — the salt is right there in the
     * config, being used by nothing — and every user fails. Failing at
     * construction is the only point at which it is visible.
     */
    public function test_a_salt_with_nowhere_to_go_is_refused(): void
    {
        $this->expectException(\DomainException::class);
        $this->expectExceptionMessageMatches('/would never be used/');

        DigestParameters::of('md5', 's4lt', SaltPlacement::None);
    }

    /**
     * And the reverse: a placement with no salt.
     *
     * Refused so the intent lives in the configuration rather than being
     * implied by a blank field — an empty salt with Prefix declared is
     * indistinguishable from "somebody forgot to wire the salt column".
     */
    public function test_a_placement_with_no_salt_is_refused(): void
    {
        $this->expectException(\DomainException::class);
        $this->expectExceptionMessageMatches('/empty salt/');

        DigestParameters::of('md5', '', SaltPlacement::Prefix);
    }

    /**
     * A checksum is not an authentication check.
     *
     * `hash()` accepts sixty algorithms including `crc32b` and `xxh64`. A
     * 32-bit checksum has collisions anybody can find in milliseconds, so a
     * column holding one would authenticate roughly one in four billion
     * guesses — which at modern speeds is minutes.
     */
    #[DataProvider('refusedAlgorithms')]
    public function test_a_checksum_is_refused_even_though_hash_accepts_it(string $algorithm): void
    {
        // Prove hash() really does accept it, so this test is about the
        // allowlist and not about a typo.
        self::assertContains($algorithm, hash_algos(), $algorithm . ' is not offered by this build');

        $this->expectException(\DomainException::class);
        $this->expectExceptionMessageMatches('/not an allowed legacy password digest/');

        DigestParameters::of($algorithm);
    }

    /** @return iterable<string, array{string}> */
    public static function refusedAlgorithms(): iterable
    {
        yield 'crc32b' => ['crc32b'];
        yield 'xxh64' => ['xxh64'];
        yield 'adler32' => ['adler32'];
        yield 'fnv132' => ['fnv132'];
    }

    public function test_the_algorithm_name_is_normalised(): void
    {
        $parameters = DigestParameters::of('  SHA256  ');

        self::assertSame('sha256', $parameters->algorithm);
        self::assertSame(32, $parameters->digestBytes());
    }

    /**
     * The expected string length is derived from the algorithm AND the
     * encoding.
     *
     * The service checks a stored digest against this BEFORE hashing, because
     * a length mismatch means a truncated column or a wrongly-declared
     * algorithm — both of which affect every row, and both of which would
     * otherwise be reported as a wrong password.
     */
    #[DataProvider('lengths')]
    public function test_the_expected_length_matches_what_the_encoding_produces(
        string $algorithm,
        DigestEncoding $encoding,
        int $expected,
    ): void {
        $parameters = DigestParameters::of($algorithm, encoding: $encoding);

        self::assertSame($expected, $parameters->expectedLength());
        // And the computed value really is that long, which is what makes the
        // check safe to apply as a guard rather than a hint.
        self::assertSame($expected, \strlen($parameters->compute('secret')));
    }

    /** @return iterable<string, array{string, DigestEncoding, int}> */
    public static function lengths(): iterable
    {
        yield 'md5 hex' => ['md5', DigestEncoding::HexLower, 32];
        yield 'md5 upper hex' => ['md5', DigestEncoding::HexUpper, 32];
        // 16 bytes is not a multiple of 3, so base64 pads — 24 characters,
        // and an implementation that computed 4*16/3 would say 21.
        yield 'md5 base64 pads' => ['md5', DigestEncoding::Base64, 24];
        yield 'sha1 hex' => ['sha1', DigestEncoding::HexLower, 40];
        yield 'sha1 base64 pads' => ['sha1', DigestEncoding::Base64, 28];
        yield 'sha256 hex' => ['sha256', DigestEncoding::HexLower, 64];
        // 32 bytes also pads.
        yield 'sha256 base64 pads' => ['sha256', DigestEncoding::Base64, 44];
        // 48 bytes IS a multiple of 3, so no padding at all.
        yield 'sha384 base64 does not pad' => ['sha384', DigestEncoding::Base64, 64];
        yield 'sha512 hex' => ['sha512', DigestEncoding::HexLower, 128];
    }

    public function test_the_encoding_is_applied_to_the_same_bytes(): void
    {
        $lower = DigestParameters::of('md5', encoding: DigestEncoding::HexLower)->compute('secret');
        $upper = DigestParameters::of('md5', encoding: DigestEncoding::HexUpper)->compute('secret');
        $b64   = DigestParameters::of('md5', encoding: DigestEncoding::Base64)->compute('secret');

        self::assertSame(strtoupper($lower), $upper);
        self::assertSame(base64_encode(hex2bin($lower)), $b64);
    }

    /**
     * `md5(md5($x))` means two different things, and the difference is total.
     *
     * In PHP the inner call returns HEX and the outer hashes those 32
     * characters; in most other languages it returns raw bytes and the outer
     * hashes those 16. Which one a legacy column holds depends on what wrote
     * it, and the stored value cannot say — so it is declared, and this test
     * pins both readings against digests computed the long way round.
     */
    public function test_a_second_round_can_re_feed_hex_or_raw(): void
    {
        $hex = DigestParameters::of('md5', rounds: 2, roundInput: DigestRoundInput::Hex);
        $raw = DigestParameters::of('md5', rounds: 2, roundInput: DigestRoundInput::Raw);

        // PHP's idiom, spelled out.
        self::assertSame(md5(md5('secret')), $hex->compute('secret'));
        // The raw reading, spelled out.
        self::assertSame(md5(md5('secret', true)), $raw->compute('secret'));

        self::assertNotSame($hex->compute('secret'), $raw->compute('secret'));
    }

    /** One round must be exactly a plain digest, with no re-feeding at all. */
    public function test_one_round_is_a_plain_digest(): void
    {
        self::assertSame(
            md5('secret'),
            DigestParameters::of('md5', rounds: 1)->compute('secret'),
        );
    }

    /**
     * The salt is applied in ROUND ONE ONLY, and that boundary is deliberate.
     *
     * vBulletin's `md5(md5($password) . $salt)` applies it in round TWO. That
     * is a different scheme and is NOT supported — supporting it would mean
     * another configuration axis whose wrong setting fails silently. The test
     * exists to make the boundary explicit rather than discovered.
     */
    public function test_the_salt_is_applied_only_in_the_first_round(): void
    {
        $parameters = DigestParameters::of(
            'md5',
            's4lt',
            SaltPlacement::Prefix,
            rounds: 2,
        );

        self::assertSame(md5(md5('s4lt' . 'secret')), $parameters->compute('secret'));

        // And explicitly NOT vBulletin's shape, so nobody configures this
        // expecting that and gets a silent mismatch.
        self::assertNotSame(md5(md5('secret') . 's4lt'), $parameters->compute('secret'));
    }

    #[DataProvider('refusedRounds')]
    public function test_an_impossible_round_count_is_refused(int $rounds): void
    {
        $this->expectException(\DomainException::class);
        $this->expectExceptionMessageMatches('/rounds must be between/');

        DigestParameters::of('md5', rounds: $rounds);
    }

    /** @return iterable<string, array{int}> */
    public static function refusedRounds(): iterable
    {
        yield 'zero' => [0];
        yield 'negative' => [-1];
        // A count in the thousands is PBKDF2, which handles its salt and
        // iteration count properly — the message says so.
        yield 'a PBKDF2-sized count' => [100000];
        yield 'one above the cap' => [DigestParameters::MAX_ROUNDS + 1];
    }

    /** The salt is never printed, only measured. */
    public function test_describe_and_debug_output_carry_no_salt(): void
    {
        $parameters = DigestParameters::of('md5', 'super-secret-salt', SaltPlacement::Prefix);

        $described = json_encode($parameters->describe());
        self::assertIsString($described);
        self::assertStringNotContainsString('super-secret-salt', $described);
        self::assertStringContainsString('"salt_bytes":17', $described);

        $dumped = print_r($parameters->__debugInfo(), true);
        self::assertStringNotContainsString('super-secret-salt', $dumped);
    }

    /**
     * Every allowlisted algorithm is one this build can actually run, and the
     * declared digest length is the real one.
     *
     * A wrong length in ALLOWED would make `expectedLength()` reject every
     * valid row for that algorithm, so the table is checked against `hash()`
     * rather than trusted.
     */
    public function test_every_allowed_algorithm_exists_with_the_declared_length(): void
    {
        foreach (DigestParameters::ALLOWED as $algorithm => $bytes) {
            self::assertContains($algorithm, hash_algos(), $algorithm . ' is not available');
            self::assertSame(
                $bytes,
                \strlen(hash($algorithm, 'x', true)),
                $algorithm . ' does not produce ' . $bytes . ' bytes',
            );
        }
    }
}
