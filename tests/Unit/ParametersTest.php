<?php

declare(strict_types=1);

namespace Tests\Plugins\LegacyPasswords\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Plugins\LegacyPasswords\Domain\DigestEncoding;
use Plugins\LegacyPasswords\Domain\FirebaseParameters;
use Plugins\LegacyPasswords\Domain\ScryptParameters;

/**
 * The out-of-band parameter objects for the two scrypt families.
 *
 * These carry no cryptography — they validate, and every assertion here is
 * about refusing a configuration that would otherwise fail silently for every
 * user in the import.
 */
final class ParametersTest extends TestCase
{
    public function test_it_accepts_firebase_defaults(): void
    {
        $parameters = ScryptParameters::firebase(salt: 'abcdefghijklmnop');

        self::assertSame(16384, $parameters->n);
        self::assertSame(8, $parameters->r);
        self::assertSame(1, $parameters->p);
        self::assertSame(64, $parameters->length);
        // 128 * 8 * 16384 = 16 MiB.
        self::assertSame(16 * 1024 * 1024, $parameters->memoryBytes());
    }

    /**
     * `mem_cost` is an EXPONENT, and passing N where it is expected has to be
     * refused.
     *
     * A Firebase export says `mem_cost: 14`, meaning N = 2^14 = 16384. Somebody
     * who knows scrypt will read "memory cost" and pass 16384 — and 2^16384
     * bytes is a number with 4,933 digits. The refusal names the distinction
     * because the two values are both plausible-looking integers.
     */
    public function test_a_memory_cost_passed_as_n_is_refused(): void
    {
        $this->expectException(\DomainException::class);
        $this->expectExceptionMessageMatches('/it is an EXPONENT/');

        ScryptParameters::firebase(memoryCost: 16384, salt: 'x');
    }

    /**
     * N must be a power of two, and the message explains the likely mistake.
     *
     * 14 is a valid-looking integer and the single most likely wrong value,
     * because it is what a Firebase export calls the memory cost.
     */
    public function test_n_must_be_a_power_of_two(): void
    {
        $this->expectException(\DomainException::class);
        $this->expectExceptionMessageMatches('/MEMORY COST EXPONENT/');

        ScryptParameters::of(n: 14, r: 8, p: 1, length: 64, salt: 'x');
    }

    #[DataProvider('refusedParameters')]
    public function test_it_refuses_parameters_outside_what_scrypt_allows(
        int $n,
        int $r,
        int $p,
        int $length,
        string $expectedMessage,
    ): void {
        $this->expectException(\DomainException::class);
        $this->expectExceptionMessageMatches($expectedMessage);

        ScryptParameters::of(n: $n, r: $r, p: $p, length: $length, salt: 'x');
    }

    /** @return iterable<string, array{int, int, int, int, string}> */
    public static function refusedParameters(): iterable
    {
        yield 'N of 1' => [1, 8, 1, 64, '/power of two greater than 1/'];
        yield 'N of 0' => [0, 8, 1, 64, '/power of two greater than 1/'];
        yield 'negative N' => [-16, 8, 1, 64, '/power of two greater than 1/'];
        yield 'r of 0' => [16, 0, 1, 64, '/r must be between/'];
        yield 'r above the cap' => [16, 65, 1, 64, '/r must be between/'];
        yield 'p of 0' => [16, 8, 0, 64, '/p must be between/'];
        yield 'p above the cap' => [16, 8, 17, 64, '/p must be between/'];
        yield 'length below the floor' => [16, 8, 1, 8, '/output length must be between/'];
        yield 'length above the cap' => [16, 8, 1, 2048, '/output length must be between/'];
        // 128 * 8 * 2^20 = 1 GiB, above the 256 MiB default ceiling.
        yield 'memory above the ceiling' => [1 << 20, 8, 1, 64, '/above the .* MB ceiling/'];
    }

    /**
     * An absurd N is refused by the ceiling, not by an overflow accident.
     *
     * An earlier version of this test asserted that `128 * r * N` wraps
     * NEGATIVE on a 64-bit build and that the float arithmetic in
     * `ScryptParameters` was therefore load-bearing. That is C's behaviour,
     * not PHP's — PHP PROMOTES TO FLOAT on integer overflow. The assertion
     * below records what actually happens, so the next reader does not inherit
     * the wrong model.
     */
    public function test_an_absurd_n_is_refused_by_the_ceiling(): void
    {
        $n = 1 << 60;

        // What PHP really does: promote, not wrap.
        self::assertIsFloat(128 * 8 * $n, 'PHP promotes an overflowing int product to float');
        self::assertGreaterThan(0, 128 * 8 * $n);

        $this->expectException(\DomainException::class);
        $this->expectExceptionMessageMatches('/ceiling/');

        ScryptParameters::of(n: $n, r: 8, p: 1, length: 64, salt: 'x');
    }

    public function test_the_salt_is_described_by_length_and_never_printed(): void
    {
        $parameters = ScryptParameters::of(
            n: 16, r: 1, p: 1, length: 64, salt: 'a-recognisable-salt',
        );

        $described = json_encode($parameters->describe());

        self::assertIsString($described);
        self::assertStringNotContainsString('a-recognisable-salt', $described);
        self::assertStringContainsString('"salt_bytes":19', $described);
    }

    public function test_the_stored_encoding_is_declared_and_defaults_to_hex(): void
    {
        $default = ScryptParameters::of(n: 16, r: 1, p: 1, length: 64, salt: 'x');
        self::assertSame(DigestEncoding::HexLower, $default->encoding);

        $explicit = ScryptParameters::of(
            n: 16, r: 1, p: 1, length: 64, salt: 'x', encoding: DigestEncoding::Base64,
        );
        self::assertSame(DigestEncoding::Base64, $explicit->encoding);

        // Firebase's export writes base64, so the named constructor says so
        // rather than inheriting the default.
        self::assertSame(DigestEncoding::Base64, ScryptParameters::firebase(salt: 'x')->encoding);
    }

    // ── Firebase ────────────────────────────────────────────────────────────

    /**
     * AN EMPTY SIGNER KEY IS A TOTAL AUTHENTICATION BYPASS, so it is refused
     * at construction.
     *
     * The Firebase construction encrypts the SIGNER KEY under a key derived
     * from the password. With no signer key there is no plaintext, and
     * `openssl_encrypt('', 'aes-256-ctr', …)` returns the EMPTY STRING rather
     * than false — measured. So every password would hash to `''`, every
     * comparison would be `'' === ''`, and every password would verify for
     * every user. Reached by forgetting one field of the export.
     */
    public function test_an_empty_signer_key_is_refused(): void
    {
        // The measurement the refusal rests on.
        self::assertSame(
            '',
            openssl_encrypt('', 'aes-256-ctr', str_repeat('k', 32), \OPENSSL_RAW_DATA, str_repeat("\0", 16)),
            'openssl_encrypt no longer returns the empty string for empty input — recheck this guard',
        );

        $this->expectException(\DomainException::class);
        $this->expectExceptionMessageMatches('/every password would therefore verify/');

        FirebaseParameters::of(salt: 'abc', saltSeparator: "\x07", signerKey: '');
    }

    public function test_an_empty_salt_separator_is_refused(): void
    {
        $this->expectException(\DomainException::class);
        $this->expectExceptionMessageMatches('/base64_salt_separator/');

        FirebaseParameters::of(salt: 'abc', saltSeparator: '', signerKey: 'k');
    }

    public function test_an_empty_per_user_salt_is_refused(): void
    {
        $this->expectException(\DomainException::class);
        $this->expectExceptionMessageMatches('/not on hash_config/');

        FirebaseParameters::of(salt: '', saltSeparator: "\x07", signerKey: 'k');
    }

    /**
     * The separator is APPENDED to the salt, not used as a delimiter.
     *
     * `Bw==` decodes to a single 0x07 byte, and the scrypt salt is
     * `salt ‖ separator`. Reading it as a delimiter — or omitting it — changes
     * the derived key for every user.
     */
    public function test_the_separator_is_concatenated_onto_the_salt(): void
    {
        $parameters = FirebaseParameters::of(
            salt: 'SALT', saltSeparator: "\x07", signerKey: 'key',
        );

        self::assertSame("SALT\x07", $parameters->scrypt()->salt);
    }

    /**
     * `fromExport()` decodes STRICTLY.
     *
     * `base64_decode()` in its default lenient mode ignores characters it does
     * not recognise and returns something plausible for almost any input — so
     * a field mangled by a line break would decode to a shorter, wrong byte
     * string and fail for every user with nothing to explain it.
     */
    #[DataProvider('badBase64')]
    public function test_from_export_refuses_input_that_is_not_base64(string $value): void
    {
        // Show that lenient decoding would have accepted it, which is the
        // whole reason strict mode is specified.
        self::assertNotFalse(
            base64_decode($value),
            'lenient decoding rejects this too, so it is not a useful case',
        );

        $this->expectException(\DomainException::class);
        $this->expectExceptionMessageMatches('/not valid base64/');

        FirebaseParameters::fromExport(
            base64Salt:          $value,
            base64SaltSeparator: 'Bw==',
            base64SignerKey:     base64_encode('key'),
        );
    }

    /** @return iterable<string, array{string}> */
    public static function badBase64(): iterable
    {
        yield 'a stray quote' => ['"AAAA"'];
        yield 'an underscore, which is base64url not base64' => ['AA_A'];
        yield 'a comma' => ['AA,A'];
    }

    public function test_from_export_decodes_the_fields(): void
    {
        $parameters = FirebaseParameters::fromExport(
            base64Salt:          base64_encode('the-salt'),
            base64SaltSeparator: 'Bw==',
            base64SignerKey:     base64_encode('the-signer-key'),
        );

        self::assertSame('the-salt', $parameters->salt);
        self::assertSame("\x07", $parameters->saltSeparator);
        self::assertSame('the-signer-key', $parameters->signerKey);
    }

    public function test_the_signer_key_is_never_printed(): void
    {
        $parameters = FirebaseParameters::of(
            salt: 'a-salt', saltSeparator: "\x07", signerKey: 'THE-PROJECT-SECRET',
        );

        $described = json_encode($parameters->describe());
        self::assertIsString($described);
        self::assertStringNotContainsString('THE-PROJECT-SECRET', $described);
        self::assertStringContainsString('[redacted: 18 bytes]', $described);

        // __debugInfo covers a var_dump and an uncaught-exception dump, which
        // is the path that actually leaks in production.
        $dumped = print_r($parameters->__debugInfo(), true);
        self::assertStringNotContainsString('THE-PROJECT-SECRET', $dumped);
        self::assertStringNotContainsString('a-salt', $dumped);
    }
}
