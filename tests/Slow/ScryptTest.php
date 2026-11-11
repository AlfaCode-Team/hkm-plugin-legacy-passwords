<?php

declare(strict_types=1);

namespace Tests\Plugins\LegacyPasswords\Slow;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Plugins\LegacyPasswords\Domain\Algorithms\FirebaseScrypt;
use Plugins\LegacyPasswords\Domain\Algorithms\Scrypt;
use Plugins\LegacyPasswords\Domain\DigestEncoding;
use Plugins\LegacyPasswords\Domain\FirebaseParameters;
use Plugins\LegacyPasswords\Domain\LegacyCredential;
use Plugins\LegacyPasswords\Domain\ScryptParameters;
use Plugins\LegacyPasswords\Infrastructure\Config\LegacyPasswordConfig;
use Plugins\LegacyPasswords\Application\Services\LegacyPasswordService;
use Tests\Plugins\LegacyPasswords\Support\RecordingHasher;
use Tests\Plugins\LegacyPasswords\Support\Vectors;

/**
 * The evidence that the pure-PHP scrypt is correct.
 *
 * ════════════════════════════════════════════════════════════════════════════
 * THIS IS THE MOST IMPORTANT FILE IN THE SUITE
 * ════════════════════════════════════════════════════════════════════════════
 *
 * Every other algorithm here is verified by something that already exists —
 * `password_verify`, `crypt`, `hash_pbkdf2`. scrypt is the one this plugin
 * IMPLEMENTS, in a few hundred lines of 32-bit arithmetic PHP performs one
 * operation at a time, and an off-by-one in the BlockMix shuffle or a missed
 * `& 0xFFFFFFFF` produces output that looks perfectly random and is simply
 * wrong. The only symptom would be every imported user being told their
 * password is incorrect.
 *
 * So the expected values here come from elsewhere: Python's `hashlib.scrypt`
 * (OpenSSL) and Node's `crypto.scryptSync`, which agree with each other and
 * with RFC 7914 §11's published vectors. Those published values were CONFIRMED
 * against the two implementations rather than recalled from memory.
 *
 * It lives in the Slow suite because it is MEASURED at about 1.58 seconds per
 * derivation at Firebase's parameters. That is not optional to run — it is the
 * only thing standing between this implementation and a silent total failure.
 */
final class ScryptTest extends TestCase
{
    /**
     * RFC 7914 §11, byte for byte.
     *
     * @param string $expected lower-case hex, from Python and Node
     */
    #[DataProvider('rfcVectors')]
    public function test_it_matches_the_rfc_7914_vectors(
        string $password,
        string $salt,
        int $n,
        int $r,
        int $p,
        int $length,
        string $expected,
    ): void {
        $parameters = ScryptParameters::of(n: $n, r: $r, p: $p, length: $length, salt: $salt);

        self::assertSame($expected, bin2hex(Scrypt::derive($password, $parameters)));
    }

    /** @return iterable<string, array{string, string, int, int, int, int, string}> */
    public static function rfcVectors(): iterable
    {
        foreach (Vectors::scrypt() as [$password, $salt, $n, $r, $p, $length, $expected]) {
            yield \sprintf('N=%d r=%d p=%d', $n, $r, $p) => [
                $password, $salt, $n, $r, $p, $length, $expected,
            ];
        }
    }

    /**
     * Every parameter actually changes the answer.
     *
     * Each of these is a way to be silently wrong. An implementation that
     * ignored `p` entirely would pass two of the three RFC vectors; one that
     * ignored the salt would pass none, but one that applied it only in the
     * first PBKDF2 pass and not the second would pass the first vector (empty
     * salt) and fail the rest in a way that looks like a different bug.
     */
    public function test_each_parameter_changes_the_output(): void
    {
        $base = ScryptParameters::of(n: 16, r: 1, p: 1, length: 64, salt: 'salt');
        $want = Scrypt::derive('password', $base);

        $variants = [
            'different N' => ScryptParameters::of(n: 32, r: 1, p: 1, length: 64, salt: 'salt'),
            'different r' => ScryptParameters::of(n: 16, r: 2, p: 1, length: 64, salt: 'salt'),
            'different p' => ScryptParameters::of(n: 16, r: 1, p: 2, length: 64, salt: 'salt'),
            'different salt' => ScryptParameters::of(n: 16, r: 1, p: 1, length: 64, salt: 'other'),
        ];

        foreach ($variants as $label => $parameters) {
            self::assertNotSame(
                $want,
                Scrypt::derive('password', $parameters),
                $label . ' produced the same bytes, so that parameter is being ignored',
            );
        }

        self::assertNotSame($want, Scrypt::derive('different-password', $base));
    }

    /**
     * A shorter requested length is a PREFIX of a longer one.
     *
     * That is a property of PBKDF2's final pass, and it is worth pinning: it
     * means a stored 32-byte digest and a stored 64-byte digest of the same
     * password share their first 32 bytes, so a length declared wrongly SHORT
     * would still match a truncated comparison. The length check in the
     * service is what stops that, and this test documents why it is needed.
     */
    public function test_a_shorter_derivation_is_a_prefix_of_a_longer_one(): void
    {
        $short = Scrypt::derive(
            'password',
            ScryptParameters::of(n: 16, r: 1, p: 1, length: 32, salt: 'salt'),
        );
        $long = Scrypt::derive(
            'password',
            ScryptParameters::of(n: 16, r: 1, p: 1, length: 64, salt: 'salt'),
        );

        self::assertSame($short, substr($long, 0, 32));
    }

    /**
     * The measured cost, asserted as a RANGE rather than a number.
     *
     * The README and several docblocks quote 1.58 seconds for Firebase's
     * parameters, and a quoted measurement that nothing checks is a comment
     * that rots. The bounds are wide enough not to fail on a slower machine
     * and tight enough to catch an accidental factor-of-ten regression — which
     * is what a reintroduced array-indexed Salsa core, or an extra copy of the
     * V table, would look like.
     */
    public function test_the_quoted_cost_is_still_roughly_right(): void
    {
        $parameters = ScryptParameters::of(
            n: 16384, r: 8, p: 1, length: 64, salt: 'SodiumChloride',
        );

        $started = hrtime(true);
        Scrypt::derive('pleaseletmein', $parameters);
        $elapsed = (hrtime(true) - $started) / 1e9;

        self::assertGreaterThan(
            0.1,
            $elapsed,
            'this finished implausibly fast — is it really doing the work?',
        );
        self::assertLessThan(
            15.0,
            $elapsed,
            \sprintf(
                'Firebase-parameter scrypt took %.1fs against a quoted 1.58s. A factor-of-ten '
                . 'regression here is what a reintroduced array-indexed Salsa core looks like.',
                $elapsed,
            ),
        );
    }

    // ── Firebase ────────────────────────────────────────────────────────────

    /**
     * Firebase's construction, against values Node produced end to end.
     *
     * Node did both halves — `crypto.scryptSync` for the derivation and
     * `crypto.createCipheriv('aes-256-ctr', …)` for the encryption — so
     * neither is checked against itself. The first vector uses the salt
     * separator and signer key from Firebase's own published example.
     */
    #[DataProvider('firebaseVectors')]
    public function test_it_matches_firebase_vectors_node_produced(
        string $password,
        string $salt,
        string $separator,
        string $signerKey,
        string $expected,
    ): void {
        $parameters = FirebaseParameters::fromExport(
            base64Salt:          $salt,
            base64SaltSeparator: $separator,
            base64SignerKey:     $signerKey,
        );

        self::assertSame($expected, FirebaseScrypt::recompute($password, $parameters));
    }

    /** @return iterable<string, array{string, string, string, string, string}> */
    public static function firebaseVectors(): iterable
    {
        foreach (Vectors::firebase() as $i => $vector) {
            yield 'vector ' . $i => [
                $vector['password'],
                $vector['salt'],
                $vector['separator'],
                $vector['signerKey'],
                $vector['hash'],
            ];
        }
    }

    /**
     * The output length follows the SIGNER KEY, not any digest size.
     *
     * The password is the AES key and the signer key is the plaintext — which
     * is backwards from how a password hash normally reads. A 64-byte signer
     * key gives 88 characters of base64; a 4-byte one gives 8. An
     * implementation that assumed a 64-byte output would pass the first vector
     * and fail the third.
     */
    public function test_the_output_length_follows_the_signer_key(): void
    {
        $vectors = Vectors::firebase();

        self::assertSame(88, \strlen($vectors[0]['hash']), 'a 64-byte signer key');
        self::assertSame(8, \strlen($vectors[2]['hash']), 'a 4-byte signer key');
    }

    /**
     * Only the FIRST 32 bytes of the derived key are used.
     *
     * Taking the wrong half, or all 64, makes `openssl_encrypt()` emit a
     * warning and silently truncate the key — returning a plausible ciphertext
     * of exactly the right length. Measured: a 64-byte key against
     * aes-256-ctr returns a string rather than false.
     */
    public function test_openssl_silently_accepts_an_oversized_key_so_the_length_check_matters(): void
    {
        $plaintext = str_repeat('p', 32);
        $iv        = str_repeat("\0", 16);

        $correct = openssl_encrypt(
            $plaintext,
            'aes-256-ctr',
            str_repeat('k', 32),
            \OPENSSL_RAW_DATA,
            $iv,
        );
        $oversized = @openssl_encrypt(
            $plaintext,
            'aes-256-ctr',
            str_repeat('k', 64),
            \OPENSSL_RAW_DATA,
            $iv,
        );

        self::assertNotFalse($oversized, 'OpenSSL accepted a 64-byte AES-256 key rather than refusing');
        // It truncates to the first 32 bytes, which here are identical — so
        // the two agree, which is exactly why the bug would be invisible.
        self::assertSame($correct, $oversized);
    }

    // ── through the service ─────────────────────────────────────────────────

    public function test_the_service_verifies_a_scrypt_credential(): void
    {
        $parameters = ScryptParameters::of(
            n: 16, r: 1, p: 1, length: 64, salt: 'salt', encoding: DigestEncoding::HexLower,
        );
        $stored = bin2hex(Scrypt::derive('secret', $parameters));

        $service = $this->service();

        self::assertTrue($service->verify('secret', LegacyCredential::scrypt($stored, $parameters))->verified);
        self::assertFalse($service->verify('wrong', LegacyCredential::scrypt($stored, $parameters))->verified);
    }

    /**
     * The declared encoding is honoured, and a wrong one fails.
     *
     * Not sniffed. A verifier that tried hex then base64 would let a wrong
     * declaration succeed and leave the misconfiguration in place for the next
     * person to find.
     */
    public function test_the_declared_encoding_is_used_rather_than_guessed(): void
    {
        $hexParameters = ScryptParameters::of(
            n: 16, r: 1, p: 1, length: 64, salt: 'salt', encoding: DigestEncoding::HexLower,
        );
        $b64Parameters = ScryptParameters::of(
            n: 16, r: 1, p: 1, length: 64, salt: 'salt', encoding: DigestEncoding::Base64,
        );

        $raw    = Scrypt::derive('secret', $hexParameters);
        $asHex  = bin2hex($raw);
        $asB64  = base64_encode($raw);

        $service = $this->service();

        // Each matches under its own declaration.
        self::assertTrue($service->verify('secret', LegacyCredential::scrypt($asHex, $hexParameters))->verified);
        self::assertTrue($service->verify('secret', LegacyCredential::scrypt($asB64, $b64Parameters))->verified);

        // And NOT under the other one — which is the point.
        self::assertFalse($service->verify('secret', LegacyCredential::scrypt($asHex, $b64Parameters))->verified);
        self::assertFalse($service->verify('secret', LegacyCredential::scrypt($asB64, $hexParameters))->verified);
    }

    public function test_the_service_verifies_a_firebase_credential(): void
    {
        $vector = Vectors::firebase()[2]; // The cheapest: a 4-byte signer key.

        $parameters = FirebaseParameters::fromExport(
            base64Salt:          $vector['salt'],
            base64SaltSeparator: $vector['separator'],
            base64SignerKey:     $vector['signerKey'],
        );

        $service    = $this->service();
        $credential = LegacyCredential::firebaseScrypt($vector['hash'], $parameters);

        self::assertTrue($service->verify($vector['password'], $credential)->verified);
        self::assertFalse($service->verify('definitely-wrong', $credential)->verified);
    }

    private function service(): LegacyPasswordService
    {
        return new LegacyPasswordService(
            config: LegacyPasswordConfig::of(),
            hasher: new RecordingHasher(),
        );
    }
}
