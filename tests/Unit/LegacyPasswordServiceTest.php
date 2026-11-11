<?php

declare(strict_types=1);

namespace Tests\Plugins\LegacyPasswords\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Plugins\LegacyPasswords\Application\Services\LegacyPasswordService;
use Plugins\LegacyPasswords\Domain\DigestParameters;
use Plugins\LegacyPasswords\Domain\FirebaseParameters;
use Plugins\LegacyPasswords\Domain\LegacyAlgorithm;
use Plugins\LegacyPasswords\Domain\LegacyCredential;
use Plugins\LegacyPasswords\Domain\LegacyRefusal;
use Plugins\LegacyPasswords\Domain\SaltPlacement;
use Plugins\LegacyPasswords\Domain\ScryptParameters;
use Plugins\LegacyPasswords\Infrastructure\Config\LegacyPasswordConfig;
use Tests\Plugins\LegacyPasswords\Support\RecordingHasher;
use Tests\Plugins\LegacyPasswords\Support\RecordingLogger;
use Tests\Plugins\LegacyPasswords\Support\Vectors;

final class LegacyPasswordServiceTest extends TestCase
{
    private RecordingHasher $hasher;

    private RecordingLogger $logger;

    protected function setUp(): void
    {
        $this->hasher = new RecordingHasher();
        $this->logger = new RecordingLogger();
    }

    private function service(?LegacyPasswordConfig $config = null): LegacyPasswordService
    {
        return new LegacyPasswordService(
            config: $config ?? LegacyPasswordConfig::of(),
            hasher: $this->hasher,
            logger: $this->logger,
        );
    }

    // ── the happy paths, one per scheme ─────────────────────────────────────

    public function test_it_verifies_a_bcrypt_hash(): void
    {
        $hash    = password_hash('secret', \PASSWORD_BCRYPT, ['cost' => 4]);
        $verdict = $this->service()->verify('secret', LegacyCredential::bcrypt($hash));

        self::assertTrue($verdict->verified);
        self::assertSame(LegacyAlgorithm::Bcrypt, $verdict->algorithm);
        self::assertTrue($verdict->mustUpgrade());
    }

    public function test_it_verifies_an_argon2_hash(): void
    {
        $hash = password_hash('secret', \PASSWORD_ARGON2ID, [
            'memory_cost' => 8192, 'time_cost' => 1, 'threads' => 1,
        ]);

        self::assertTrue($this->service()->verify('secret', LegacyCredential::argon2($hash))->verified);
    }

    #[DataProvider('cryptSettings')]
    public function test_it_verifies_a_crypt_hash(string $setting): void
    {
        $hash = crypt('secret', $setting);

        self::assertStringStartsNotWith('*', $hash, 'crypt() could not use ' . $setting);
        self::assertTrue($this->service()->verify('secret', LegacyCredential::crypt($hash))->verified);
        self::assertFalse($this->service()->verify('wrong', LegacyCredential::crypt($hash))->verified);
    }

    /** @return iterable<string, array{string}> */
    public static function cryptSettings(): iterable
    {
        yield 'md5-crypt' => ['$1$abcdefgh$'];
        yield 'sha256-crypt' => ['$5$abcdefghijklmnop$'];
        yield 'sha512-crypt' => ['$6$abcdefghijklmnop$'];
        yield 'sha512-crypt with rounds' => ['$6$rounds=5000$abcdefghijklmnop$'];
        yield 'DES' => ['ab'];
    }

    public function test_it_verifies_a_phpass_hash(): void
    {
        $vector  = Vectors::phpass()[0];
        $verdict = $this->service()->verify($vector['password'], LegacyCredential::phpass($vector['hash']));

        self::assertTrue($verdict->verified);
        self::assertSame(LegacyAlgorithm::Phpass, $verdict->algorithm);
    }

    public function test_it_verifies_a_pbkdf2_hash(): void
    {
        $vector = Vectors::pbkdf2()[2]; // 100 iterations, so it is fast.

        self::assertTrue(
            $this->service()->verify($vector['password'], LegacyCredential::pbkdf2($vector['hash']))->verified,
        );
    }

    public function test_it_verifies_a_salted_digest(): void
    {
        $parameters = DigestParameters::of('md5', 's4lt', SaltPlacement::Prefix);
        $credential = LegacyCredential::digest(md5('s4lt' . 'secret'), $parameters);

        self::assertTrue($this->service()->verify('secret', $credential)->verified);
        self::assertFalse($this->service()->verify('wrong', $credential)->verified);
    }

    // ── CHECK 1: an empty stored value ──────────────────────────────────────

    /**
     * An empty stored value must never verify, for any scheme and any
     * password.
     *
     * A null or blank password column is ordinary in an import — users who
     * never set one, rows where the column did not come across. And the
     * failure mode is not subtle: `hash_equals('', '')` is TRUE, so a
     * plaintext or digest credential over an empty column would authenticate
     * an empty password, and for the Firebase path an empty signer key makes
     * EVERY password hash to the empty string.
     */
    #[DataProvider('everyAlgorithm')]
    public function test_an_empty_stored_value_never_verifies(LegacyAlgorithm $algorithm): void
    {
        $credential = match ($algorithm) {
            LegacyAlgorithm::Bcrypt    => LegacyCredential::bcrypt(''),
            LegacyAlgorithm::Argon2    => LegacyCredential::argon2(''),
            LegacyAlgorithm::Crypt     => LegacyCredential::crypt(''),
            LegacyAlgorithm::Phpass    => LegacyCredential::phpass(''),
            LegacyAlgorithm::Pbkdf2    => LegacyCredential::pbkdf2(''),
            LegacyAlgorithm::Plaintext => LegacyCredential::plaintext(''),
            LegacyAlgorithm::Digest    => LegacyCredential::digest('', DigestParameters::of('md5')),

            // The two bare scrypt families need real parameter objects. They
            // are built with the CHEAPEST legal parameters — N=16, r=1 — so
            // that if the empty-stored guard ever regressed, this test would
            // fail fast rather than spending 1.58 seconds per case proving it.
            LegacyAlgorithm::Scrypt => LegacyCredential::scrypt(
                '',
                ScryptParameters::of(n: 16, r: 1, p: 1, length: 64, salt: 'salt'),
            ),
            LegacyAlgorithm::FirebaseScrypt => LegacyCredential::firebaseScrypt(
                '',
                FirebaseParameters::of(
                    salt:          'salt',
                    saltSeparator: "\x07",
                    signerKey:     'signer-key',
                    // mem_cost 4 is N=16, the cheapest this accepts.
                    memoryCost:    4,
                    rounds:        1,
                ),
            ),
        };

        // Plaintext enabled, so this test is about the empty guard and not
        // about the plaintext switch.
        $service = $this->service(LegacyPasswordConfig::of(allowPlaintext: true));

        foreach (['', 'secret', "\0"] as $password) {
            $verdict = $service->verify($password, $credential);

            self::assertFalse($verdict->verified, $algorithm->value . ' verified an empty hash');
            self::assertSame(LegacyRefusal::MalformedHash, $verdict->refusal);
        }
    }

    /** @return iterable<string, array{LegacyAlgorithm}> */
    public static function everyAlgorithm(): iterable
    {
        foreach (LegacyAlgorithm::cases() as $case) {
            yield $case->value => [$case];
        }
    }

    /**
     * The empty-stored guard holds even for plaintext with an empty password,
     * which is the one combination that would otherwise be a bypass.
     */
    public function test_an_empty_password_against_an_empty_plaintext_column_is_refused(): void
    {
        $service = $this->service(LegacyPasswordConfig::of(allowPlaintext: true));

        // Prove the hazard is real: this is what the guard prevents.
        self::assertTrue(hash_equals('', ''), 'hash_equals on two empty strings is true');

        $verdict = $service->verify('', LegacyCredential::plaintext(''));

        self::assertFalse($verdict->verified);
        self::assertSame(LegacyRefusal::MalformedHash, $verdict->refusal);
    }

    // ── CHECK 2: plaintext ──────────────────────────────────────────────────

    public function test_plaintext_is_refused_by_default(): void
    {
        $verdict = $this->service()->verify('hunter2', LegacyCredential::plaintext('hunter2'));

        self::assertFalse($verdict->verified);
        self::assertSame(LegacyRefusal::PlaintextRefused, $verdict->refusal);
        self::assertTrue($verdict->suggestsMisconfiguration());
    }

    public function test_plaintext_verifies_only_when_deliberately_enabled(): void
    {
        $service = $this->service(LegacyPasswordConfig::of(allowPlaintext: true));

        self::assertTrue($service->verify('hunter2', LegacyCredential::plaintext('hunter2'))->verified);
        self::assertFalse($service->verify('hunter3', LegacyCredential::plaintext('hunter2'))->verified);
    }

    /**
     * Plaintext is refused BEFORE any comparison happens.
     *
     * Not merely "the verdict is false" — a disabled deployment must not
     * compare at all, so there is no timing signal and no path where the
     * comparison's result could be used.
     */
    public function test_a_disabled_plaintext_scheme_is_absent_from_supported(): void
    {
        self::assertNotContains(LegacyAlgorithm::Plaintext, $this->service()->supported());
        self::assertContains(
            LegacyAlgorithm::Plaintext,
            $this->service(LegacyPasswordConfig::of(allowPlaintext: true))->supported(),
        );
    }

    // ── CHECK 3: malformed is not "wrong password" ──────────────────────────

    /**
     * The distinction that keeps a broken import visible.
     *
     * Both outcomes are "the user cannot log in", but one affects an entire
     * population and needs an operator, and the other is one person mistyping.
     * `suggestsMisconfiguration()` is what a caller routes on.
     */
    public function test_a_malformed_hash_is_not_reported_as_a_wrong_password(): void
    {
        $verdict = $this->service()->verify('secret', LegacyCredential::bcrypt('$2y$12$tooshort'));

        self::assertFalse($verdict->verified);
        self::assertSame(LegacyRefusal::MalformedHash, $verdict->refusal);
        self::assertTrue($verdict->suggestsMisconfiguration());
    }

    public function test_a_wrong_password_is_not_reported_as_a_misconfiguration(): void
    {
        $hash    = password_hash('secret', \PASSWORD_BCRYPT, ['cost' => 4]);
        $verdict = $this->service()->verify('wrong', LegacyCredential::bcrypt($hash));

        self::assertFalse($verdict->verified);
        self::assertSame(LegacyRefusal::WrongPassword, $verdict->refusal);
        self::assertFalse($verdict->suggestsMisconfiguration());
    }

    /**
     * crypt()'s `*0` failure marker must not verify against a stored `*0`.
     *
     * A column full of `*0` is exactly what a half-finished migration leaves
     * behind, and `crypt()` returns `*0` for a salt it cannot use — so
     * without the guard the recomputed value and the stored value would be
     * identical and every such row would authenticate ANY password.
     */
    #[DataProvider('cryptFailureMarkers')]
    public function test_a_crypt_failure_marker_never_verifies(string $stored): void
    {
        $verdict = $this->service()->verify('anything', LegacyCredential::crypt($stored));

        self::assertFalse($verdict->verified);
        self::assertSame(LegacyRefusal::MalformedHash, $verdict->refusal);
    }

    /** @return iterable<string, array{string}> */
    public static function cryptFailureMarkers(): iterable
    {
        yield '*0' => ['*0'];
        yield '*1' => ['*1'];
        yield '*' => ['*'];
    }

    // ── CHECK 3a: a bare scheme's length IS its well-formedness ─────────────

    /**
     * A digest of the wrong length is MALFORMED, not a wrong password.
     *
     * This is the verdict a revert check exposed as missing. The length check
     * used to live inside `checkDigest()` and return `false`, which the caller
     * turned into `WrongPassword` — the exact outcome its own comment said it
     * existed to prevent. So removing it changed nothing observable and the
     * suite stayed green.
     *
     * It matters because a truncated column or a misdeclared algorithm affects
     * EVERY ROW of that shape. Reported as "wrong password" it looks like a
     * population of users who all forgot; reported as malformed it reaches an
     * operator.
     */
    #[DataProvider('wrongLengthDigests')]
    public function test_a_digest_of_the_wrong_length_is_malformed(
        string $stored,
        string $algorithm,
        string $why,
    ): void {
        $credential = LegacyCredential::digest($stored, DigestParameters::of($algorithm));
        $verdict    = $this->service()->verify('secret', $credential);

        self::assertFalse($verdict->verified);
        self::assertSame(LegacyRefusal::MalformedHash, $verdict->refusal, $why);
        self::assertTrue($verdict->suggestsMisconfiguration(), $why);
    }

    /** @return iterable<string, array{string, string, string}> */
    public static function wrongLengthDigests(): iterable
    {
        yield 'md5 truncated by one character' => [
            substr(md5('secret'), 0, 31), 'md5', 'a column one character short is a broken import',
        ];
        yield 'md5 with a character too many' => [
            md5('secret') . 'a', 'md5', 'a column that gained a character is a broken import',
        ];
        yield 'a sha256 digest declared as md5' => [
            hash('sha256', 'secret'), 'md5', 'the algorithm was declared wrongly',
        ];
        yield 'an md5 digest declared as sha256' => [
            md5('secret'), 'sha256', 'the algorithm was declared wrongly the other way',
        ];
        yield 'a base64 digest declared as hex' => [
            base64_encode(hash('md5', 'secret', true)), 'md5', 'the encoding was declared wrongly',
        ];
    }

    /**
     * And a digest of the RIGHT length that simply does not match is still a
     * wrong password.
     *
     * Without this the test above would pass just as well if everything were
     * reported as malformed, which would destroy the distinction rather than
     * establish it.
     */
    public function test_a_digest_of_the_right_length_that_does_not_match_is_a_wrong_password(): void
    {
        $credential = LegacyCredential::digest(md5('secret'), DigestParameters::of('md5'));
        $verdict    = $this->service()->verify('not-secret', $credential);

        self::assertFalse($verdict->verified);
        self::assertSame(LegacyRefusal::WrongPassword, $verdict->refusal);
        self::assertFalse($verdict->suggestsMisconfiguration());
    }

    /**
     * The same check covers scrypt, whose length is also fully determined.
     *
     * Cheap parameters (N=16, r=1) so this is a length test rather than a
     * 1.58-second one — and it never reaches the derivation at all, which is
     * the point: a malformed column is refused before the work.
     */
    public function test_a_scrypt_digest_of_the_wrong_length_is_malformed(): void
    {
        $parameters = ScryptParameters::of(n: 16, r: 1, p: 1, length: 64, salt: 'salt');

        // 64 bytes in lower hex is 128 characters; this is 127.
        $credential = LegacyCredential::scrypt(str_repeat('a', 127), $parameters);
        $verdict    = $this->service()->verify('secret', $credential);

        self::assertFalse($verdict->verified);
        self::assertSame(LegacyRefusal::MalformedHash, $verdict->refusal);
    }

    /**
     * And Firebase, whose stored length follows the SIGNER KEY.
     *
     * AES-CTR is a stream cipher, so the ciphertext is exactly as long as the
     * signer key it encrypted — which makes the base64 length predictable
     * without doing the 1.58-second derivation.
     */
    public function test_a_firebase_hash_of_the_wrong_length_is_malformed(): void
    {
        $parameters = FirebaseParameters::of(
            salt:          'salt',
            saltSeparator: "\x07",
            // 32 bytes -> 44 characters of base64.
            signerKey:     str_repeat('k', 32),
            memoryCost:    4,
            rounds:        1,
        );

        $verdict = $this->service()->verify(
            'secret',
            LegacyCredential::firebaseScrypt(str_repeat('A', 43), $parameters),
        );

        self::assertFalse($verdict->verified);
        self::assertSame(LegacyRefusal::MalformedHash, $verdict->refusal);
    }

    /**
     * Plaintext has no predictable length, so the check must not refuse it.
     *
     * A password may be any length. A length check applied here would refuse
     * every plaintext row whose password was not some arbitrary size.
     */
    public function test_plaintext_is_not_subject_to_a_length_check(): void
    {
        $service = $this->service(LegacyPasswordConfig::of(allowPlaintext: true));

        foreach (['a', 'hunter2', str_repeat('x', 200)] as $password) {
            self::assertTrue(
                $service->verify($password, LegacyCredential::plaintext($password))->verified,
                'a plaintext password of length ' . \strlen($password) . ' was refused',
            );
        }
    }

    // ── CHECK 3b: the Argon2 variant ────────────────────────────────────────

    /**
     * argon2d is reported UNSUPPORTED, not malformed.
     *
     * The hash is perfectly valid and PHP simply cannot verify it — calling
     * that "malformed" would send an operator looking for a corrupt import
     * that does not exist.
     */
    public function test_argon2d_is_unsupported_rather_than_malformed(): void
    {
        $hash    = '$argon2d$v=19$m=65536,t=4,p=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNo';
        $verdict = $this->service()->verify('secret', LegacyCredential::argon2($hash));

        self::assertFalse($verdict->verified);
        self::assertSame(LegacyRefusal::Unsupported, $verdict->refusal);
        self::assertTrue($verdict->suggestsMisconfiguration());
    }

    // ── CHECK 4: the work-factor ceiling ────────────────────────────────────

    /**
     * A planted high-cost bcrypt hash is refused BEFORE the work is done.
     *
     * `$2y$31$…` is a valid bcrypt hash with 2^31 rounds — hours of CPU for
     * one verification. Planting it in an import file costs nothing and it
     * passes every format check, so from then on every login attempt against
     * that account occupies a worker until the request times out.
     *
     * The test asserts it comes back quickly, because a test that merely
     * asserted the verdict would pass just as happily after hours.
     */
    public function test_an_absurd_bcrypt_cost_is_refused_without_spending_it(): void
    {
        // A structurally valid cost-31 hash: 22 characters of salt plus 31 of
        // digest, which is what password_get_info() needs to parse it.
        $hash = '$2y$31$' . str_repeat('a', 53);

        self::assertNotNull(password_get_info($hash)['algo'], 'the hash must be parseable to be a test');
        self::assertSame(31, password_get_info($hash)['options']['cost'] ?? null);

        $started = hrtime(true);
        $verdict = $this->service()->verify('secret', LegacyCredential::bcrypt($hash));
        $elapsed = (hrtime(true) - $started) / 1e9;

        self::assertFalse($verdict->verified);
        self::assertSame(LegacyRefusal::CostRefused, $verdict->refusal);
        self::assertLessThan(
            1.0,
            $elapsed,
            'the refusal must happen BEFORE the work factor is spent, not after',
        );
    }

    public function test_a_bcrypt_cost_at_the_ceiling_is_allowed(): void
    {
        $config = LegacyPasswordConfig::of(maxBcryptCost: 4);
        $hash   = password_hash('secret', \PASSWORD_BCRYPT, ['cost' => 4]);

        self::assertTrue($this->service($config)->verify('secret', LegacyCredential::bcrypt($hash))->verified);
    }

    public function test_a_bcrypt_cost_one_above_the_ceiling_is_refused(): void
    {
        $config = LegacyPasswordConfig::of(maxBcryptCost: 4);
        $hash   = password_hash('secret', \PASSWORD_BCRYPT, ['cost' => 5]);

        $verdict = $this->service($config)->verify('secret', LegacyCredential::bcrypt($hash));

        self::assertFalse($verdict->verified);
        self::assertSame(LegacyRefusal::CostRefused, $verdict->refusal);
    }

    /**
     * An Argon2 hash declaring more memory than the ceiling is refused.
     *
     * Without the ceiling libargon2 would attempt the allocation — `m` is in
     * KiB, so `m=4194304` is four gigabytes.
     */
    public function test_an_argon2_memory_cost_above_the_ceiling_is_refused(): void
    {
        $hash = '$argon2id$v=19$m=4194304,t=8,p=4$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNo';

        $verdict = $this->service(LegacyPasswordConfig::of(maxArgon2MemoryKib: 65536))
            ->verify('secret', LegacyCredential::argon2($hash));

        self::assertFalse($verdict->verified);
        self::assertSame(LegacyRefusal::CostRefused, $verdict->refusal);
    }

    /**
     * A phpass hash above the iteration ceiling is refused.
     *
     * `$P$J` is 2^21 = 2,097,152 iterations of MD5, which is above the default
     * ceiling of 1,000,000 — so the shipped default genuinely refuses
     * something, rather than being a number nothing reaches.
     */
    public function test_a_phpass_count_above_the_ceiling_is_refused(): void
    {
        $vector = Vectors::phpass()[4]; // $P$J — 2^21 iterations.

        $verdict = $this->service()->verify($vector['password'], LegacyCredential::phpass($vector['hash']));

        self::assertFalse($verdict->verified);
        self::assertSame(LegacyRefusal::CostRefused, $verdict->refusal);

        // And it verifies once the ceiling is raised, which proves the refusal
        // was the ceiling and not a broken hash.
        $raised = $this->service(LegacyPasswordConfig::of(maxIterations: 4_000_000));
        self::assertTrue($raised->verify($vector['password'], LegacyCredential::phpass($vector['hash']))->verified);
    }

    public function test_a_pbkdf2_iteration_count_above_the_ceiling_is_refused(): void
    {
        $vector = Vectors::pbkdf2()[1]; // 390,000 iterations.

        $verdict = $this->service(LegacyPasswordConfig::of(maxIterations: 8192))
            ->verify($vector['password'], LegacyCredential::pbkdf2($vector['hash']));

        self::assertFalse($verdict->verified);
        self::assertSame(LegacyRefusal::CostRefused, $verdict->refusal);
    }

    /**
     * An ordinary `$6$salt$hash` with NO rounds field must not be refused.
     *
     * sha256-crypt and sha512-crypt default to 5,000 rounds, so an absent
     * field is not "unlimited". Returning PHP_INT_MAX for it would refuse
     * every ordinary crypt hash in existence — which is the overwhelming
     * majority of them.
     */
    public function test_a_crypt_hash_without_a_rounds_field_is_not_refused(): void
    {
        $hash = crypt('secret', '$6$abcdefghijklmnop$');

        self::assertStringStartsNotWith('*', $hash);
        self::assertStringNotContainsString('rounds=', $hash);

        // The tightest ceiling the config allows, which is still above the
        // scheme's 5,000 default.
        $config = LegacyPasswordConfig::of(maxIterations: 1);

        self::assertSame(8192, $config->maxIterations, 'the floor should have clamped this');
        self::assertTrue($this->service($config)->verify('secret', LegacyCredential::crypt($hash))->verified);
    }

    public function test_a_crypt_rounds_field_above_the_ceiling_is_refused(): void
    {
        $hash = crypt('secret', '$6$rounds=100000$abcdefghijklmnop$');

        self::assertStringStartsNotWith('*', $hash);

        $verdict = $this->service(LegacyPasswordConfig::of(maxIterations: 50000))
            ->verify('secret', LegacyCredential::crypt($hash));

        self::assertFalse($verdict->verified);
        self::assertSame(LegacyRefusal::CostRefused, $verdict->refusal);
    }

    // ── upgrade ─────────────────────────────────────────────────────────────

    /**
     * `upgrade()` delegates to the application's own hasher, with the exact
     * password that was verified.
     *
     * Not a normalised or truncated version of it — which is why the fake
     * records the plaintext.
     */
    public function test_upgrade_delegates_to_the_application_hasher(): void
    {
        $password = 'a password with a space and ümlauts';
        $upgraded = $this->service()->upgrade($password);

        self::assertSame([$password], $this->hasher->hashed);
        self::assertTrue(password_verify($password, $upgraded));
    }

    public function test_a_success_always_asks_for_an_upgrade(): void
    {
        $hash    = password_hash('secret', \PASSWORD_BCRYPT, ['cost' => 4]);
        $verdict = $this->service()->verify('secret', LegacyCredential::bcrypt($hash));

        // No condition. A legacy hash should not be there any more, whatever
        // its cost — there is no "good enough" legacy hash.
        self::assertTrue($verdict->mustUpgrade());
    }

    public function test_a_refusal_never_asks_for_an_upgrade(): void
    {
        $hash    = password_hash('secret', \PASSWORD_BCRYPT, ['cost' => 4]);
        $verdict = $this->service()->verify('wrong', LegacyCredential::bcrypt($hash));

        self::assertFalse($verdict->mustUpgrade());
    }

    /**
     * Without a hasher, verification still works and only `upgrade()` fails.
     *
     * That is what lets the diagnostic command register from the
     * CoreContainer even in a project that bound `HashingPort` only
     * per-request — a command that refused to appear would be hidden at
     * exactly the moment an import is going wrong.
     */
    public function test_verification_works_without_a_hasher_but_upgrade_explains_itself(): void
    {
        $service = new LegacyPasswordService(config: LegacyPasswordConfig::of(), hasher: null);
        $hash    = password_hash('secret', \PASSWORD_BCRYPT, ['cost' => 4]);

        self::assertTrue($service->verify('secret', LegacyCredential::bcrypt($hash))->verified);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessageMatches('/withPorts/');

        $service->upgrade('secret');
    }

    // ── logging ─────────────────────────────────────────────────────────────

    /**
     * An operational refusal is an ERROR; a wrong password is DEBUG.
     *
     * The levels carry a real requirement. An operational refusal means a
     * whole population cannot log in and nobody has been told, so it has to
     * reach somewhere an operator sees. A wrong password happens thousands of
     * times a day and would bury it.
     */
    public function test_an_operational_refusal_is_logged_as_an_error(): void
    {
        $this->service()->verify('secret', LegacyCredential::bcrypt('$2y$12$tooshort'));

        self::assertCount(1, $this->logger->messagesAt('error'));
        self::assertSame([], $this->logger->messagesAt('debug'));
    }

    public function test_a_wrong_password_is_logged_at_debug(): void
    {
        $hash = password_hash('secret', \PASSWORD_BCRYPT, ['cost' => 4]);
        $this->service()->verify('wrong', LegacyCredential::bcrypt($hash));

        self::assertCount(1, $this->logger->messagesAt('debug'));
        self::assertSame([], $this->logger->messagesAt('error'));
    }

    /**
     * A SUCCESS is logged at info, because during a migration that count is
     * the number an operator watches go to zero — and it is unobtainable
     * afterwards.
     */
    public function test_a_success_is_logged_at_info_with_the_algorithm(): void
    {
        $hash = password_hash('secret', \PASSWORD_BCRYPT, ['cost' => 4]);
        $this->service()->verify('secret', LegacyCredential::bcrypt($hash));

        $info = $this->logger->messagesAt('info');

        self::assertCount(1, $info);
        self::assertStringContainsString('algorithm=bcrypt', $info[0]);
        self::assertStringContainsString('action=upgrade', $info[0]);
    }

    /**
     * NOTHING LOGGED MAY CONTAIN THE PASSWORD OR THE HASH.
     *
     * The algorithm is included deliberately — it is the number a migration is
     * tracked by, and it is not a secret from anyone who already has the
     * database. The hash is a different matter: for the weak schemes this
     * plugin exists to read, a hash in a log file is a password with a delay.
     */
    public function test_no_log_line_contains_the_password_or_the_hash(): void
    {
        $password = 'a-very-recognisable-password';
        $service  = $this->service(LegacyPasswordConfig::of(allowPlaintext: true));

        $cases = [
            LegacyCredential::bcrypt(password_hash($password, \PASSWORD_BCRYPT, ['cost' => 4])),
            LegacyCredential::bcrypt('$2y$12$tooshort'),
            LegacyCredential::plaintext($password),
            LegacyCredential::digest(md5($password), DigestParameters::of('md5')),
            LegacyCredential::phpass(Vectors::phpass()[0]['hash']),
        ];

        foreach ($cases as $credential) {
            $service->verify($password, $credential);
            $service->verify('wrong-' . $password, $credential);
        }

        $logged = $this->logger->everything();

        self::assertStringNotContainsString($password, $logged);
        self::assertStringNotContainsString(md5($password), $logged);
        self::assertStringNotContainsString(Vectors::phpass()[0]['hash'], $logged);
        // The $P$ prefix would be the start of a leaked phpass hash.
        self::assertStringNotContainsString('$P$', $logged);
        // Sanity: something WAS logged, so the assertions above are not
        // passing because the logger is empty.
        self::assertNotSame('', trim($logged));
    }

    public function test_a_missing_logger_does_not_break_verification(): void
    {
        $service = new LegacyPasswordService(
            config: LegacyPasswordConfig::of(),
            hasher: $this->hasher,
            logger: null,
        );

        $hash = password_hash('secret', \PASSWORD_BCRYPT, ['cost' => 4]);

        self::assertTrue($service->verify('secret', LegacyCredential::bcrypt($hash))->verified);
    }

    // ── detect / supported / describe ───────────────────────────────────────

    public function test_detect_delegates_and_returns_null_for_a_bare_digest(): void
    {
        $service = $this->service();

        self::assertNotNull($service->detect(password_hash('x', \PASSWORD_BCRYPT, ['cost' => 4])));
        self::assertNull($service->detect(md5('secret')));
    }

    public function test_supported_reports_what_this_build_can_really_do(): void
    {
        $supported = $this->service()->supported();

        // Always available: no extension needed for any of these.
        self::assertContains(LegacyAlgorithm::Bcrypt, $supported);
        self::assertContains(LegacyAlgorithm::Phpass, $supported);
        self::assertContains(LegacyAlgorithm::Pbkdf2, $supported);
        self::assertContains(LegacyAlgorithm::Scrypt, $supported);
        self::assertContains(LegacyAlgorithm::Digest, $supported);

        // Build-dependent, and the assertion follows the build rather than
        // asserting a fixed answer — otherwise the suite would fail on a PHP
        // compiled without Argon2 for a reason that is not a bug.
        self::assertSame(
            \in_array('argon2id', password_algos(), true) || \in_array('argon2i', password_algos(), true),
            \in_array(LegacyAlgorithm::Argon2, $supported, true),
        );
        self::assertSame(
            \in_array('aes-256-ctr', openssl_get_cipher_methods(), true),
            \in_array(LegacyAlgorithm::FirebaseScrypt, $supported, true),
        );
    }

    public function test_describe_carries_no_secret(): void
    {
        $described = $this->service()->describe();

        self::assertStringContainsString('max_bcrypt_cost=15', $described);
        self::assertStringContainsString('allow_plaintext=no', $described);
        self::assertStringContainsString('supported=', $described);
    }
}
