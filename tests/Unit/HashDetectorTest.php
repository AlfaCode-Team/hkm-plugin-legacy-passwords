<?php

declare(strict_types=1);

namespace Tests\Plugins\LegacyPasswords\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Plugins\LegacyPasswords\Domain\HashDetector;
use Plugins\LegacyPasswords\Domain\LegacyAlgorithm;

final class HashDetectorTest extends TestCase
{
    #[DataProvider('selfDescribing')]
    public function test_it_recognises_a_hash_that_says_what_it_is(
        string $stored,
        LegacyAlgorithm $expected,
    ): void {
        self::assertSame($expected, HashDetector::algorithm($stored));

        $credential = HashDetector::detect($stored);

        self::assertNotNull($credential);
        self::assertSame($expected, $credential->algorithm);
        self::assertSame($stored, $credential->stored());
    }

    /** @return iterable<string, array{string, LegacyAlgorithm}> */
    public static function selfDescribing(): iterable
    {
        yield '$2y$ bcrypt' => [
            password_hash('x', \PASSWORD_BCRYPT, ['cost' => 4]), LegacyAlgorithm::Bcrypt,
        ];
        // The older prefixes, which real databases still hold. $2a$ is what
        // phpass emits in its non-portable mode, and $2x$ was PHP's marker for
        // the 2011 crypt_blowfish bug.
        yield '$2a$ bcrypt' => ['$2a$08$' . str_repeat('a', 53), LegacyAlgorithm::Bcrypt];
        yield '$2b$ bcrypt' => ['$2b$08$' . str_repeat('a', 53), LegacyAlgorithm::Bcrypt];
        yield '$2x$ bcrypt' => ['$2x$08$' . str_repeat('a', 53), LegacyAlgorithm::Bcrypt];
        yield '$2$ bcrypt'  => ['$2$08$' . str_repeat('a', 53), LegacyAlgorithm::Bcrypt];

        yield 'argon2id' => ['$argon2id$v=19$m=65536,t=4,p=1$c2FsdHNhbHQ$aaaa', LegacyAlgorithm::Argon2];
        yield 'argon2i'  => ['$argon2i$v=19$m=65536,t=4,p=1$c2FsdHNhbHQ$aaaa', LegacyAlgorithm::Argon2];
        // argon2d is detected even though PHP cannot verify it — knowing WHAT
        // it is turns a silent failure into "unsupported", which is the
        // difference between an operator searching for a bug and an operator
        // reading a message.
        yield 'argon2d'  => ['$argon2d$v=19$m=65536,t=4,p=1$c2FsdHNhbHQ$aaaa', LegacyAlgorithm::Argon2];

        yield 'md5-crypt'    => ['$1$abcdefgh$cHJi5PXp/ki/ktXzqlk6I1', LegacyAlgorithm::Crypt];
        yield 'sha256-crypt' => [
            '$5$abcdefghijklmnop$i7zHaTeYqXlesRXJ8dXj6o.MEFQdzfIJpJpcWAtszs6', LegacyAlgorithm::Crypt,
        ];
        yield 'sha512-crypt' => [
            '$6$abcdefghijklmnop$J/AWykHqo2Tx5UtavGnFc3ytI33la50JpzLTarSWVhkIXK6'
            . 'wOjNwwZjsrIw2UgmrER2EKrSHCeQyAINEEXAk1/', LegacyAlgorithm::Crypt,
        ];

        yield 'phpass $P$' => ['$P$Be.39vipNM3QIErUZ.CevixuseSbRo0', LegacyAlgorithm::Phpass];
        yield 'phpass $H$' => ['$H$Be.39vipNM3QIErUZ.CevixuseSbRo0', LegacyAlgorithm::Phpass];

        yield 'django pbkdf2' => [
            'pbkdf2_sha256$260000$aBcDeFgHiJkL$hi4yngU53R23HHl8EG6Z0i8eA7KCLIaegHx21tD6Sqs=',
            LegacyAlgorithm::Pbkdf2,
        ];
    }

    /**
     * A bare digest comes back NULL, and that is the contract rather than a
     * failure.
     *
     * This is the most important test in the file. The convenient thing to
     * build is a detector that sees 32 hex characters and concludes MD5; it
     * must not exist, because guessing across algorithms gives an attacker
     * several chances at a collision instead of one, and the security of the
     * set collapses to that of its weakest member.
     */
    #[DataProvider('bare')]
    public function test_it_refuses_to_guess_at_a_bare_digest(string $stored): void
    {
        self::assertNull(HashDetector::algorithm($stored), 'nothing here may be classified');
        self::assertNull(HashDetector::detect($stored));
    }

    /** @return iterable<string, array{string}> */
    public static function bare(): iterable
    {
        yield 'md5 of "secret"' => ['5ebe2294ecd0e0f08eab7690d2a6ee69'];
        yield 'sha1' => ['e5e9fa1ba31ecd1ae84f75caaa474f3a663f05f4'];
        yield 'sha256' => ['2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b'];
        yield 'base64 of an md5' => ['Xr4ilOzQ4PCOq3aQ0qbuaQ=='];
        yield 'a plaintext password' => ['hunter2'];
        yield 'empty' => [''];
        // 13 characters, a valid DES crypt hash. crypt() CAN verify one, and
        // LegacyCredential::crypt() accepts it — but a 13-character
        // alphanumeric string is also a truncated column, a session id or a
        // username, so declaring it is fine and inferring it is not.
        yield 'a DES crypt hash, which is deliberately not detected' => ['rEK1ecacw.Fuk'];
        // A near miss: the right shape but not a prefix this knows.
        yield 'an unknown modular prefix' => ['$9$abcdefgh$somethingelse'];
        yield 'drupal 7, deliberately absent' => ['$S$Dvs4YMm0SSxQhmWQhKb0.tlTQ5NRYdvGHHMB9ABz8e0A.Z9Vt09z'];
    }

    /**
     * Malformed is NOT the same as wrong password, and this is what separates
     * them.
     *
     * Both look identical from outside — verification simply fails — but one
     * is a broken import that will fail for an entire population and the other
     * is one person mistyping. Collapsing them is how a broken import stays
     * invisible until support notices that everybody "forgot" at once.
     */
    #[DataProvider('malformedForTheirScheme')]
    public function test_it_tells_a_malformed_hash_from_a_valid_one(
        string $stored,
        LegacyAlgorithm $algorithm,
    ): void {
        self::assertFalse(HashDetector::isWellFormed($stored, $algorithm));
    }

    /** @return iterable<string, array{string, LegacyAlgorithm}> */
    public static function malformedForTheirScheme(): iterable
    {
        yield 'truncated bcrypt' => ['$2y$12$abcdefghijklmnopqrstuv', LegacyAlgorithm::Bcrypt];
        yield 'bcrypt prefix only' => ['$2y$', LegacyAlgorithm::Bcrypt];
        yield 'argon2 with no parameters' => ['$argon2id$', LegacyAlgorithm::Argon2];

        // crypt()'s own failure value. A column full of these is exactly what
        // a half-finished migration leaves behind, and `*0` against a stored
        // `*0` would otherwise be a MATCH.
        yield 'crypt failure marker' => ['*0', LegacyAlgorithm::Crypt];
        yield 'crypt other failure marker' => ['*1', LegacyAlgorithm::Crypt];
        // A SETTING string: salt but no hash yet.
        yield 'crypt setting with no hash' => ['$6$abcdefghijklmnop', LegacyAlgorithm::Crypt];
        yield 'crypt setting with trailing separator' => ['$6$abcdefghijklmnop$', LegacyAlgorithm::Crypt];
        yield 'sha512-crypt truncated mid-hash' => ['$6$salt$tooshort', LegacyAlgorithm::Crypt];
        // sha256-crypt's section is 43 characters; 86 is sha512's.
        yield 'sha256-crypt carrying a sha512 length' => [
            '$5$abcdefghijklmnop$J/AWykHqo2Tx5UtavGnFc3ytI33la50JpzLTarSWVhkIXK6'
            . 'wOjNwwZjsrIw2UgmrER2EKrSHCeQyAINEEXAk1/', LegacyAlgorithm::Crypt,
        ];

        yield 'pbkdf2 with too few fields' => ['pbkdf2_sha256$260000$salt', LegacyAlgorithm::Pbkdf2];
        yield 'pbkdf2 with a non-numeric count' => [
            'pbkdf2_sha256$many$salt$aaaa', LegacyAlgorithm::Pbkdf2,
        ];
        yield 'pbkdf2 with an unknown digest' => [
            'pbkdf2_crc32b$1000$salt$aaaa', LegacyAlgorithm::Pbkdf2,
        ];
    }

    /**
     * The `rounds=` field is not optional to handle.
     *
     * sha256-crypt and sha512-crypt both accept an explicit iteration count,
     * and `$6$rounds=5000$salt$hash` is an ordinary hash any /etc/shadow or
     * Dovecot export may contain. A pattern that ignored it would read
     * `rounds=5000` as the salt, find `salt$hash` as the hash section, measure
     * the wrong length and reject the row — for every user whose hash carried
     * the field, which on some systems is all of them.
     */
    #[DataProvider('cryptSettings')]
    public function test_a_crypt_hash_with_an_explicit_rounds_field_is_well_formed(string $setting): void
    {
        $hash = crypt('secret', $setting);

        // Guard the oracle: if this build's crypt() could not use the setting
        // it returns `*0`, and the assertion below would be testing nothing.
        self::assertStringStartsNotWith('*', $hash, 'crypt() could not use ' . $setting);

        self::assertTrue(
            HashDetector::isWellFormed($hash, LegacyAlgorithm::Crypt),
            $setting . ' produced a hash this does not consider well formed: ' . $hash,
        );
    }

    /** @return iterable<string, array{string}> */
    public static function cryptSettings(): iterable
    {
        yield 'md5-crypt' => ['$1$abcdefgh$'];
        yield 'sha256-crypt' => ['$5$abcdefghijklmnop$'];
        yield 'sha512-crypt' => ['$6$abcdefghijklmnop$'];
        yield 'sha256-crypt with rounds' => ['$5$rounds=10000$abcdefghijklmnop$'];
        yield 'sha512-crypt with rounds' => ['$6$rounds=5000$abcdefghijklmnop$'];
        yield 'sha512-crypt with a high rounds' => ['$6$rounds=100000$abcdefghijklmnop$'];
    }

    /**
     * A DES hash is well formed when DECLARED, even though it is not detected.
     *
     * The two halves of that sentence are the whole design: `isWellFormed()`
     * must accept what `crypt()` can verify, while `algorithm()` must not
     * classify a bare 13-character string as anything.
     */
    public function test_a_declared_des_hash_is_accepted_as_well_formed(): void
    {
        $hash = crypt('secret', 'ab');

        self::assertSame(13, \strlen($hash), 'this build did not produce a DES hash');
        self::assertTrue(HashDetector::isWellFormed($hash, LegacyAlgorithm::Crypt));
        self::assertNull(HashDetector::algorithm($hash), 'and it is still never detected');
    }

    /**
     * `$argon2id$` must be tested before `$argon2i$`.
     *
     * The shorter string is a prefix of the longer one. It happens not to
     * matter today because both map to one enum case and `password_verify()`
     * reads the real variant from the string — but relying on that is how a
     * latent ordering bug becomes a live one the moment anything branches on
     * the variant, so the ordering is asserted rather than assumed.
     */
    public function test_argon2id_is_not_swallowed_by_the_argon2i_prefix(): void
    {
        $id = password_hash('x', \PASSWORD_ARGON2ID);

        self::assertStringStartsWith('$argon2id$', $id);
        self::assertSame(LegacyAlgorithm::Argon2, HashDetector::algorithm($id));
        self::assertTrue(HashDetector::isWellFormed($id, LegacyAlgorithm::Argon2));

        // And PHP agrees it is argon2id specifically, which is what would
        // break if a future change classified it as argon2i and acted on that.
        self::assertSame('argon2id', password_get_info($id)['algoName']);
    }

    /**
     * A bare scheme has no form to check, so `isWellFormed` answers true.
     *
     * That is not a loophole: the service checks a bare digest's LENGTH
     * against its declared parameters, which is the only thing that can be
     * checked, and only the parameters can say what it should be.
     */
    #[DataProvider('bareAlgorithms')]
    public function test_a_bare_scheme_has_no_shape_to_validate(LegacyAlgorithm $algorithm): void
    {
        self::assertFalse($algorithm->selfDescribing());
        self::assertTrue(HashDetector::isWellFormed('anything at all', $algorithm));
    }

    /** @return iterable<string, array{LegacyAlgorithm}> */
    public static function bareAlgorithms(): iterable
    {
        yield 'scrypt' => [LegacyAlgorithm::Scrypt];
        yield 'firebase' => [LegacyAlgorithm::FirebaseScrypt];
        yield 'digest' => [LegacyAlgorithm::Digest];
        yield 'plaintext' => [LegacyAlgorithm::Plaintext];
    }

    /**
     * Every prefix the detector knows maps to a self-describing algorithm, and
     * every self-describing algorithm has a credential constructor.
     *
     * This pins the invariant the `default` arm in `detect()` exists to
     * protect: adding a prefix without a matching arm would otherwise be found
     * at runtime, by a user who could not log in.
     */
    public function test_every_detectable_algorithm_can_be_built(): void
    {
        foreach (self::selfDescribing() as $case) {
            [$stored, $expected] = $case;

            self::assertTrue(
                $expected->selfDescribing(),
                $expected->value . ' is detected but not marked self-describing',
            );
            self::assertNotNull(
                HashDetector::detect($stored),
                $expected->value . ' is detected but has no credential constructor',
            );
        }
    }
}
