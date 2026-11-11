<?php

declare(strict_types=1);

namespace Plugins\LegacyPasswords\Domain;

/**
 * Where the salt goes relative to the password.
 *
 * There is no way to work this out from the data. `md5('s4lt' . 'secret')` and
 * `md5('secret' . 's4lt')` are both 32 hex characters and neither resembles the
 * other, so a wrong guess looks exactly like a wrong password — for every user
 * at once. It has to come from reading the source application's code.
 *
 * The two orders are not equally common. Prepending is what the UNIX crypt(3)
 * tradition did and what most hand-rolled PHP from the 2000s copied; appending
 * is Joomla's, and Django's pre-PBKDF2 `sha1$salt$hash` rows. Both are met
 * often enough that assuming either is wrong.
 */
enum SaltPlacement: string
{
    /** `hash(salt . password)` — crypt(3)-style, osCommerce, most hand-rolled PHP. */
    case Prefix = 'prefix';

    /** `hash(password . salt)` — Joomla, legacy Django. */
    case Suffix = 'suffix';

    /** `hash(password)` — no salt at all. One rainbow table breaks every user. */
    case None = 'none';

    public function apply(#[\SensitiveParameter] string $password, string $salt): string
    {
        return match ($this) {
            self::Prefix => $salt . $password,
            self::Suffix => $password . $salt,
            self::None   => $password,
        };
    }
}
