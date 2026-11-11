<?php

declare(strict_types=1);

/**
 * Test bootstrap.
 *
 * This plugin touches no database, so unlike its siblings it does not need
 * LetMigrate or Ground — but it DOES need the kernel's `HashingPort` and
 * `LoggerPort` interfaces, and the `env()` helper the config reads. The
 * kernel's own `vendor/autoload.php` is used when present because it carries
 * the path packages; a bare `src/` map is enough when it is not.
 *
 * Order, most specific first:
 *   1. HKM_KERNEL_PATH      — an explicit checkout
 *   2. vendor/autoload.php  — composer-installed (CI)
 *   3. ../../../PHP         — the conventional workspace layout
 */

$pluginRoot = \dirname(__DIR__);

spl_autoload_register(static function (string $class) use ($pluginRoot): void {
    // Test support first. `Tests\Plugins\LegacyPasswords\` is not matched by
    // the `Plugins\LegacyPasswords\` prefix, but listing it second would still
    // be wrong the day somebody reorders them — so the order is explicit and
    // commented.
    $map = [
        'Tests\\Plugins\\LegacyPasswords\\' => $pluginRoot . '/tests/',
        'Plugins\\LegacyPasswords\\'        => $pluginRoot . '/',
    ];

    foreach ($map as $prefix => $base) {
        if (!str_starts_with($class, $prefix)) {
            continue;
        }

        $relative = substr($class, \strlen($prefix));
        $path     = $base . str_replace('\\', '/', $relative) . '.php';

        if (is_file($path)) {
            require_once $path;
        }

        return;
    }
});

$kernelRoot = getenv('HKM_KERNEL_PATH') ?: null;

if ($kernelRoot === null && is_file($pluginRoot . '/vendor/autoload.php')) {
    require_once $pluginRoot . '/vendor/autoload.php';
    $kernelRoot = false; // composer-installed: everything is already on the path
}

if ($kernelRoot !== false) {
    $kernelRoot ??= \dirname($pluginRoot, 3) . '/PHP';

    if (!is_dir($kernelRoot . '/src/Kernel')) {
        fwrite(STDERR, \sprintf(
            "\nCannot find the kernel. Looked in %s.\nSet HKM_KERNEL_PATH to a checkout, or run"
            . " `composer install`.\n\n",
            $kernelRoot,
        ));
        exit(1);
    }

    if (is_file($kernelRoot . '/vendor/autoload.php')) {
        require_once $kernelRoot . '/vendor/autoload.php';
    } else {
        // No vendor tree: map the kernel's own namespace directly. Sufficient
        // here because nothing in this plugin's suite reaches a path package —
        // it needs the two port INTERFACES and the env() helper, nothing more.
        spl_autoload_register(static function (string $class) use ($kernelRoot): void {
            $prefix = 'AlfacodeTeam\\PhpServicePlatform\\';

            if (!str_starts_with($class, $prefix)) {
                return;
            }

            $path = $kernelRoot . '/src/' . str_replace(
                '\\',
                '/',
                substr($class, \strlen($prefix)),
            ) . '.php';

            if (is_file($path)) {
                require_once $path;
            }
        });
    }

    if (is_file($kernelRoot . '/src/Kernel/Support/helpers.php')) {
        require_once $kernelRoot . '/src/Kernel/Support/helpers.php';
    }
}

// The config object reads env() for its ceilings, and the suite must not
// inherit whatever the developer's shell happens to hold — a machine with
// LEGACY_PASSWORD_ALLOW_PLAINTEXT exported would otherwise PASS a test that
// asserts plaintext is refused, and fail nowhere else.
//
// Clearing $_ENV and $_SERVER is not sufficient. The kernel's helper was read
// rather than assumed:
//
//     $value = $_ENV[$key] ?? $_SERVER[$key] ?? getenv($key);
//
// so an exported shell variable still reaches it through the third branch.
// `putenv($key)` with no `=` is what removes it from that one.
//
// This is the only place in the plugin that touches putenv/getenv, and it is
// not a violation of the project's "never getenv() for a .env value" rule —
// nothing is being READ here. The point is to guarantee the variables are
// absent on every branch of the helper, so `fromEnv()` returns its documented
// defaults no matter whose machine the suite runs on.
foreach ([
    'LEGACY_PASSWORD_MAX_BCRYPT_COST',
    'LEGACY_PASSWORD_MAX_ARGON2_MEMORY',
    'LEGACY_PASSWORD_MAX_ITERATIONS',
    'LEGACY_PASSWORD_ALLOW_PLAINTEXT',
] as $key) {
    unset($_ENV[$key], $_SERVER[$key]);
    putenv($key);
}
