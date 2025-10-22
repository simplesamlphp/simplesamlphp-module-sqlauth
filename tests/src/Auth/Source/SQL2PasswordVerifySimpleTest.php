<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\sqlauth\Auth\Source;

use PDO;

/**
 * The scenario for this test case is a single database of customers who have their
 * metadata in a single database, and passwords are hashed using password_hash(),
 * and verification done using password_verify().
 *
 * The tests are essentially the same tests as SQLTest, but using the SQLv2
 * configuration and code, not the SQL1 code or SQL1Compat interface.
 */
#CoversClass(SimpleSAML\Module\sqlauth\Auth\Source\SQL2::class)
class SQL2PasswordVerifySimpleTest extends SQL2SimpleTest
{
    // We need to return password column for password_verify() to use.
    protected string $extraSqlSelectColumns = ', password ';

    // We need to not specify the 'password=:password' clause in the WHERE clause,
    // as password_verify() does not work that way.
    protected string $extraSqlAndClauses = ' ';


    public function setUp(): void
    {
        parent::setUp();

        foreach ($this->config['auth_queries'] as &$query) {
            $query['password_verify_hash_column'] = 'password';
        }
    }


    public static function setUpBeforeClass(): void
    {
        parent::setUpBeforeClass();

        $pdo = new PDO('sqlite:file:defaultdb?mode=memory&cache=shared', null, null, [PDO::ATTR_PERSISTENT => true]);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $pdo->prepare("UPDATE users SET password=?")
                ->execute([password_hash('password', PASSWORD_ARGON2ID)]);
    }
}
