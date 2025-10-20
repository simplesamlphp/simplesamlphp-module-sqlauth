<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\sqlauth\Auth\Source;

use PDO;

/**
 * The scenario for this test case is a single database of customers who have their
 * metadata spread across multiple databases, and passwords are hashed using password_hash(),
 * and verification done using password_verify(). Customers login with their email address,
 * but the common identifier across all databases is the userid (uid).
 * 
 * The attributes then come from multiple databases.
 * 
 * @covers \SimpleSAML\Module\core\Auth\Process\AttributeLimit
 */
class SQL2PasswordVerifySingleAuthTest extends SQL2SingleAuthTest
{
    // We need to return password column for password_verify() to use.
    protected string $extraSqlSelectColumns = ', password ';

    // We need to not specify the 'password=:password' clause in the WHERE clause,
    // as password_verify() does not work that way.
    protected string $extraSqlAndClauses = '';

    protected function getConfig(int $numDatabases, int $numAuthQueries, array $authQueryAttributes, int $numAttrQueries): array
    {
        $config = parent::getConfig($numDatabases, $numAuthQueries, $authQueryAttributes, $numAttrQueries);

        foreach ($config['auth_queries'] as &$query) {
            $query['password_verify_hash_column'] = 'password';
        }

        return $config;
    }

    public static function setUpBeforeClass(): void
    {
        parent::setUpBeforeClass();

        $pdo = new PDO('sqlite:file:authdb?mode=memory&cache=shared', null, null, [PDO::ATTR_PERSISTENT => true]);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $pdo->prepare("UPDATE users SET password=?")
                ->execute([password_hash('password', PASSWORD_ARGON2ID)]);
    }
}
