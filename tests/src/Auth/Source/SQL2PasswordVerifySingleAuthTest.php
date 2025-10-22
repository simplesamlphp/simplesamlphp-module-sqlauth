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
 */
#CoversClass(SimpleSAML\Module\sqlauth\Auth\Source\SQL2::class)
class SQL2PasswordVerifySingleAuthTest extends SQL2SingleAuthTest
{
    // We need to return password column for password_verify() to use.
    protected string $extraSqlSelectColumns = ', password ';

    // We need to not specify the 'password=:password' clause in the WHERE clause,
    // as password_verify() does not work that way.
    protected string $extraSqlAndClauses = '';


    /**
     * Different tests require different combinations of databases, auth queries and attr queries.
     * This function returns a config with the requested number of each.
     *
     * @param int $numDatabases
     * @param int $numAuthQueries
     * @param array<string> $authQueryAttributes
     * @param int $numAttrQueries
     * @return array<string, mixed>
     */
    protected function getConfig(
        int $numDatabases,
        int $numAuthQueries,
        array $authQueryAttributes,
        int $numAttrQueries,
    ): array {
        $config = parent::getConfig($numDatabases, $numAuthQueries, $authQueryAttributes, $numAttrQueries);

        // @phpstan-ignore argument.type
        foreach (array_keys($config['auth_queries']) as $authQueryName) {
            // @phpstan-ignore offsetAccess.nonOffsetAccessible
            $config['auth_queries'][$authQueryName]['password_verify_hash_column'] = 'password';
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
