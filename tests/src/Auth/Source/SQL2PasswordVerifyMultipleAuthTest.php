<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\sqlauth\Auth\Source;

use PDO;
use PHPUnit\Framework\TestCase;

/**
 * The scenario is SQL2MultipleAuthTest but with passwords hashed using password_hash()
 *
 * @covers \SimpleSAML\Module\core\Auth\Process\AttributeLimit
 */
class SQL2PasswordVerifyMultipleAuthTest extends SQL2MultipleAuthTest
{
    // We need to return password column for password_verify() to use.
    protected string $extraSqlSelectColumns = ', password ';

    // We need to not specify the 'password=:password' clause in the WHERE clause,
    // as password_verify() does not work that way.
    protected string $extraSqlAndClauses = '';

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

        $studentsPdo = new PDO('sqlite:file:studentsdb?mode=memory&cache=shared', null, null, [PDO::ATTR_PERSISTENT => true]);
        $studentsPdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $studentsPdo->prepare("UPDATE students SET password=?")
                ->execute([password_hash('password', PASSWORD_ARGON2ID)]);

        $staffPdo = new PDO('sqlite:file:staffdb?mode=memory&cache=shared', null, null, [PDO::ATTR_PERSISTENT => true]);
        $staffPdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $staffPdo->prepare("UPDATE staff SET password=?")
            ->execute([password_hash('password', PASSWORD_ARGON2ID)]);
        
        $physicsStaffPdo = new PDO('sqlite:file:physics_staffdb?mode=memory&cache=shared', null, null, [PDO::ATTR_PERSISTENT => true]);
        $physicsStaffPdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $physicsStaffPdo->prepare("UPDATE staff SET password=?")
            ->execute([password_hash('password', PASSWORD_ARGON2ID)]);
    }
}
