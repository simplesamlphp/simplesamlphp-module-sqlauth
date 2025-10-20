<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\sqlauth\Auth\Source;

use PDO;
use PHPUnit\Framework\TestCase;

/**
 * The scenario for this test case is a single database of customers who have their
 * metadata spread across multiple databases. Customers login with their email address,
 * but the common identifier across all databases is the userid (uid).
 *
 * The attributes then come from multiple databases.
 *
 * @covers \SimpleSAML\Module\core\Auth\Process\AttributeLimit
 */
class SQL2SingleAuthTest extends TestCase
{
    /** @var array<string, string> */
    private array $info = ['AuthId' => 'testAuthId'];

    protected string $extraSqlSelectColumns = '';

    protected string $extraSqlAndClauses = ' and password=:password';


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
        $config = [
            "databases" => [
                "authdb" => [
                    "dsn" => 'sqlite:file:authdb?mode=memory&cache=shared',
                    "username" => "notused",
                    "password" => "notused",
                ],
                "staffdb" => [
                    "dsn" => 'sqlite:file:staffdb?mode=memory&cache=shared',
                    "username" => "notused",
                    "password" => "notused",
                ],
                "studentsdb" => [
                    "dsn" => 'sqlite:file:studentsdb?mode=memory&cache=shared',
                    "username" => "notused",
                    "password" => "notused",
                ],
            ],
            "auth_queries" => [
                "auth_query_id" => [
                    "database" => "authdb",
                    "query" =>
                        "select uid, givenName, email " . $this->extraSqlSelectColumns .
                        " from users where uid=:username" . $this->extraSqlAndClauses,
                    "username_regex" => '/^\\d+$/',
                    "extract_userid_from" => 'uid',
                ],
                "auth_query_email" => [
                    "database" => "authdb",
                    "query" =>
                        "select uid, givenName, email " . $this->extraSqlSelectColumns .
                        " from users where email=:username" . $this->extraSqlAndClauses,
                    "username_regex" => '/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/',
                    "extract_userid_from" => 'uid',
                ],
            ],
            "attr_queries" => [
                [
                    'database' => 'staffdb',
                    'query' => "select department, role from staff where uid=:userid",
                ],
                [
                    'database' => 'studentsdb',
                    'query' => "select course, year from students where uid=:userid",
                ],
                [
                    'database' => 'studentsdb',
                    'query' => "select unit_code from units_enrolled where uid=:userid",
                ],
            ],
        ];

        $ret = [];
        $ret['databases'] = array_slice($config['databases'], 0, $numDatabases);
        $ret['auth_queries'] = array_slice($config['auth_queries'], 0, $numAuthQueries);
        $ret['attr_queries'] = array_slice($config['attr_queries'], 0, $numAttrQueries);

        // Only return the auth query attributes that were requested
        foreach ($ret['auth_queries'] as $authQueryName => $authQuery) {
            // Firstly, go through each auth query, removing any that weren't requested.
            foreach (array_keys($authQuery) as $authQueryKey) {
                if (!in_array($authQueryKey, $authQueryAttributes)) {
                    unset($ret['auth_queries'][$authQueryName][$authQueryKey]);
                }
            }

            // Then check all of the requested attributes are in each auth query.
            foreach ($authQueryAttributes as $attribute) {
                if (!array_key_exists($attribute, $authQuery)) {
                    throw new \InvalidArgumentException(
                        "Auth query attribute \"$attribute\" not found in auth query \"$authQueryName\"",
                    );
                }
            }
        }

        return $ret;
    }


    public static function setUpBeforeClass(): void
    {
        // Auth database
        $authPdo = new PDO('sqlite:file:authdb?mode=memory&cache=shared', null, null, [PDO::ATTR_PERSISTENT => true]);
        $authPdo->exec("DROP TABLE IF EXISTS users");

        // Create tables
        $authPdo->exec("
            CREATE TABLE users (
                uid int NOT NULL PRIMARY KEY,
                password TEXT NOT NULL,
                givenName TEXT NOT NULL,
                email TEXT NOT NULL
            )
        ");

        // Create test data for users table
        $users = [
            [1, 'password', 'Alice', 'alice@example.com'],
            [2, 'password', 'Bob', 'bob@example.com'],
            [3, 'password', 'Trudy', 'trudy@example.com'],
            [4, 'password', 'Eve', 'eve@example.com'],
            [5, 'password', 'Mallory', 'mallory@example.com'],
        ];
        foreach ($users as $user) {
            $authPdo->prepare("INSERT INTO users VALUES (?,?,?,?)")
                ->execute($user);
        }

        // Staff database
        $staffPdo = new PDO('sqlite:file:staffdb?mode=memory&cache=shared', null, null, [PDO::ATTR_PERSISTENT => true]);
        $staffPdo->exec("DROP TABLE IF EXISTS staff");
        $staffPdo->exec("
            CREATE TABLE staff (
                uid int NOT NULL PRIMARY KEY,
                department TEXT NOT NULL,
                role TEXT NOT NULL
            )
        ");
        $staff = [
            [1, 'HR', 'Manager'],
            [2, 'IT', 'Developer'],
        ];
        foreach ($staff as $s) {
            $staffPdo->prepare("INSERT INTO staff VALUES (?,?,?)")
                ->execute($s);
        }

        // Students database
        $studentsPdo = new PDO(
            'sqlite:file:studentsdb?mode=memory&cache=shared',
            null,
            null,
            [PDO::ATTR_PERSISTENT => true],
        );
        $studentsPdo->exec("DROP TABLE IF EXISTS students");
        $studentsPdo->exec("
            CREATE TABLE students (
                uid int NOT NULL PRIMARY KEY,
                course TEXT NOT NULL,
                year int NOT NULL
            )
        ");
        $students = [
            [3, 'Computer Science', 2],
            [4, 'Mathematics', 1],
            [5, 'Physics', 3],
        ];
        foreach ($students as $s) {
            $studentsPdo->prepare("INSERT INTO students VALUES (?,?,?)")
                ->execute($s);
        }

        $studentsPdo->exec("DROP TABLE IF EXISTS units_enrolled");

        $studentsPdo->exec("
            CREATE TABLE units_enrolled (
                uid int NOT NULL,
                unit_code TEXT NOT NULL,
                PRIMARY KEY (uid, unit_code)
            )
        ");
        $enrollments = [
            [3, 'CS101'],
            [3, 'CS102'],
            [5, 'PHYS101'],
        ];
        foreach ($enrollments as $e) {
            $studentsPdo->prepare("INSERT INTO units_enrolled VALUES (?,?)")
                ->execute($e);
        }
    }


    public function testSingleAuthQueryOnlySuccess(): void
    {
        $config = $this->getConfig(1, 1, ['database', 'query'], 0);

        // Correct username/password
        $ret = (new SQL2Wrapper($this->info, $config))->callLogin('2', 'password');
        asort($ret);
        $this->assertCount(3, $ret);
        $this->assertEquals($ret, [
            'uid' => ['2'],
            'email' => ['bob@example.com'],
            'givenName' => ["Bob"],
        ]);
    }


    public function testSingleAuthQueryOnlyPasswordFailure(): void
    {
        $this->expectException(\SimpleSAML\Error\Error::class);

        $config = $this->getConfig(1, 1, ['database', 'query'], 0);

        // Wrong password
        (new SQL2Wrapper($this->info, $config))->callLogin('2', 'wrongpassword');
    }


    public function testSingleAuthQueryOnlyUsernameFailure(): void
    {
        $this->expectException(\SimpleSAML\Error\Error::class);

        $config = $this->getConfig(1, 1, ['database', 'query'], 0);

        // Nonexistent username
        (new SQL2Wrapper($this->info, $config))->callLogin('201', 'password');
    }


    public function testSingleAuthQueryOnlySuccessWithRegex(): void
    {
        $config = $this->getConfig(1, 1, ['database', 'query', 'username_regex'], 0);

        // Correct username/password
        $ret = (new SQL2Wrapper($this->info, $config))->callLogin('2', 'password');
        asort($ret);
        $this->assertCount(3, $ret);
        $this->assertEquals($ret, [
            'uid' => ['2'],
            'email' => ['bob@example.com'],
            'givenName' => ["Bob"],
        ]);
    }


    public function testSingleAuthQueryOnlyFailureDueToRegex(): void
    {
        $this->expectException(\SimpleSAML\Error\Error::class);
        $config = $this->getConfig(1, 1, ['database', 'query', 'username_regex'], 0);

        // Correct username/password
        (new SQL2Wrapper($this->info, $config))->callLogin('bad-username', 'password');
    }


    public function testSingleAuthQuerySingleAttrQuerySuccess(): void
    {
        $config = $this->getConfig(2, 1, ['database', 'query', 'extract_userid_from'], 1);

        // Correct username/password
        $ret = (new SQL2Wrapper($this->info, $config))->callLogin('2', 'password');
        asort($ret);

        $this->assertCount(5, $ret);
        $this->assertEquals($ret, [
            'uid' => ['2'],
            'email' => ['bob@example.com'],
            'givenName' => ["Bob"],
            'department' => ['IT'],
            'role' => ['Developer'],
        ]);
    }


    public function testSingleAuthQuerySingleAttrQueryPasswordFailure(): void
    {
        $this->expectException(\SimpleSAML\Error\Error::class);

        $config = $this->getConfig(2, 1, ['database', 'query'], 1);

        // Wrong password
        (new SQL2Wrapper($this->info, $config))->callLogin('2', 'wrongpassword');
    }


    public function testMultipleAuthQueryNoAttrQueryUsernameIsIdSuccess(): void
    {
        $config = $this->getConfig(2, 2, ['database', 'query', 'username_regex'], 0);

        // Correct username/password
        $ret = (new SQL2Wrapper($this->info, $config))->callLogin('2', 'password');
        asort($ret);
        $this->assertCount(3, $ret);
        $this->assertEquals($ret, [
            'uid' => ['2'],
            'email' => ['bob@example.com'],
            'givenName' => ["Bob"],
        ]);
    }


    public function testMultipleAuthQueryNoAttrQueryUsernameIsEmailSuccess(): void
    {
        $config = $this->getConfig(2, 2, ['database', 'query', 'username_regex'], 0);

        // Correct username/password
        $ret = (new SQL2Wrapper($this->info, $config))->callLogin('bob@example.com', 'password');
        asort($ret);
        $this->assertCount(3, $ret);
        $this->assertEquals($ret, [
            'uid' => ['2'],
            'email' => ['bob@example.com'],
            'givenName' => ["Bob"],
        ]);
    }


    public function testMultipleAuthQueryNoAttrQueryUsernameIsEmailFailure(): void
    {
        $this->expectException(\SimpleSAML\Error\Error::class);

        $config = $this->getConfig(2, 2, ['database', 'query', 'username_regex'], 0);

        // Correct username/password
        (new SQL2Wrapper($this->info, $config))->callLogin('nonexistent@example.com', 'password');
    }


    public function testMultipleAuthQuerySingleAttrQueryUsernameIsEmailSuccess(): void
    {
        $config = $this->getConfig(2, 2, ['database', 'query', 'username_regex', 'extract_userid_from'], 1);

        // Correct username/password
        $ret = (new SQL2Wrapper($this->info, $config))->callLogin('bob@example.com', 'password');
        asort($ret);

        $this->assertCount(5, $ret);
        $this->assertEquals($ret, [
            'uid' => ['2'],
            'email' => ['bob@example.com'],
            'givenName' => ["Bob"],
            'department' => ['IT'],
            'role' => ['Developer'],
        ]);
    }


    public function testMultipleAuthQueryStudentWithMultipleEnrolmentsSuccess(): void
    {
        $config = $this->getConfig(3, 2, ['database', 'query', 'username_regex', 'extract_userid_from'], 3);

        // Correct username/password
        $ret = (new SQL2Wrapper($this->info, $config))->callLogin('3', 'password');
        asort($ret);
        $this->assertCount(6, $ret);
        $this->assertEquals($ret, [
            'uid' => ['3'],
            'email' => ['trudy@example.com'],
            'givenName' => ["Trudy"],
            'course' => ['Computer Science'],
            'year' => ['2'],
            'unit_code' => ['CS101', 'CS102'],
        ]);
    }


    public function testMultipleAuthQueryStudentWithNoEnrolmentsSuccess(): void
    {
        $config = $this->getConfig(3, 2, ['database', 'query', 'username_regex', 'extract_userid_from'], 3);

        // Correct username/password
        $ret = (new SQL2Wrapper($this->info, $config))->callLogin('4', 'password');
        asort($ret);
        $this->assertCount(5, $ret);
        $this->assertArrayNotHasKey('unit_code', $ret);
        $this->assertEquals($ret, [
            'uid' => ['4'],
            'email' => ['eve@example.com'],
            'givenName' => ["Eve"],
            'course' => ['Mathematics'],
            'year' => ['1'],
            // No units_enrolled, 'unit_code' is not set
        ]);
    }


    public function testMultipleAuthQueryStudentWithSingleEnrolmentSuccess(): void
    {
        $config = $this->getConfig(3, 2, ['database', 'query', 'username_regex', 'extract_userid_from'], 3);

        // Correct username/password
        $ret = (new SQL2Wrapper($this->info, $config))->callLogin('5', 'password');
        asort($ret);
        $this->assertCount(6, $ret);
        $this->assertEquals($ret, [
            'uid' => ['5'],
            'email' => ['mallory@example.com'],
            'givenName' => ["Mallory"],
            'course' => ['Physics'],
            'year' => ['3'],
            'unit_code' => ['PHYS101'],
        ]);
    }
}
