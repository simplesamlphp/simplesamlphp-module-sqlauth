<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\sqlauth\Auth\Source;

use PDO;
use PHPUnit\Framework\TestCase;

/**
 * The scenario for this test case is a single database of customers who have their
 * metadata in a single database. This is essentially the same tests as SQLTest, but
 * using the SQLv2 configuration and code, not the SQL1 code or SQL1Compat interface.
 * 
 * @covers \SimpleSAML\Module\core\Auth\Process\AttributeLimit
 */
class SQL2SimpleTest extends TestCase
{
    private array $info = ['AuthId' => 'testAuthId'];
    protected array $config = []; // Filled out in setUp()

    protected string $extraSqlSelectColumns = '';
    protected string $extraSqlAndClauses = ' and password=:password';

    public function setUp(): void
    {
        $this->config = [
            "databases" => [
                "defaultdb" => [
                    "dsn" => 'sqlite:file:defaultdb?mode=memory&cache=shared',
                    "username" => "notused",
                    "password" => "notused",
                ],
            ],
            "auth_queries" => [
                "auth_query" => [
                    "database" => "defaultdb",
                    "query" => null, // Filled out by each test case
                ],
            ],
        ];
    }

    protected static function transformPassword(string $password): string
    {
        // In this simple test, passwords are stored in plaintext, so no transformation is needed.
        // The SQL2PasswordVerifySimpleTest subclass override this to hash the password appropriately.
        return $password;
    }

    public static function setUpBeforeClass(): void
    {
        $pdo = new PDO('sqlite:file:defaultdb?mode=memory&cache=shared', null, null, [PDO::ATTR_PERSISTENT => true]);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $pdo->exec("DROP TABLE IF EXISTS users");
        $pdo->exec("DROP TABLE IF EXISTS usergroups");

        // Create tables
        $pdo->exec("
            CREATE TABLE users (
                uid VARCHAR(30) NOT NULL PRIMARY KEY,
                password TEXT NOT NULL,
                givenName TEXT NOT NULL,
                email TEXT NOT NULL
            )
        ");
        $pdo->exec("
            CREATE TABLE usergroups (
                uid VARCHAR(30) NOT NULL REFERENCES users (uid) ON DELETE CASCADE ON UPDATE CASCADE,
                groupname VARCHAR(30) NOT NULL,
                UNIQUE(uid, groupname)
            )
        ");

        // Create test data for users table
        $users = [
            ['alice', 'password', 'Alice', 'alice@example.com'],
            ['bob', 'password', 'Bob', 'bob@example.com'],
            ['trudy', 'password', 'Trudy', 'trudy@example.com'],
        ];
        foreach ($users as $user) {
            $pdo->prepare("INSERT INTO users VALUES (?,?,?,?)")
                ->execute($user);
        }

        // Create test data for usergroups table
        $groups = [
            ['alice', 'users'],
            ['alice', 'staff'],
            ['bob',   'users'],
            ['bob',   'students'],
            ['trudy', 'users'],
            ['trudy', 'students'],
            ['trudy', 'tutors'],
        ];
        foreach ($groups as $group) {
            $pdo->prepare("INSERT INTO usergroups VALUES (?,?)")
                ->execute($group);
        }
    }

    public function testBasicSingleSuccess(): void
    {
        // Correct username/password
        $this->config['auth_queries']['auth_query']['query'] = "select givenName, email " . $this->extraSqlSelectColumns . " from users where uid=:username" . $this->extraSqlAndClauses;
        $ret = (new SQL2Wrapper($this->info, $this->config))->callLogin('bob', 'password');
        asort($ret);
        $this->assertCount(2, $ret);
        $this->assertEquals($ret, [
            'email' => ['bob@example.com'],
            'givenName' => ["Bob"],
        ]);
    }

    public function testBasicSingleUsernameRegexSuccess(): void
    {
        // Correct username/password
        $this->config['auth_queries']['auth_query']['query'] = "select givenName, email " . $this->extraSqlSelectColumns . " from users where uid=:username" . $this->extraSqlAndClauses;
        $this->config['auth_queries']['auth_query']['username_regex'] = '/^[a-z]+$/'; // Username must be a single lower case word
        $ret = (new SQL2Wrapper($this->info, $this->config))->callLogin('bob', 'password');
        asort($ret);
        $this->assertCount(2, $ret);
        $this->assertEquals($ret, [
            'email' => ['bob@example.com'],
            'givenName' => ["Bob"],
        ]);
    }

    public function testBasicSingleUsernameRegexFailedLogin(): void
    {
        $this->expectException(\SimpleSAML\Error\Error::class);
        // Correct username/password, but doesn't match the username regex
        $this->config['auth_queries']['auth_query']['query'] = "select givenName, email " . $this->extraSqlSelectColumns . " from users where uid=:username" . $this->extraSqlAndClauses;
        $this->config['auth_queries']['auth_query']['username_regex'] = '/^\d+$/'; // Username must be a non-negative integer
        $ret = (new SQL2Wrapper($this->info, $this->config))->callLogin('bob', 'password');
        asort($ret);
        $this->assertCount(0, $ret);
    }

    public function testBasicSingleUsernameRegexFailedLoginNonExistingUser(): void
    {
        $this->expectException(\SimpleSAML\Error\Error::class);
        // Correct username/password, but doesn't match the username regex
        $this->config['auth_queries']['auth_query']['query'] = "select givenName, email " . $this->extraSqlSelectColumns . " from users where uid=:username" . $this->extraSqlAndClauses;
        $this->config['auth_queries']['auth_query']['username_regex'] = '/^\d+$/'; // Username must be a non-negative integer
        $ret = (new SQL2Wrapper($this->info, $this->config))->callLogin('henry', 'password');
        asort($ret);
        $this->assertCount(0, $ret);
    }

    public function testBasicSingleFailedLogin(): void
    {
        $this->expectException(\SimpleSAML\Error\Error::class);
        // Wrong username/password
        $this->config['auth_queries']['auth_query']['query'] = "select givenName, email " . $this->extraSqlSelectColumns . " from users where uid=:username" . $this->extraSqlAndClauses;
        $ret = (new SQL2Wrapper($this->info, $this->config))->callLogin('alice', 'wrong');
        $this->assertCount(0, $ret);
    }

    public function testJoinSingleSuccess(): void
    {
        // Correct username/password
        $this->config['auth_queries']['auth_query']['query'] = "
            select u.givenName, u.email, ug.groupname" . $this->extraSqlSelectColumns . " 
            from users u left join usergroups ug on (u.uid=ug.uid)
            where u.uid=:username" . $this->extraSqlAndClauses;
        $ret = (new SQL2Wrapper($this->info, $this->config))->callLogin('bob', 'password');
        asort($ret);
        asort($ret['groupname']);
        $this->assertCount(3, $ret);
        $this->assertEquals($ret, [
            'email' => ['bob@example.com'],
            'givenName' => ["Bob"],
            'groupname' => ['students', 'users'],
        ]);
    }

    public function testJoinSingleFailedLogin(): void
    {
        $this->expectException(\SimpleSAML\Error\Error::class);
        // Wrong username/password
        $this->config['auth_queries']['auth_query']['query'] = "
            select u.givenName, u.email, ug.groupname" . $this->extraSqlSelectColumns . " 
            from users u left join usergroups ug on (u.uid=ug.uid)
            where u.uid=:username" . $this->extraSqlAndClauses;
        $ret = (new SQL2Wrapper($this->info, $this->config))->callLogin('alice', 'wrong');
        $this->assertCount(0, $ret);
    }

    public function testMultiQuerySuccess(): void
    {
        // Correct username/password
        $this->config['auth_queries']['auth_query']['query'] = 
            "select givenName, email " . $this->extraSqlSelectColumns . " from users where uid=:username" . $this->extraSqlAndClauses;
        $this->config['attr_queries'] = [
            [
                'database' => 'defaultdb',
                'query' => "select groupname from usergroups where uid=:username",
            ]
        ];

        $ret = (new SQL2Wrapper($this->info, $this->config))->callLogin('bob', 'password');
        asort($ret);
        asort($ret['groupname']);
        $this->assertCount(3, $ret);
        $this->assertEquals($ret, [
            'email' => ['bob@example.com'],
            'givenName' => ["Bob"],
            'groupname' => ['students', 'users'],
        ]);
    }

    public function testMultiQueryFailedLogin(): void
    {
        $this->expectException(\SimpleSAML\Error\Error::class);
        // Wrong username/password
        $this->config['auth_queries']['auth_query']['query'] = 
            "select givenName, email " . $this->extraSqlSelectColumns . " from users where uid=:username" . $this->extraSqlAndClauses;
        $this->config['attr_queries'] = [
            [
                'database' => 'defaultdb',
                'query' => "select groupname from usergroups where uid=:username",
            ]
        ];
        $ret = (new SQL2Wrapper($this->info, $this->config))->callLogin('alice', 'wrong');
        $this->assertCount(0, $ret);
    }

    public function testMultiQuerySubsequentNoRowsSuccess(): void
    {
        // Correct username/password. Second query returns no rows, third query returns just one row
        $this->config['auth_queries']['auth_query']['query'] = 
            "select givenName, email " . $this->extraSqlSelectColumns . " from users where uid=:username" . $this->extraSqlAndClauses;
        $this->config['attr_queries'] = [
            [
                'database' => 'defaultdb',
                'query' => "select groupname from usergroups where uid=:username and groupname like '%nomatch%'",
            ],
            [
                'database' => 'defaultdb',
                'query' => "select groupname from usergroups where uid=:username and groupname like 'stud%'",
            ],
        ];

        $ret = (new SQL2Wrapper($this->info, $this->config))->callLogin('bob', 'password');
        asort($ret);
        asort($ret['groupname']);
        $this->assertCount(3, $ret);
        $this->assertEquals($ret, [
            'email' => ['bob@example.com'],
            'givenName' => ["Bob"],
            'groupname' => ['students'],
        ]);
    }

    public function testMultiQuerySubsequentAppendSuccess(): void
    {
        // Correct username/password. Second query returns a row, third query appends one row
        $this->config['auth_queries']['auth_query']['query'] = 
            "select givenName, email " . $this->extraSqlSelectColumns . " from users where uid=:username" . $this->extraSqlAndClauses;
        $this->config['attr_queries'] = [
            [
                'database' => 'defaultdb',
                'query' => "select groupname from usergroups where uid=:username and groupname like 'stud%'",
            ],
            [
                'database' => 'defaultdb',
                'query' => "select groupname from usergroups where uid=:username and groupname like '%sers'",
            ],
        ];
        $ret = (new SQL2Wrapper($this->info, $this->config))->callLogin('bob', 'password');
        asort($ret);
        asort($ret['groupname']);
        $this->assertCount(3, $ret);
        $this->assertEquals($ret, [
            'email' => ['bob@example.com'],
            'givenName' => ["Bob"],
            'groupname' => ['students', 'users'],
        ]);
    }
}
