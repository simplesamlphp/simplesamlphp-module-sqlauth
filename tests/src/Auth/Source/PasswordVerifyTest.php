<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\sqlauth\Auth\Source;

use PDO;
use PHPUnit\Framework\TestCase;

#CoversClass(\SimpleSAML\Module\sqlauth\Auth\Source\PasswordVerify::class)
class PasswordVerifyTest extends TestCase
{
    /** @var array<string, string> */
    private array $info = ['AuthId' => 'testAuthId'];

    /** @var array<string, list<string>|string|null> */
    private array $config = [
        "dsn" => 'sqlite:file::memory:?cache=shared',
        "username" => "notused",
        "password" => "notused",
        "query" => null, // Filled out by each test case
    ];


    public static function setUpBeforeClass(): void
    {
        $pdo = new PDO('sqlite:file::memory:?cache=shared', null, null, [PDO::ATTR_PERSISTENT => true]);

        $pdo->exec("DROP TABLE IF EXISTS users");
        $pdo->exec("DROP TABLE IF EXISTS usergroups");

        // Create tables
        $pdo->exec("
            CREATE TABLE users (
                uid VARCHAR(30) NOT NULL PRIMARY KEY,
                passwordhash TEXT NOT NULL,
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

        $p1 = password_hash("password1", PASSWORD_ARGON2ID);
        $p2 = password_hash("password2", PASSWORD_ARGON2ID);

        // Create test data for users table
        $users = [
            ['alice', $p1, 'Alice', 'alice@example.com'],
            ['bob', $p1, 'Bob', 'bob@example.com'],
            ['trudy', $p2, 'Trudy', 'trudy@example.com'],
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


    /**
     * @param array<mixed> $info
     * @param array<mixed> $config
     */
    protected function createWrapper(array $info, array $config): WrapperInterface
    {
        return new PasswordVerifyWrapper($info, $config);
    }


    public function testBasicSingleSuccess(): void
    {
        // Correct username/password
        $this->config['query'] = "select givenName, email, passwordhash from users where uid=:username";
        $ret = $this->createWrapper($this->info, $this->config)->callLogin('bob', 'password1');
        asort($ret);
        $this->assertCount(2, $ret);
        $this->assertEquals($ret, [
            'email' => ['bob@example.com'],
            'givenName' => ["Bob"],
        ]);
    }


    public function testBasicSingleFailedLogin(): void
    {
        $this->expectException(\SimpleSAML\Error\Error::class);
        // Wrong username/password
        $this->config['query'] = "select givenName, email, passwordhash from users where uid=:username";
        $ret = $this->createWrapper($this->info, $this->config)->callLogin('alice', 'wrong');
        $this->assertCount(0, $ret);
    }


    public function testBasicSingleFailedLoginNonExisting(): void
    {
        $this->expectException(\SimpleSAML\Error\Error::class);
        // Wrong username/password
        $this->config['query'] = "select givenName, email, passwordhash from users where uid=:username";
        $ret = $this->createWrapper($this->info, $this->config)->callLogin('henry', 'boo');
        $this->assertCount(0, $ret);
    }


    public function testBasicSingleFailedLoginNonExistingNoPassword(): void
    {
        $this->expectException(\SimpleSAML\Error\Error::class);
        // Wrong username/password
        $this->config['query'] = "select givenName, email, passwordhash from users where uid=:username";
        $ret = $this->createWrapper($this->info, $this->config)->callLogin('alice2', '');
        $this->assertCount(0, $ret);
    }


    public function testJoinSingleSuccess(): void
    {
        // Correct username/password
        $this->config['query'] = "
            select u.givenName, u.email, ug.groupname, passwordhash
            from users u left join usergroups ug on (u.uid=ug.uid)
            where u.uid=:username 
            order by ug.groupname";
        $ret = $this->createWrapper($this->info, $this->config)->callLogin('bob', 'password1');
        asort($ret);
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
        $this->config['query'] = "
            select u.givenName, u.email, ug.groupname, passwordhash
            from users u left join usergroups ug on (u.uid=ug.uid)
            where u.uid=:username";
        $ret = $this->createWrapper($this->info, $this->config)->callLogin('alice', 'wrong');
        $this->assertCount(0, $ret);
    }


    public function testMultiQuerySuccess(): void
    {
        // Correct username/password
        $this->config['query'] = [
            "select givenName, email, passwordhash from users where uid=:username",
            "select groupname from usergroups where uid=:username order by groupname",
        ];
        $ret = $this->createWrapper($this->info, $this->config)->callLogin('bob', 'password1');
        asort($ret);
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
        $this->config['query'] = [
            "select givenName, email, passwordhash from users where uid=:username",
            "select groupname from usergroups where uid=:username",
        ];
        $ret = $this->createWrapper($this->info, $this->config)->callLogin('alice', 'wrong');
        $this->assertCount(0, $ret);
    }


    public function testMultiQuerySubsequentNoRowsSuccess(): void
    {
        // Correct username/password. Second query returns no rows, third query returns just one row
        $this->config['query'] = [
            "select givenName, email, passwordhash from users where uid=:username",
            "select groupname from usergroups where uid=:username and groupname like '%nomatch%'",
            "select groupname from usergroups where uid=:username and groupname like 'stud%' order by groupname",
        ];
        $ret = $this->createWrapper($this->info, $this->config)->callLogin('bob', 'password1');
        asort($ret);
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
        $this->config['query'] = [
            "select givenName, email, passwordhash from users where uid=:username",
            "select groupname from usergroups where uid=:username and groupname like 'stud%' order by groupname",
            "select groupname from usergroups where uid=:username and groupname like '%sers' order by groupname",
        ];
        $ret = $this->createWrapper($this->info, $this->config)->callLogin('bob', 'password1');
        asort($ret);
        $this->assertCount(3, $ret);
        $this->assertEquals($ret, [
            'email' => ['bob@example.com'],
            'givenName' => ["Bob"],
            'groupname' => ['students', 'users'],
        ]);
    }
}
