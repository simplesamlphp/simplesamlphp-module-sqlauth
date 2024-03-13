<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\sqlauth\Auth\Source;

use Exception;
use PDO;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Configuration;
use SimpleSAML\Test\Module\sqlauth\Auth\Source\SQLWrapper;

/**
 * Test for the core:AttributeLimit filter.
 *
 * @covers \SimpleSAML\Module\core\Auth\Process\AttributeLimit
 */
class SQLTest extends TestCase
{
    private array $info = ['AuthId' => 'testAuthId'];
    private array $config = [
        "dsn" => 'sqlite:file::memory:?cache=shared',
        "username" => "notused",
        "password" => "notused",
        "query" => null, // Filled out by each test case
    ];

    public static function setUpBeforeClass(): void
    {
        $pdo = new PDO('sqlite:file::memory:?cache=shared', null, null, array(PDO::ATTR_PERSISTENT => true));

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
        $this->config['query'] = "select givenName, email from users where uid=:username and password=:password";
        $ret = (new SQLWrapper($this->info, $this->config))->callLogin('bob', 'password');
        asort($ret);
        $this->assertCount(2, $ret);
        $this->assertEquals($ret, [
            'email' => ['bob@example.com'],
            'givenName' => ["Bob"],
        ]);
    }

    public function testBasicSingleFailedLogin() {
        $this->expectException(\SimpleSAML\Error\Error::class);
        // Wrong username/password
        $this->config['query'] = "select givenName, email from users where uid=:username and password=:password";
        $ret = (new SQLWrapper($this->info, $this->config))->callLogin('alice', 'wrong');
        $this->assertCount(0, $ret);
    }

    public function testJoinSingleSuccess(): void
    {
        // Correct username/password
        $this->config['query'] = "
            select u.givenName, u.email, ug.groupname
            from users u left join usergroups ug on (u.uid=ug.uid)
            where u.uid=:username and u.password=:password";
        $ret = (new SQLWrapper($this->info, $this->config))->callLogin('bob', 'password');
        asort($ret);
        asort($ret['groupname']);
        $this->assertCount(3, $ret);
        $this->assertEquals($ret, [
            'email' => ['bob@example.com'],
            'givenName' => ["Bob"],
            'groupname' => ['students', 'users'],
        ]);
    }

    public function testJoinSingleFailedLogin() {
        $this->expectException(\SimpleSAML\Error\Error::class);
        // Wrong username/password
        $this->config['query'] = "
            select u.givenName, u.email, ug.groupname
            from users u left join usergroups ug on (u.uid=ug.uid)
            where u.uid=:username and u.password=:password";
        $ret = (new SQLWrapper($this->info, $this->config))->callLogin('alice', 'wrong');
        $this->assertCount(0, $ret);
    }

    public function testMultiQuerySuccess(): void
    {
        // Correct username/password
        $this->config['query'] = [
            "select givenName, email from users where uid=:username and password=:password",
            "select groupname from usergroups where uid=:username",
        ]; 
        $ret = (new SQLWrapper($this->info, $this->config))->callLogin('bob', 'password');
        asort($ret);
        asort($ret['groupname']);
        $this->assertCount(3, $ret);
        $this->assertEquals($ret, [
            'email' => ['bob@example.com'],
            'givenName' => ["Bob"],
            'groupname' => ['students', 'users'],
        ]);
    }

    public function testMultiQueryFailedLogin() {
        $this->expectException(\SimpleSAML\Error\Error::class);
        // Wrong username/password
        $this->config['query'] = [
            "select givenName, email from users where uid=:username and password=:password",
            "select groupname from usergroups where uid=:username",
        ]; 
        $ret = (new SQLWrapper($this->info, $this->config))->callLogin('alice', 'wrong');
        $this->assertCount(0, $ret);
    }

    public function testMultiQuerySubsequentNoRowsSuccess(): void
    {
        // Correct username/password. Second query returns no rows, third query returns just one row
        $this->config['query'] = [
            "select givenName, email from users where uid=:username and password=:password",
            "select groupname from usergroups where uid=:username and groupname like '%nomatch%'",
            "select groupname from usergroups where uid=:username and groupname like 'stud%'",
        ]; 
        $ret = (new SQLWrapper($this->info, $this->config))->callLogin('bob', 'password');
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
        $this->config['query'] = [
            "select givenName, email from users where uid=:username and password=:password",
            "select groupname from usergroups where uid=:username and groupname like 'stud%'",
            "select groupname from usergroups where uid=:username and groupname like '%sers'",
        ]; 
        $ret = (new SQLWrapper($this->info, $this->config))->callLogin('bob', 'password');
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
