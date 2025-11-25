<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\sqlauth\Auth\Source;

use Exception;
use PHPUnit\Framework\TestCase;

/*
 * It was possible to misconfigure the SQL2 authentication source to point to
 * a non-existent database. This test ensures that this misconfiguration is
 * detected and handled gracefully.
 */
#CoversClass(SimpleSAML\Module\sqlauth\Auth\Source\SQL2::class)
class SQL2NonExistentDbTest extends TestCase
{
    /** @var array<string, string> */
    private array $info = ['AuthId' => 'testAuthId'];

    protected array $config = [
        "databases" => [
            "defaultdb" => [
                "dsn" => 'sqlite:file:defaultdb?mode=memory&cache=shared',
                "username" => "notused",
                "password" => "notused",
            ],
        ],
        "auth_queries" => [
            "auth_query" => [
                "database" => "wrong-name", // Non-existent database
                "query" => "select 1;",
            ],
        ],
    ];


    public function testNonExistentDatabaseFailure(): void
    {
        $this->expectException(Exception::class);
        (new SQL2Wrapper($this->info, $this->config))->callLogin('bob', 'password');
        $this->fail('Expected exception was not thrown.');
    }
}
