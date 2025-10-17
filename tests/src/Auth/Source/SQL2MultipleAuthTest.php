<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\sqlauth\Auth\Source;

use PDO;
use PHPUnit\Framework\TestCase;

/**
 * The scenario for this test case is two separate types of users (staff and students), 
 * each of which has its own set of attributes in separate databases. In addition, the
 * physics department have their own legacy database of staff, which has some extra 
 * attributes which are not in the main staff database, and their passwords are still
 * in that legacy database. But physics staff records exist in the new staff database too.
 * 
 * The technical scenario is that there is one student database, two staff databases,
 * which a subset of the staff are in only one database, whereas some staff are in both.
 * Attributes for students come from just the student database, whereas the staff attributes
 * come from both staff databases if the user is in both, and only the main staff database
 * if they are not in the physics department.
 *
 * @covers \SimpleSAML\Module\core\Auth\Process\AttributeLimit
 */
class SQL2MultipleAuthTest extends TestCase
{
    private array $info = ['AuthId' => 'testAuthId'];
    private array $config = [
        "databases" => [
            "studentsdb" => [
                "dsn" => 'sqlite:file:studentsdb?mode=memory&cache=shared',
                "username" => "notused",
                "password" => "notused",
            ],
            "physics_staffdb" => [
                "dsn" => 'sqlite:file:physics_staffdb?mode=memory&cache=shared',
                "username" => "notused",
                "password" => "notused",
            ],
            "staffdb" => [
                "dsn" => 'sqlite:file:staffdb?mode=memory&cache=shared',
                "username" => "notused",
                "password" => "notused",
            ],
        ],
        "auth_queries" => [
            "auth_query_students" => [
                "database" => "studentsdb",
                "query" => "select studentid, givenName, lastName, email, course, year from students where email=:username and password=:password",
                "username_regex" => '/^[a-zA-Z0-9._%+-]+@student\.example\.edu$/',
                "extract_userid_from" => 'studentid',
            ],

            // We specify the physics_staffdb auth query before the staffdb one, so that if a user exists in both
            // staff databases, they will be authenticated against the physics_staffdb one.
            "auth_query_physics_staff" => [
                "database" => "physics_staffdb",
                "query" => "select psid as uid, CASE WHEN typically_wears_matching_socks=true THEN 'true' ELSE 'false' END as \"typically_wears_matching_socks\" from staff where email=:username and password=:password",
                "username_regex" => '/^[a-zA-Z0-9._%+-]+@example\.edu$/',
                "extract_userid_from" => 'uid',
            ],

            "auth_query_staff" => [
                "database" => "staffdb",
                "query" => "select uid, givenName, lastName, email, department from staff where email=:username and password=:password",
                "username_regex" => '/^[a-zA-Z0-9._%+-]+@example\.edu$/',
                "extract_userid_from" => 'uid',
            ],
        ],
        "attr_queries" => [
            [
                'database' => 'staffdb',
                'query' => "select givenName, lastName, email, department from staff where uid=:userid",
                'only_for_auth' => ['auth_query_staff', 'auth_query_physics_staff'],
            ],
            [
                'database' => 'staffdb',
                'query' => "select role from staff_roles where uid=:userid",
                'only_for_auth' => ['auth_query_staff', 'auth_query_physics_staff'],
            ],
            [
                'database' => 'physics_staffdb',
                'query' => "select qualification from staff_qualifications where psid=:userid order by qualification desc",
                'only_for_auth' => ['auth_query_physics_staff'],
            ],
            [
                'database' => 'studentsdb',
                'query' => "select unit_code from units_enrolled where studentid=:userid",
                'only_for_auth' => ['auth_query_students'],
            ],
        ],
    ];

    public static function setUpBeforeClass(): void
    {
        // Students database
        $studentsPdo = new PDO('sqlite:file:studentsdb?mode=memory&cache=shared', null, null, [PDO::ATTR_PERSISTENT => true]);
        $studentsPdo->exec("DROP TABLE IF EXISTS students");
        // Create tables
        $studentsPdo->exec("
            CREATE TABLE students (
                studentid int NOT NULL PRIMARY KEY,
                givenName TEXT NOT NULL,
                lastName TEXT NOT NULL,
                email TEXT NOT NULL,
                password TEXT NOT NULL,
                course TEXT NOT NULL,
                year int NOT NULL
            )
        ");

        // Create test data for students table
        $students = [
            [1, 'Alice', 'Gibson', 'alice.gibson@student.example.edu', 'password', 'Engineering', 1],
            [2, 'Bob', 'Builder', 'bob.builder@student.example.edu', 'password', 'Architecture', 2],
            [3, 'Trudy', 'Tester', 'trudy.tester@student.example.edu', 'password', 'Computer Science', 3],
        ];
        foreach ($students as $student) {
            $studentsPdo->prepare("INSERT INTO students VALUES (?,?,?,?,?,?,?)")
                ->execute($student);
        }

        $studentsPdo->exec("DROP TABLE IF EXISTS units_enrolled");
        $studentsPdo->exec("
            CREATE TABLE units_enrolled (
                studentid int NOT NULL,
                unit_code TEXT NOT NULL,
                PRIMARY KEY (studentid, unit_code)
            )
        ");
        $enrollments = [
            [1, 'ENG101'],
            [1, 'ENG102'],
            [2, 'ARCH201'],
            [3, 'CS101'],
            [3, 'CS102'],
        ];
        foreach ($enrollments as $e) {
            $studentsPdo->prepare("INSERT INTO units_enrolled VALUES (?,?)")
                ->execute($e);
        }


        // Staff database
        $staffPdo = new PDO('sqlite:file:staffdb?mode=memory&cache=shared', null, null, [PDO::ATTR_PERSISTENT => true]);
        $staffPdo->exec("DROP TABLE IF EXISTS staff");
        $staffPdo->exec("
            CREATE TABLE staff (
                uid int NOT NULL PRIMARY KEY,
                givenName TEXT NOT NULL,
                lastName TEXT NOT NULL,
                email TEXT NOT NULL,
                password TEXT DEFAULT NULL,
                department TEXT NOT NULL
            )
        ");
        $staff = [
            [1, 'Eve', 'Evans', 'eve.evans@example.edu', 'password', 'Mathematics'],
            [2, 'Mallory', 'Mallory', 'mallory.mallory@example.edu', 'password', 'Physics'],
        ];
        foreach ($staff as $s) {
            $staffPdo->prepare("INSERT INTO staff VALUES (?,?,?,?,?,?)")
                ->execute($s);
        }

        $staffPdo->exec("DROP TABLE IF EXISTS staff_roles");
        $staffPdo->exec("
            CREATE TABLE staff_roles (
                uid int NOT NULL,
                role TEXT NOT NULL,
                PRIMARY KEY (uid, role)
            )
        ");
        $roles = [
            [1, 'lecturer'],
            [2, 'professor'],
        ];
        foreach ($roles as $r) {
            $staffPdo->prepare("INSERT INTO staff_roles VALUES (?,?)")
                ->execute($r);
        }

        // Physics staff database
        $physicsStaffPdo = new PDO('sqlite:file:physics_staffdb?mode=memory&cache=shared', null, null, [PDO::ATTR_PERSISTENT => true]);
        $physicsStaffPdo->exec("DROP TABLE IF EXISTS staff");
        $physicsStaffPdo->exec("
            CREATE TABLE staff (
                psid int NOT NULL PRIMARY KEY,
                email TEXT NOT NULL,
                password TEXT DEFAULT NULL,
                typically_wears_matching_socks BOOLEAN NOT NULL
            )
        ");
        $physicsStaff = [
            [2, 'mallory.mallory@example.edu', 'password', false],
        ];
        foreach ($physicsStaff as $ps) {
            $physicsStaffPdo->prepare("INSERT INTO staff VALUES (?,?,?,?)")
                ->execute($ps);
        }

        $physicsStaffPdo->exec("DROP TABLE IF EXISTS staff_qualifications");
        $physicsStaffPdo->exec("
            CREATE TABLE staff_qualifications (
                psid int NOT NULL,
                qualification TEXT NOT NULL,
                PRIMARY KEY (psid, qualification)
            )
        ");
        $physicsStaff = [
            [2, 'PhD in Physics'],
            [2, 'MSc in Astrophysics'],
        ];
        foreach ($physicsStaff as $ps) {
            $physicsStaffPdo->prepare("INSERT INTO staff_qualifications VALUES (?,?)")
                ->execute($ps);
        }
    }

    public function testStudentLoginSuccess(): void
    {
        // Correct username/password
        $ret = (new SQL2Wrapper($this->info, $this->config))->callLogin('alice.gibson@student.example.edu', 'password');
        asort($ret);
        $this->assertCount(7, $ret);
        $this->assertCount(2, $ret['unit_code']);
        $this->assertEquals($ret, [
            'studentid' => ['1'],
            'givenName' => ["Alice"],
            'lastName' => ["Gibson"],
            'email' => ['alice.gibson@student.example.edu'],
            'course' => ["Engineering"],
            'year' => ["1"],
            'unit_code' => ["ENG101", "ENG102"],
        ]);
    }

    public function testNonPhysicsStaffLoginSuccess(): void
    {
        // Correct username/password for non-physics staff
        $ret = (new SQL2Wrapper($this->info, $this->config))->callLogin('eve.evans@example.edu', 'password');
        asort($ret);
        $this->assertCount(6, $ret);
        $this->assertCount(1, $ret['role']);
        $this->assertEquals($ret, [
            'uid' => ['1'],
            'givenName' => ["Eve"],
            'lastName' => ["Evans"],
            'email' => ['eve.evans@example.edu'],
            'role' => ['lecturer'],
            'department' => ['Mathematics'],
        ]);
    }

    public function testPhysicsStaffLoginSuccess(): void
    {
        // Correct username/password for physics staff
        $ret = (new SQL2Wrapper($this->info, $this->config))->callLogin('mallory.mallory@example.edu', 'password');
        asort($ret);
        var_dump($ret);
        $this->assertCount(8, $ret);
        $this->assertCount(1, $ret['role']);
        $this->assertEquals($ret, [
            'uid' => ['2'],
            'givenName' => ["Mallory"],
            'lastName' => ["Mallory"],
            'email' => ['mallory.mallory@example.edu'],
            'role' => ['professor'],
            'department' => ['Physics'],
            'qualification' => ['PhD in Physics', 'MSc in Astrophysics'],
            'typically_wears_matching_socks' => ['false'],
        ]);
    }
}
