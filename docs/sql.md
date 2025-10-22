# `sqlauth:SQL`

These are authentication modules for authenticating a user against and retrieving attributes from an SQL database.

The authentication can be done in one of two ways:

- Most commonly, as a part of the SQL query itself (ie. using SQL functions to hash a parameterized password and compare that to a value stored in the database).
- Less commonly, just store the hash in the database, retrieve that then compare that hash using PHP's `password_verify()` function to authenticate. This is useful in cases where there is minimal support in the database or to allow the same code to work against many databases without modification. The differences in how this is configured are in a section towards the bottom of this file.

There are two different configuration formats supported ("version 1" and "version 2"). Version 1 is simpler, but is more limited in functionality. Version 2 is more powerful and configurable, but a little more verbose. If you wish to authenticate or gather attributes from more than one SQL database, or need more than one SQL query for authentication then you definitely need Version 2.

The Version 1 configuration support comes in two flavours (but identical configurations):

- `sqlauth:SQL` uses the legacy Version 1 configuration format and code. Eventually the old code will be phased out, and `sqlauth:SQL` will become a synonym for `sqlauth:SQL1Compat`.
- `sqlauth:SQL1Compat` uses the legacy Version 1 configuration, but applies it to the Version 2 code.

If you are starting out we recommend the Version 2 (`sqlauth:SQL2`) configuration format.

You enable the module in `config/config.php`.

```php
    'module.enable' => [
        [...]
        'sqlauth' => true,
        [...]
    ],
```

## Basic Concepts

The basic concepts of how `sqlauth` works is common between versions 1 and 2.

`Authentication Query`
: An SQL query which takes the parameters `:username` and `:password`, which are evaluated by the query for authentication purposes. If the username/password is incorrect, the "authentication query" **must** return no rows. If the "authentication query" returns one or more rows, authentication is deemed to succeed (ie. the username/password were correct). The resulting rows returned represent SAML attributes to be returned. Version 1 supports only one authentication query, whereas Version 2 supports one or more.

`Attribute Query`
: Optional SQL queries executed after the authentication queries are executed. The resulting rows returned represent SAML attributes to be returned. If no rows are returned, this is not an error condition - it just doesn't add any extra SAML attributes to be returned.

- Authentication queries. If this returns zero rows, authentication fails. If it returns more than one row, authentication is deemed to succeed. the parameters `:username` and `:password` are available and should be evaluated by the query for authentication purposes. Each column returned becomes an attribute.The rows returned represent attributes to be returned.
- Zero or more Attribute queries. All columns returned become attributes. Duplicates are supressed. Arrays with multiple values come from multiple rows being returned.The rows returned represent attributes to be returned.

As a worked example, consider the following example table useful for authentication:

| uid | password | salt | givenName | email             |
|-----|----------|------|-----------|-------------------|
| bob | ******** | **** | Bob       | <bob@example.com> |

and another table (potentially in a completely separate database) which has attributes we want to return:

| uid | groupName |
|-----|-----------|
| bob | users     |
| bob | staff     |

An example authentication query might be:

```sql
select uid, givenName as \"givenName\", email from users where uid=:username and password=encode(sha512(concat((select salt from users where uid=1), :password)::bytea), 'base64')
```

And we could use an attribute query like:

```sql
select groupName from usergroups where uid=:username
```

Note: Depending upon configuration, attibute queries using the Version 2 configuration format may use `:username` or `:userid`. See the Version 2 section below for more details.

In summary:

- If the authentication query returns no rows, that indicates authentication failed.
- The authentication query is passed `:username` and `:password` query parameters to do authentication.
- If more than one query is desirable or required to get all of the attributes, you can use attribute queries to capture those. In this case, the result set of the attribute queries in that array provide attributes only - only the authentication query is used to determine if the username/password is correct or not, and as such `:password` is not passed to attribute queries.
- Because attribute queries have no role in authentication, these queries are allowed to return no rows, simply indicating that query should have no effect on the final returned attribute set.
- If any query returns multiple rows, they will be merged into the attributes.
- The column names are used for the attribute names. Some databases will lowercase all column names unless you specify a seemingly unneeded "as" clause (eg. `select givenName as \"givenName\"`). SAML is case sensitive in attribute names, so this matters.
- If multiple queries return the same column names, they will also be merged into the same attributes.
- Duplicate values and NULL values will be removed.

## Version 2 Configuration Format

The Version 2 configuration format supports:

- One or more database connections.
- One or more authentication queries using any database defined in the `databases` section.
- Zero or more attribute queries. Each query can use any database defined in the database section, and can be restricted to apply only to one or more authentication queries.

All configuration for this module is done in `authsources.php`. A trivial example with a single database, only a single authentication query and no extra attribute queries:

```php
$config = [
    [...]
    'example-sql' => [
        'sqlauth:SQL2',

        'databases' => [
            'idp' => [
                'dsn' => 'pgsql:host=postgresql;port=5432;dbname=simplesaml',
                'username' => 'simplesaml',
                'password' => 'secretpassword',
            ],
        ]

        'auth_queries' => [
            'auth_username' => [
                'database' => 'idp',
                'query' => "select uid, givenName as \"givenName\", email from users where uid=:username and password=encode(sha512(concat((select salt from users where uid=1), :password)::bytea), 'base64')",
            ],
        ],
    ],
    [...]
];
```

Assuming the correct `:username` and `:password` are passed, the resulting SAML attributes returned by this configuration would be:

| Attribute Name | Attribute Value     |
|----------------|---------------------|
| uid            | [ bob ]             |
| givenName      | [ Bob ]             |
| email          | [ bob@example.com ] |

It's really easy to add extra attributes by adding one or more attribute queries:

```php
$config = [
    [...]
    'example-sql' => [
        'sqlauth:SQL2',

        'databases' => [
            'idp' => [
                'dsn' => 'pgsql:host=postgresql;port=5432;dbname=simplesaml',
                'username' => 'simplesaml',
                'password' => 'secretpassword',
            ],
        ]

        'auth_queries' => [
            'auth_username' => [
                'database' => 'idp',
                'query' => "select uid, givenName as \"givenName\", email from users where uid=:username and password=encode(sha512(concat((select salt from users where uid=1), :password)::bytea), 'base64')"
            ],
        ],

        'attr_queries' => [
            [
                'database' => 'idp',
                'query' => "select groupName from usergroups where uid=:username",
            ],
        ],
    ],
    [...]
];
```

Assuming the correct `:username` and `:password` are passed, the resulting SAML attributes returned by this configuration would be:

| Attribute Name | Attribute Value     |
|----------------|---------------------|
| uid            | [ bob ]             |
| givenName      | [ Bob ]             |
| email          | [ bob@example.com ] |
| groupName      | [ users, staff ]    |

In the below example, we have users in two separate databases and two authentication queries. Authentication queries are run in the order they are configured, and once an authentication query successfully authenticates a user it is deemed to be authenticated using that query, and no further authentication queries are run. In the below case, the username formats are defined (single lower case word for staff, suppliers have a "supp_" prefix), and as a result we can use the optional `username_regex` parameter to get a slight performance boost out of not running unneccessary queries.

```php
$config = [
    [...]
    'example-sql' => [
        'sqlauth:SQL2',

        'databases' => [
            'staff' => [
                'dsn' => 'pgsql:host=postgresql;port=5432;dbname=staff',
                'username' => 'simplesaml',
                'password' => 'secretpassword',
            ],

            'suppliers' => [
                'dsn' => 'pgsql:host=postgresql;port=5432;dbname=suppliers',
                'username' => 'anotheruser',
                'password' => 'somepassword',
            ],
        ]

        'auth_queries' => [
            'auth_username' => [
                'database' => 'staff',
                'query' => "select uid, givenName as \"givenName\", email from users where uid=:username and password=encode(sha512(concat((select salt from users where uid=1), :password)::bytea), 'base64')"
                'username_regex' => '/^[a-z]+$/', // Username will only be acceptable if it is a single lower case word
            ],

            'auth_supplier' => [
                'database' => 'suppliers',
                'query' => "select supplierId as \"uid\", supplierName as \"givenName\", email from suppliers where supplierId=:username and password=encode(sha512(concat((select salt from users where uid=1), :password)::bytea), 'base64')"
                'username_regex' => '/^supp_[a-z]+$/', // Suppliers have a "supp_" prefix
            ]
        ],
    ],
    [...]
];
```

An example staff login with the above configuration might result in SAML attribues like:

| Attribute Name | Attribute Value       |
|----------------|-----------------------|
| uid            | [ brian ]             |
| givenName      | [ Brian ]             |
| email          | [ brian@example.com ] |

The next example shows a case where we have a single database we are authenticating against, but are aggregating attributes from a number of different databases. In such cases it is common that users might login with an email address, however the shared User ID between databases is some other ID. To support this, the `extract_userid` takes the value from this other ID field in the authentication query and makes it available as `:userid` in the attribute queries instead of `:username`.

```php
$config = [
    [...]
    'example-sql' => [
        "databases" => [
            "authdb" => [
                'dsn' => 'pgsql:host=postgresql;port=5432;dbname=authdb',
                'username' => 'someuser',
                'password' => 'somepassword',
            ],
            "staffdb" => [
                'dsn' => 'pgsql:host=postgresql;port=5432;dbname=staffdb',
                'username' => 'anotheruser',
                'password' => 'anotherpassword',
            ],
            "studentsdb" => [
                'dsn' => 'pgsql:host=postgresql;port=5432;dbname=studentsdb',
                'username' => 'differentuser',
                'password' => 'differentpassword',
            ],
        ],
        "auth_queries" => [
            "auth_query_email" => [
                "database" => "authdb",
                "query" =>
                    "select uid, givenName, email "
                    "from users where email=:username "
                    "and password=encode(sha512(concat((select salt from users where uid=1), :password)::bytea), 'base64')",
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
        ],
    ],
    [...]
];
```

A staff member authenticating might return SAML attributes like:

| Attribute Name | Attribute Value       |
|----------------|-----------------------|
| uid            | [ 10543 ]             |
| givenName      | [ Brian ]             |
| email          | [ brian@example.edu ] |
| department     | [ Physics ]           |
| role           | [ Lecturer ]          |

and a student might look like:

| Attribute Name | Attribute Value              |
|----------------|------------------------------|
| uid            | [ 20625 ]                    |
| givenName      | [ Jane ]                     |
| email          | [ jane@student.example.edu ] |
| course         | [ Mathematics ]              |
| year           | [ 2 ]                        |

When you've got more than one authentication query, it is possible to restrict attribute queries to only run for certain authentication queries using the `only_for_auth` attribute query configuration parameter:

```php
$this->config = [
    'example-sql' => [
        [...]
        "databases" => [
            "staffdb" => [
                'dsn' => 'pgsql:host=postgresql;port=5432;dbname=staffdb',
                'username' => 'anotheruser',
                'password' => 'anotherpassword',
            ],
            "studentsdb" => [
                'dsn' => 'pgsql:host=postgresql;port=5432;dbname=studentsdb',
                'username' => 'differentuser',
                'password' => 'differentpassword',
            ],
            "auth_queries" => [
                "auth_query_students" => [
                    "database" => "studentsdb",
                    "query" =>
                        "select studentid, givenName, lastName, email, course, year " .
                        "from students where email=:username "
                        "and password=encode(sha512(concat((select salt from users where uid=1), :password)::bytea), 'base64')",
                    "username_regex" => '/^[a-zA-Z0-9._%+-]+@student\.example\.edu$/',
                    "extract_userid_from" => 'studentid',
                ],
                "auth_query_staff" => [
                    "database" => "staffdb",
                    "query" =>
                        "select uid, givenName, lastName, email, department " .
                        "from staff where email=:username "
                        "and password=encode(sha512(concat((select salt from users where uid=1), :password)::bytea), 'base64')",
                    "username_regex" => '/^[a-zA-Z0-9._%+-]+@example\.edu$/',
                    "extract_userid_from" => 'uid',
                ],
            ],
            "attr_queries" => [
                [
                    'database' => 'staffdb',
                    'query' => "select role from staff_roles where uid=:userid",
                    'only_for_auth' => ['auth_query_staff' ],
                ],
                [
                    'database' => 'studentsdb',
                    'query' => "select unit_code from units_enrolled where studentid=:userid order by unit_code",
                    'only_for_auth' => ['auth_query_students'],
                ],
            ],
        ],
    ],
    [...]
];
```

A staff member authenticating might return SAML attributes like:

| Attribute Name | Attribute Value       |
|----------------|-----------------------|
| uid            | [ 10543 ]             |
| givenName      | [ Brian ]             |
| lastName       | [ Perkins ]           |
| email          | [ brian@example.edu ] |
| department     | [ Physics ]           |
| role           | [ Lecturer, Tutor]    |

and a student might look like:

| Attribute Name | Attribute Value              |
|----------------|------------------------------|
| studentid      | [ 20625 ]                    |
| givenName      | [ Jane ]                     |
| lastName       | [ Smith ]                    |
| email          | [ jane@student.example.edu ] |
| course         | [ Mathematics ]              |
| year           | [ 2 ]                        |
| unit_code      | [ MATH201, MATH202, MATH203] |

### Configuration Parameter Dictionary (Version 2)

There are three sections in the configuration, as follows:

```php
$this->config = [
    [...]
    'example-sql' => [
        "databases" => [
            // One or more databases
        ],
        "auth_queries" => [
            // One or more Authentication Queries
        ],
        "attr_queries" => [
            // Zero or more Attribute Queries
        ],
    ],
    [...]
];
```

#### databases

`dsn`
:   The DSN which should be used to connect to the database server.
    Check the various database drivers in the [PHP documentation](http://php.net/manual/en/pdo.drivers.php) for a description of the various DSN formats.

`username`
:   The username which should be used when connecting to the database server.

`password`
:   The password which should be used when connecting to the database server.

#### auth_queries

`database`
:   ID of the database in the `databases` configuration (previous section) that this authentication query should run on.

`query`
:   The SQL query which should be used to authenticate the user and retrieve attributes. This query is passed the `:username` and `:password` SQL parameters.

`username_regex`
:   (Optional) A regular expression that the username must match. Useful if the type of the username column in the database isn't a string (eg. an integer), or if the format is well known (eg. email address, single word with no spaces, etc) to avoid going to the database for a query that will never result in successful authentication.

`extract_userid_from`
:   (Optional) If the username from the authentication is not the ID used in the attribute queries. A common example is where they login with their email address (ie. `:username` is an email address), but their real user ID is in a different column. In that case, specify the column their real user ID is in.

`password_verify_hash_column`
:   (Optional) See the section at the bottom of this page covering Password Verify support.

#### attr_queries

`database`
:   ID of the database in the `databases` configuration (previous section) that this authentication query should run on.

`query`
:   The SQL query which should be used to gather attributes with. This query is passed either the `:username` or `:userid` parameters - if the `extract_userid_from` parameter was specified in the authentication query, the `:userid` SQL parameter will be passed to the query. Otherwise, `:username` is passed as an SQL parameter.

`only_for_auth`
:   (Optional) Only run the attribute query if the user authenticated using one of the authentication queries referenced in this list.

## Version 1 Configuration Format

The Version 1 format is more basic, both in terms of configuration and different use cases it supports. Specifically, it supports:

- One database only
- One authentication query
- Zero or more attribute queries

Taking this example schema:

```sql
    CREATE TABLE users (
      uid VARCHAR(30) NOT NULL PRIMARY KEY,
      password TEXT NOT NULL,
      salt TEXT NOT NULL,
      givenName TEXT NOT NULL,
      email TEXT NOT NULL,
      eduPersonPrincipalName TEXT NOT NULL
    );
    CREATE TABLE usergroups (
      uid VARCHAR(30) NOT NULL REFERENCES users (uid) ON DELETE CASCADE ON UPDATE CASCADE,
      groupname VARCHAR(30) NOT NULL,
      UNIQUE(uid, groupname)
    );
```

a basic entry with a single SQL string in `authsources.php` might look like this (PostgreSQL, SHA512 of salt + password, base64 encoded with the salt stored in an independent column):

```php
    'example-sql' => [
        'sqlauth:SQL',
        'dsn' => 'pgsql:host=postgresql;port=5432;dbname=simplesaml',
        'username' => 'simplesaml',
        'password' => 'secretpassword',
        'query' => "select uid, givenName as \"givenName\", email from users where uid=:username and password=encode(sha512(concat((select salt from users where uid=1),  :password)::bytea), 'base64')",
        'username_regex' => '/^[a-z]+$/', // Username will only be acceptable if it is a single lower case word
    ],
```

It's worth repeating at this point that if authentication is unsuccessful (ie. the username / password pair don't match), this query **must** return zero rows. Assuming the username / password pair provided was a match, the name of the columns in result set will be used as attribute names. In the above case, PostgreSQL lowercases the names by default, which we correct with the "as" clause. The result might look like this:

| Attribute Name | Attribute Value |
|----------------|-----------------|
| uid            | [ bobsmith ]    |
| givenName      | [ Bob ]         |
| email          | [ bob@example.com ] |

You'll likely need to collect attributes from more than just the table with the username and password hash. There are two supported ways to do this: table joins on your authentication query, or providing an array of queries for the `query` parameter instead of just the single query.

A basic example of the single query with join:

```php
    'example-sql' => [
        'sqlauth:SQL',
        'dsn' => 'pgsql:host=postgresql;port=5432;dbname=simplesaml',
        'username' => 'simplesaml',
        'password' => 'secretpassword',
        'query' => "select u.uid, u.givenName as \"givenName\", ug.groupname as \"groupName\" from users u left join usergroups ug on (u.uid=ug.uid) where u.uid=:username and u.password=encode(sha512(concat((select salt from users where uid=1),  :password)::bytea), 'base64')",
    ],
```

which can also be written as:

```php
    'example-sql' => [
        'sqlauth:SQL',
        'dsn' => 'pgsql:host=postgresql;port=5432;dbname=simplesaml',
        'username' => 'simplesaml',
        'password' => 'secretpassword',
        'query' => [
            "select uid, givenName as \"givenName\", email from users where uid=:username and password=encode(sha512(concat((select salt from users where uid=1),  :password)::bytea), 'base64')",
            "select groupName as \"groupName\" from usergroups where uid=:username",
        ],
        "select u.uid, u.givenName, ug.groupname from users u left join usergroups ug on (u.uid=ug.uid) where u.uid=:username and u.password=encode(sha512(concat((select salt from users where uid=1),  :password)::bytea), 'base64')",
    ],
```

both of which will return attributes like:

| Attribute Name | Attribute Value |
|----------------|-----------------|
| uid            | [ bobsmith ]    |
| givenName      | [ Bob ]         |
| email          | [ bob@example.com ] |
| groupName      | [ users, staff ]  |

For simple cases, the single query will suffice. As the number of tables you are joining to collate your attributes gets higher, then using the query list will make your configuration more maintainable.

In summary:

- If the single string query (or the first query if it's an array of queries) returns no rows, that indicates authentication failed.
- The single string query (or the first query if it's an array of queries) should use the passed `:username` and `:password` query parameters to do authentication.
- If more than one query is desirable or required to get all of the attributes, you can specify an array of queries. In this case, the result set of the second and subsequent queries in that array provide attributes only - only the first query is used to determine if the username/password is correct or not, and as such :password is only passed to the first query in the list.
- If `query` is an array of queries, because the second and subsequent queries have no role in authentication, these queries may return no rows, simply indicating that query should have no effect on the final returned attribute set.
- If any query returns multiple rows, they will be merged into the attributes.
- If multiple queries return the same column names, they will also be merged into the same attributes.
- Duplicate values and NULL values will be removed.

### Configuration Parameter Dictionary (Version 1)

`dsn`
:   The DSN which should be used to connect to the database server.
    Check the various database drivers in the [PHP documentation](http://php.net/manual/en/pdo.drivers.php) for a description of the various DSN formats.

`username`
:   The username which should be used when connecting to the database server.

`password`
:   The password which should be used when connecting to the database server.

`query`
:   Either a single string with an SQL statement, or an array of queries, run in order. That single string (or the first query in the array) is the "authentication query" - the parameters `:username` and `:password` are available and should be evaluated by the query for authentication purposes. If the username/password is incorrect, the "authentication query" should return no rows. The rows returned represent attributes to be returned.

`username_regex`
:   (Optional) A regular expression that the username must match. Useful if the type of the username column in the database isn't a string (eg. an integer), or if the format is well known (eg. email address, single word with no spaces, etc) to avoid going to the database for a query that will never result in successful authentication.

`passwordhashcolumn`
:    (Optional) Only When using the sqlauth:PasswordVerify module. This is the name of the column that contains the hashed password. The default is to look for a column 'passwordhash' in the database. See the section at the bottom of this page covering Password Verify support.

## Further Authentication Query Examples

```sql
Example query - SHA256 of salt + password, with the salt stored in an independent column, MySQL server:

    SELECT uid, givenName, email, eduPersonPrincipalName
    FROM users
    WHERE uid = :username
    AND PASSWORD = SHA2(
        CONCAT(
            (SELECT salt FROM users WHERE uid = :username),
            :password
        ),
        256
    )
```

Example query - SHA256 of salt + password, with the salt stored in an independent column. Multiple groups, MySQL server:

```sql
    SELECT users.uid, givenName, email, eduPersonPrincipalName, groupname AS groups
    FROM users LEFT JOIN usergroups ON users.uid = usergroups.username
    WHERE users.uid = :username
    AND PASSWORD = SHA2(
        CONCAT(
            (SELECT salt FROM users WHERE uid = :username),
            :password
        ),
        256
    )
```

Example query - SHA512 of salt + password, stored as salt (32 bytes) + sha256(salt + password) in password-field, PostgreSQL server:

```sql
    SELECT uid, givenName, email, eduPersonPrincipalName
    FROM users
    WHERE username = :username
    AND SUBSTRING(
        password FROM LENGTH(password) - 31
    ) = SHA2(
        CONCAT(
            SUBSTRING(password FROM 1 FOR LENGTH(password) - 32),
            :password
        ),
        512
    )
```

## Connecting with UNIX Domain Sockets (Local Sockets)

When on a UNIX-like platform (Linux, *BSD, etc), and when your SQL database server is running on the same host as the web server
hosting SimpleSAMLphp, it is possible to use UNIX domain sockets instead of TCP sockets for the database connection. This
configuration should result in marginally better performance and security (when configured correctly).

Here is an example Version 2 configuration using PostgreSQL:

```php
$config = [
    [...]
    'example-sql' => [
        'sqlauth:SQL2',

        'databases' => [
            'idp' => [
                'dsn' => 'pgsql:host=/var/run/postgresql;dbname=simplesaml',
                'username' => 'www-data',
                'password' => 'this-is-ignored',
            ],
        ]

        'auth_queries' => [
            'auth_username' => [
                'database' => 'idp',
                'query' => 'SELECT uid, givenName, email, eduPersonPrincipalName FROM users WHERE uid = :username ' .
                    'AND password = SHA2(CONCAT((SELECT salt FROM users WHERE uid = :username), :password), 256);',
            ],
        ],
    ],
    [...]
];
```

Configuration is largely the same as TCP sockets (documented above), with the differences being:

`dsn`
:   The key difference is that the `host` parameter. This needs to be the **directory** that contains the socket file used to connect to the PostgreSQL server. For example, actual socket file might be `/var/run/postgresql/.s.PGSQL.5432`, so `host=/var/run/postgresql` is the parameter that you need. If you're struggling to find where the socket is, the `unix_socket_directories` parameter in the server `postgresql.conf` is where that location is configured.

`username`
:   The UNIX username of the user running SimpleSAMLphp (ie. the web server user or the php-fpm user, depending on your setup).

`password`
:   Required, but the value you specify is ignored (so you can put any placeholder string value in there). All authentication for UNIX domain sockets are done by the operating system kernel.

## Security considerations

Please never store passwords in plaintext in a database. You should always hash your passwords with a secure one-way
function like the ones in the SHA2 family. Use randomly generated salts with a length at least equal to the hash of the
password itself. Salts should be per-password, that meaning every time a password changes, the salt must change, and
therefore salts must be stored in the database alongside the passwords they were used for. Application-wide salts can
be used (by just concatenating them to the input of the hash function), but should never replace per-password salts,
used instead as an additional security measure.

One way hashing algorithms like MD5 or SHA1 are considered insecure and should therefore be avoided.

## `password_verify()` support

A common one-way password hashing function is the [crypt](https://www.php.net/manual/en/function.crypt.php) function that `libc` on UNIX has provided natively for decades. PHP provides a useful [password_verify()](https://www.php.net/password_verify) function to authenticate a password against a previously stored `crypt` hash. Hashes can be created in PHP using the [password_hash()](https://www.php.net/password_hash) function.

In doing this, the authentication query no longer actually does the authentication - it returns the password hash. As a result, the authentication query is no longer passed the `:password` parameter.

Given the SQL schema:

```sql
    CREATE TABLE users (
      uid VARCHAR(30) NOT NULL PRIMARY KEY,
      passwordhash TEXT NOT NULL,
      givenName TEXT NOT NULL,
      email TEXT NOT NULL,
      eduPersonPrincipalName TEXT NOT NULL
    );
```

the Version 2 configuration parameter `password_verify_hash_column` specifies which column has the `crypt` hash:

```php
$config = [
    [...]
    'example-sql' => [
        'sqlauth:SQL2',

        'databases' => [
            'idp' => [
                'dsn' => 'pgsql:host=postgresql;port=5432;dbname=simplesaml',
                'username' => 'simplesaml',
                'password' => 'secretpassword',
            ],
        ]

        'auth_queries' => [
            'auth_username' => [
                'database' => 'idp',
                'query' => "select uid, email, passwordhash, eduPersonPrincipalName from users where uid = :username",
                'password_verify_hash_column' => 'passwordhash',
            ],
        ],
    ],
    [...]
];
```

The equivalent Version 1 configuration has slight differences, in that `PasswordVerify` was a separate module in Version 1 (whereas it is supported in them main `SQL2` Version 2 module), and the `passwordhashcolumn` parameter specifies the column that has the `crypt` hash:

```php
'smalldb-dbauth' => [
    'sqlauth:PasswordVerify',
    'dsn' => 'pgsql:host=...',
    'username' => 'dbuser',
    'password' => 'dbpassword',
    'passwordhashcolumn' =>  'passwordhash',
    'query' => 'select uid, email, passwordhash, eduPersonPrincipalName from users where uid = :username ',
],

```

In both cases, the authentication query must return the column referenced by the `password_verify_hash_column` (Version 2) or `passwordhashcolumn` (Version 1). `sqlauth` will then call [password_verify()](https://www.php.net/password_verify) with that hash and the user provided password to determine whether authentication is successful.

If the authentication is successful, all attributes returned by the authentication query are returned as SAML attributes (as per any other authentication query) **except the password hash column**. This is dropped and not exposed as a SAML attribute for security reasons.

Note: An inconsistency between Version 1 and Version 2 configurations is that the Version 1 had `passwordhashcolumn` being an optional element with a default value of `passwordhash`. With Version 2, [password_verify()](https://www.php.net/password_verify) support is enabled by specifying the optional `password_verify_hash_column` configuration parameter, hence it does not have a default value.
