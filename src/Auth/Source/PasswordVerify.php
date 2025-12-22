<?php

declare(strict_types=1);

namespace SimpleSAML\Module\sqlauth\Auth\Source;

use SimpleSAML\Assert\Assert;
use SimpleSAML\Error;
use SimpleSAML\Logger;
use SimpleSAML\Module\sqlauth\Auth\Source\SQL;

use function array_key_exists;
use function array_keys;
use function count;
use function implode;
use function is_null;
use function password_verify;
use function sprintf;

/**
 * Simple SQL authentication source
 *
 * This class is very much like the SQL class. The major difference is that
 * instead of using SHA2 and other functions in the database we use the PHP
 * password_verify() function to allow for example PASSWORD_ARGON2ID to be used
 * for verification.
 *
 * While this class has a query parameter as the SQL class does the meaning
 * is different. The query for this class should return at least a column
 * called passwordhash containing the hashed password which was generated
 * for example using
 *    password_hash('hello', PASSWORD_ARGON2ID );
 *
 * Auth only passes if the PHP code below returns true.
 *   password_verify($password, row['passwordhash'] );
 *
 * Unlike the SQL class the username is the only parameter passed to the SQL query,
 * the query can not perform password checks, they are performed by the PHP code
 * in this class using password_verify().
 *
 * If there are other columns in the returned data they are assumed to be attributes
 * you would like to be returned through SAML.
 *
 * @package SimpleSAMLphp
 */

class PasswordVerify extends PasswordVerify1Compat {}
