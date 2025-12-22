<?php

declare(strict_types=1);

namespace SimpleSAML\Module\sqlauth\Auth\Source;

use Exception;
use PDO;
use PDOException;
use SimpleSAML\Error;
use SimpleSAML\Logger;
use SimpleSAML\Module\core\Auth\UserPassBase;

use function array_key_exists;
use function array_keys;
use function count;
use function explode;
use function implode;
use function in_array;
use function is_array;
use function is_null;
use function is_string;
use function password_verify;
use function preg_match;
use function preg_replace;
use function sprintf;
use function strlen;
use function strtolower;
use function var_export;

/**
 * An authentication source source that uses (potentially multiple) SQL databases.
 *
 * This class is an example authentication source which authenticates an user
 * against a SQL database.
 *
 * @package SimpleSAMLphp
 */

class SQL2 extends UserPassBase
{
    /**
     * List of one or more databases that are used by auth and attribute queries.
     * Each database must have a unique name, and the name is used to refer to
     * the database in auth and attribute queries.
     *
     * @var array
     */
    private array $databases = [];

    /**
     * List of one or more authentication queries. The first query that returns a result
     * is considered to have authenticated the user (and termed "winning").
     *
     * @var array
     */
    private array $authQueries = [];

    /**
     * List of zero or more attribute queries, which can optionally be limited to run only
     * for certain "winning" authentication queries.
     *
     * @var array
     */
    private array $attributesQueries = [];


    /**
     * Constructor for this authentication source.
     *
     * @param array $info  Information about this authentication source.
     * @param array $config  Configuration.
     */
    public function __construct(array $info, array $config)
    {
        // Call the parent constructor first, as required by the interface
        parent::__construct($info, $config);

        // Check databases configuration that all required parameters are present
        if (!array_key_exists('databases', $config)) {
            throw new Exception(sprintf(
                'Missing required attribute \'databases\' for authentication source \'%s\'',
                $this->authId,
            ));
        } else {
            if (!is_array($config['databases'])) {
                throw new Exception(sprintf(
                    'Required parameter \'databases\' for authentication source \'%s\''
                    . ' was provided and is expected to be an array. Instead it was: %s',
                    $this->authId,
                    var_export($config['databases'], true),
                ));
            }

            if (empty($config['databases'])) {
                throw new Exception(sprintf(
                    'Required parameter \'databases\' for authentication source \'%s\''
                    . ' was provided but is an empty array.',
                    $this->authId,
                ));
            }

            foreach ($config['databases'] as $dbname => $dbConfig) {
                if (!is_array($dbConfig)) {
                    throw new Exception(sprintf(
                        'Each entry in the %s \'databases\' parameter for authentication source \'%s\''
                        . ' is expected to be an array. Instead it was: %s',
                        $dbname,
                        $this->authId,
                        var_export($dbConfig, true),
                    ));
                }
                foreach (['dsn', 'username', 'password'] as $param) {
                    if (!array_key_exists($param, $dbConfig)) {
                        throw new Exception(sprintf(
                            'Database %s is missing required attribute \'%s\' for authentication source \'%s\'',
                            $dbname,
                            $param,
                            $this->authId,
                        ));
                    }
                    if (!is_string($dbConfig[$param])) {
                        throw new Exception(sprintf(
                            'Expected parameter \'%s\' for authentication source %s to be a string. '
                            . 'Instead it was: %s',
                            $dbname,
                            $this->authId,
                            var_export($config[$param], true),
                        ));
                    }
                }

                if (array_key_exists('options', $dbConfig) && !is_array($dbConfig['options'])) {
                    throw new Exception(sprintf(
                        'Optional parameter \'options\' for authentication source \'%s\''
                        . ' was provided and is expected to be an array. Instead it was: %s',
                        $this->authId,
                        var_export($dbConfig['options'], true),
                    ));
                }

                $this->databases[$dbname] = [
                    '_pdo' => null, // Will hold the PDO connection when connected
                    'dsn' => $dbConfig['dsn'],
                    'username' => $dbConfig['username'],
                    'password' => $dbConfig['password'],
                    'options' => $dbConfig['options'] ?? [],
                ];
            }
        }

        // Check auth_queries configuration that all required parameters are present
        if (!array_key_exists('auth_queries', $config)) {
            throw new Exception(sprintf(
                'Missing required attribute \'auth_queries\' for authentication source \'%s\'',
                $this->authId,
            ));
        } else {
            if (!is_array($config['auth_queries'])) {
                throw new Exception(sprintf(
                    'Required parameter \'auth_queries\' for authentication source \'%s\''
                    . ' was provided and is expected to be an array. Instead it was: %s',
                    $this->authId,
                    var_export($config['auth_queries'], true),
                ));
            }

            if (empty($config['auth_queries'])) {
                throw new Exception(sprintf(
                    'Required parameter \'auth_queries\' for authentication source \'%s\''
                    . ' was provided but is an empty array.',
                    $this->authId,
                ));
            }

            foreach ($config['auth_queries'] as $authQueryName => $authQueryConfig) {
                if (!is_array($authQueryConfig)) {
                    throw new Exception(sprintf(
                        'Each entry in the %s \'auth_queries\' parameter for authentication source '
                        . '\'%s\' is expected to be an array. Instead it was: %s' .
                        $authQueryName,
                        $this->authId,
                        var_export($authQueryConfig, true),
                    ));
                }

                foreach (['database', 'query'] as $param) {
                    if (!array_key_exists($param, $authQueryConfig)) {
                        throw new Exception(sprintf(
                            'Auth query %s is missing required attribute \'%s\' for authentication source \'%s\'',
                            $param,
                            $authQueryName,
                            $this->authId,
                        ));
                    }
                    if (!is_string($authQueryConfig[$param])) {
                        throw new Exception(sprintf(
                            'Expected parameter \'%s\' for authentication source \'%s\' to be a string.'
                            . ' Instead it was: %s',
                            $param,
                            $this->authId,
                            var_export($authQueryConfig[$param], true),
                        ));
                    }
                }

                if (!array_key_exists($authQueryConfig['database'], $this->databases)) {
                    throw new Exception(sprintf(
                        'Auth query %s references unknown database \'%s\' for authentication source \'%s\'',
                        $authQueryName,
                        $authQueryConfig['database'],
                        $this->authId,
                    ));
                }

                $this->authQueries[$authQueryName] = [
                    // Will be set to true for the query that successfully authenticated the user
                    '_winning_auth_query' => false,

                    // Will hold the value of the attribute named by 'extract_userid_from'
                    // if specified and authentication succeeds
                    '_extracted_userid' => null,

                    'database' => $authQueryConfig['database'],
                    'query' => $authQueryConfig['query'],
                ];

                if (array_key_exists('username_regex', $authQueryConfig)) {
                    if (!is_string($authQueryConfig['username_regex'])) {
                        throw new Exception(sprintf(
                            'Optional parameter \'username_regex\' for authentication source \'%s\''
                            . ' was provided and is expected to be a string. Instead it was: %s',
                            $this->authId,
                            var_export($authQueryConfig['username_regex'], true),
                        ));
                    }
                    $this->authQueries[$authQueryName]['username_regex'] = $authQueryConfig['username_regex'];
                }

                if (array_key_exists('extract_userid_from', $authQueryConfig)) {
                    if (!is_string($authQueryConfig['extract_userid_from'])) {
                        throw new Exception(sprintf(
                            'Optional parameter \'extract_userid_from\' for authentication source \'%s\''
                            . ' was provided and is expected to be a string. Instead it was: %s',
                            $this->authId,
                            var_export($authQueryConfig['extract_userid_from'], true),
                        ));
                    }
                    $this->authQueries[$authQueryName]['extract_userid_from'] = $authQueryConfig['extract_userid_from'];
                }

                if (array_key_exists('password_verify_hash_column', $authQueryConfig)) {
                    if (!is_string($authQueryConfig['password_verify_hash_column'])) {
                        throw new Exception(sprintf(
                            'Optional parameter \'password_verify_hash_column\' for authentication source \'%s\''
                            . ' was provided and is expected to be a string. Instead it was: %s',
                            $this->authId,
                            var_export($authQueryConfig['password_verify_hash_column'], true),
                        ));
                    }
                    $this->authQueries[$authQueryName]['password_verify_hash_column'] =
                        $authQueryConfig['password_verify_hash_column'];
                }
            }
        }

        // attr_queries is optional, but if specified, we need to check the parameters
        if (array_key_exists('attr_queries', $config)) {
            if (!is_array($config['attr_queries'])) {
                throw new Exception(sprintf(
                    'Optional parameter \'attr_queries\' for authentication source \'%s\''
                    . ' was provided and is expected to be an array. Instead it was: %s',
                    $this->authId,
                    var_export($config['attr_queries'], true),
                ));
            }

            foreach ($config['attr_queries'] as $attrQueryConfig) {
                if (!is_array($attrQueryConfig)) {
                    throw new Exception(sprintf(
                        '\'attr_queries\' parameter for authentication source \'%s\''
                        . ' is expected to be an array. Instead it was: %s' .
                        $this->authId,
                        var_export($attrQueryConfig, true),
                    ));
                }

                foreach (['database', 'query'] as $param) {
                    if (!array_key_exists($param, $attrQueryConfig)) {
                        throw new Exception(sprintf(
                            'Attribute query is missing required attribute \'%s\' for authentication source %s',
                            $param,
                            $this->authId,
                        ));
                    }

                    if (!is_string($attrQueryConfig[$param])) {
                        throw new Exception(sprintf(
                            'Expected parameter \'%s\' for authentication source \'%s\''
                            . ' to be a string. Instead it was: %s',
                            $param,
                            $this->authId,
                            var_export($attrQueryConfig[$param], true),
                        ));
                    }
                }

                $currentAttributeQuery = [
                    'database' => $attrQueryConfig['database'],
                    'query' => $attrQueryConfig['query'],
                ];

                if (!array_key_exists($attrQueryConfig['database'], $this->databases)) {
                    throw new Exception(sprintf(
                        'Attribute query references unknown database \'%s\' for authentication source \'%s\'',
                        $attrQueryConfig['database'],
                        $this->authId,
                    ));
                }

                if (array_key_exists('only_for_auth', $attrQueryConfig)) {
                    if (!is_array($attrQueryConfig['only_for_auth'])) {
                        throw new Exception(sprintf(
                            'Optional parameter \'only_for_auth\' for authentication source \'%s\''
                            . ' was provided and is expected to be an array. Instead it was: %s',
                            $this->authId,
                            var_export($attrQueryConfig['only_for_auth'], true),
                        ));
                    }
                    foreach ($attrQueryConfig['only_for_auth'] as $authQueryName) {
                        if (!is_string($authQueryName)) {
                            throw new Exception(sprintf(
                                'Each entry in the \'only_for_auth\' array for authentication source \'%s\''
                                . ' is expected to be a string. Instead it was: %s',
                                $this->authId,
                                var_export($authQueryName, true),
                            ));
                        }
                        if (!array_key_exists($authQueryName, $this->authQueries)) {
                            throw new Exception(sprintf(
                                'Attribute query references unknown auth query \'%s\' for authentication source %s',
                                $authQueryName,
                                $this->authId,
                            ));
                        }
                    }
                    $currentAttributeQuery['only_for_auth'] = $attrQueryConfig['only_for_auth'];
                }

                $this->attributesQueries[] = $currentAttributeQuery;
            }
        }
    }


    /**
     * Create a database connection.
     *
     * @return \PDO  The database connection.
     */
    protected function connect(string $dbname): PDO
    {
        if (!array_key_exists($dbname, $this->databases)) {
            throw new Exception(sprintf(
                "sqlauth:%s: Attempt to connect to unknown database '%s'",
                $this->authId,
                $dbname,
            ));
        }
        if ($this->databases[$dbname]['_pdo'] !== null) {
            // Already connected
            return $this->databases[$dbname]['_pdo'];
        }

        try {
            $db = new PDO(
                $this->databases[$dbname]['dsn'],
                $this->databases[$dbname]['username'],
                $this->databases[$dbname]['password'],
                $this->databases[$dbname]['options'],
            );
        } catch (PDOException $e) {
            // Obfuscate the password if it's part of the dsn
            throw new Exception(sprintf(
                "sqlauth:%s: - Failed to connect to '%s': %s",
                $this->authId,
                preg_replace('/(user|password)=(.*?([;]|$))/', '${1}=***', $this->databases[$dbname]['dsn']),
                $e->getMessage(),
            ));
        }

        $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $driver = explode(':', $this->databases[$dbname]['dsn'], 2);
        $driver = strtolower($driver[0]);

        // Driver specific initialization
        switch ($driver) {
            case 'mysql':
                // Use UTF-8
                $db->exec("SET NAMES 'utf8mb4'");
                break;
            case 'pgsql':
                // Use UTF-8
                $db->exec("SET NAMES 'UTF8'");
                break;
        }

        Logger::debug(sprintf('sqlauth:%s: Connected to database %s', $this->authId, $dbname));
        $this->databases[$dbname]['_pdo'] = $db;
        return $db;
    }


    /**
     * Extract SQL columns into SAML attribute array
     *
     * @param array $attributes output place to store extracted attributes
     * @param array  $data  Associative array from database in the format of PDO fetchAll
     * @param array  $forbiddenAttributes An array of attributes to never return
     * @return array &$attributes
     */
    protected function extractAttributes(array &$attributes, array $data, array $forbiddenAttributes = []): array
    {
        foreach ($data as $row) {
            foreach ($row as $name => $value) {
                if ($value === null) {
                    continue;
                }
                if (in_array($name, $forbiddenAttributes)) {
                    continue;
                }

                $value = (string) $value;

                if (!array_key_exists($name, $attributes)) {
                    $attributes[$name] = [];
                }

                if (in_array($value, $attributes[$name], true)) {
                    // Value already exists in attribute
                    continue;
                }

                $attributes[$name][] = $value;
            }
        }
        return $attributes;
    }


    /**
     * Execute the query with given parameters and return the tuples that result.
     *
     * @param string $query  SQL to execute
     * @param array $params parameters to the SQL query
     * @return array tuples that result
     */
    protected function executeQuery(PDO $db, string $query, array $params): array
    {
        try {
            $sth = $db->prepare($query);
        } catch (PDOException $e) {
            throw new Exception(sprintf(
                'sqlauth:%s: - Failed to prepare query: %s',
                $this->authId,
                $e->getMessage(),
            ));
        }

        try {
            $sth->execute($params);
        } catch (PDOException $e) {
            throw new Exception(sprintf(
                'sqlauth:%s: - Failed to execute query: %s',
                $this->authId,
                $e->getMessage(),
            ));
        }

        try {
            $data = $sth->fetchAll(PDO::FETCH_ASSOC);
            return $data;
        } catch (PDOException $e) {
            throw new Exception(sprintf(
                'sqlauth:%s: - Failed to fetch result set: %s',
                $this->authId,
                $e->getMessage(),
            ));
        } finally {
            unset($sth);
        }
    }


    /**
     * Authenticate using the optional password_verify() support against a hash retrieved from the database.
     *
     * @param string $queryname   Name of the auth query being processed
     * @param array $queryConfig  Configuration from authsources.php for this auth query
     * @param array $data         Result data from the database query
     * @param string $password    Password to verify with password_verify()
     * @return bool  True if password_verify() password verification succeeded, false otherwise
     */
    protected function authenticatePasswordVerifyHash(
        string $queryname,
        array $queryConfig,
        array $data,
        string $password,
    ): bool {
        // If password_verify_hash_column is not set, we are not using password_verify()
        if (!array_key_exists('password_verify_hash_column', $queryConfig)) {
            Logger::error(sprintf(
                'sqlauth:%s: authenticatePasswordVerifyHash() called but configuration for ' .
                '"password_verify_hash_column" not found in query config for query %s.',
                $this->authId,
                $queryname,
            ));
            throw new Error\Error('WRONGUSERPASS');
        } elseif (count($data) < 1) {
            // No rows returned, password_verify() cannot succeed
            return false;
        }

        /* This is where we need to run password_verify() if we are using password_verify() to
            * authenticate hashed passwords that are only stored in the database. */
        $hashColumn = $queryConfig['password_verify_hash_column'];
        if (!array_key_exists($hashColumn, $data[0])) {
            Logger::error(sprintf(
                'sqlauth:%s: Auth query %s did not return expected hash column \'' . $hashColumn . '\'',
                $this->authId,
                $queryname,
            ));
            throw new Error\Error('WRONGUSERPASS');
        }

        $passwordHash = null;
        foreach ($data as $row) {
            if ((!array_key_exists($hashColumn, $row)) || is_null($row[$hashColumn])) {
                Logger::error(sprintf(
                    'sqlauth:%s: column `%s` must be in every result tuple.',
                    $this->authId,
                    $hashColumn,
                ));
                throw new Error\Error('WRONGUSERPASS');
            }

            if (strlen($row[$hashColumn]) === 0) {
                Logger::error(sprintf(
                    'sqlauth:%s: column `%s` must contain a valid password hash.',
                    $this->authId,
                    $hashColumn,
                ));
                throw new Error\Error('WRONGUSERPASS');
            } elseif ($passwordHash === null) {
                $passwordHash = $row[$hashColumn];
            } elseif ($passwordHash != $row[$hashColumn]) {
                Logger::error(sprintf(
                    'sqlauth:%s: column %s must be THE SAME in every result tuple.',
                    $this->authId,
                    $hashColumn,
                ));
                throw new Error\Error('WRONGUSERPASS');
            }
        }

        if (($passwordHash == null) || (!password_verify($password, $passwordHash))) {
            Logger::error(sprintf(
                'sqlauth:%s: Auth query %s password verification failed',
                $this->authId,
                $queryname,
            ));
            /* Authentication with verify_password() failed, however that only means that
                * this auth query did not succeed. We should try the next auth query if any. */
            return false;
        }

        Logger::debug(sprintf(
            'sqlauth:%s: Auth query %s password verification using password_verify() succeeded',
            $this->authId,
            $queryname,
        ));
        return true;
    }


    /**
     * Attempt to log in using the given username and password.
     *
     * On a successful login, this function should return the users attributes. On failure,
     * it should throw an exception. If the error was caused by the user entering the wrong
     * username or password, a \SimpleSAML\Error\Error('WRONGUSERPASS') should be thrown.
     *
     * Note that both the username and the password are UTF-8 encoded.
     *
     * @param string $username  The username the user wrote.
     * @param string $password  The password the user wrote.
     * @return array  Associative array with the users attributes.
     */
    protected function login(
        string $username,
        #[\SensitiveParameter]
        string $password,
    ): array {

        $attributes = [];
        $winningAuthQuery = null;

        // Run authentication queries in order until one succeeds.
        foreach ($this->authQueries as $queryname => &$queryConfig) {
            // Check if the username matches the username_regex for this query
            if (
                array_key_exists('username_regex', $queryConfig) &&
                !preg_match($queryConfig['username_regex'], $username)
            ) {
                Logger::debug(sprintf(
                    'sqlauth:%s: Skipping auth query %s because username %s does not match username_regex %s',
                    $this->authId,
                    $queryname,
                    $username,
                    $queryConfig['username_regex'],
                ));
                continue;
            }

            Logger::debug('sqlauth:' . $this->authId . ': Trying auth query ' . $queryname);

            $db = $this->connect($queryConfig['database']);

            try {
                $sqlParams = ['username' => $username];
                if (!array_key_exists('password_verify_hash_column', $queryConfig)) {
                    // If we are not using password_verify(), pass the password to the query
                    $sqlParams['password'] = $password;
                }
                $data = $this->executeQuery($db, $queryConfig['query'], $sqlParams);
            } catch (PDOException $e) {
                Logger::error(sprintf(
                    'sqlauth:%s: Auth query %s failed with error: %s',
                    $this->authId,
                    $queryname,
                    $e->getMessage(),
                ));
                continue;
            }

            // If we got any rows, the authentication succeeded. If not, try the next query.
            if (
                (count($data) > 0) &&
                ((array_key_exists('password_verify_hash_column', $queryConfig) === false) ||
                    $this->authenticatePasswordVerifyHash($queryname, $queryConfig, $data, $password))
            ) {
                Logger::debug(sprintf(
                    'sqlauth:%s: Auth query %s succeeded with %d rows',
                    $this->authId,
                    $queryname,
                    count($data),
                ));
                $queryConfig['_winning_auth_query'] = true;

                if (array_key_exists('extract_userid_from', $queryConfig)) {
                    $queryConfig['_extracted_userid'] = $data[0][$queryConfig['extract_userid_from']];
                }
                $winningAuthQuery = $queryname;

                $forbiddenAttributes = [];
                if (array_key_exists('password_verify_hash_column', $queryConfig)) {
                    $forbiddenAttributes[] = $queryConfig['password_verify_hash_column'];
                }
                $this->extractAttributes($attributes, $data, $forbiddenAttributes);

                // The first auth query that succeeds is the winning one, so we can stop here.
                break;
            } else {
                Logger::debug(sprintf(
                    'sqlauth:%s: Auth query %s returned no rows, trying next auth query if any',
                    $this->authId,
                    $queryname,
                ));
            }
        }

        if (empty($attributes)) {
            // No auth query succeeded
            Logger::error(sprintf(
                'sqlauth:%s: No auth query succeeded. Probably wrong username/password.',
                $this->authId,
            ));
            throw new Error\Error('WRONGUSERPASS');
        }

        // Run attribute queries. Each attribute query can specify which auth queries it applies to.
        foreach ($this->attributesQueries as $attrQueryConfig) {
            // If the attribute query is limited to certain auth queries, check if the winning auth query
            // is one of those.
            Logger::debug(sprintf(
                'sqlauth:%s: Considering attribute query \'%s\' for winning auth query \'%s\''
                . ' with only_for_auth \'%s\'',
                $this->authId,
                $attrQueryConfig['query'],
                $winningAuthQuery,
                implode(',', $attrQueryConfig['only_for_auth'] ?? []),
            ));

            if (
                (!array_key_exists('only_for_auth', $attrQueryConfig)) ||
                in_array($winningAuthQuery, $attrQueryConfig['only_for_auth'], true)
            ) {
                Logger::debug(sprintf(
                    'sqlauth:%s: Running attribute query \'%s\' for winning auth query \'%s\'',
                    $this->authId,
                    $attrQueryConfig['query'],
                    $winningAuthQuery,
                ));

                $db = $this->connect($attrQueryConfig['database']);

                try {
                    $params = ($this->authQueries[$winningAuthQuery]['_extracted_userid'] !== null) ?
                        ['userid' => $this->authQueries[$winningAuthQuery]['_extracted_userid']] :
                        ['username' => $username];
                    $data = $this->executeQuery($db, $attrQueryConfig['query'], $params);
                } catch (PDOException $e) {
                    Logger::error(sprintf(
                        'sqlauth:%s: Attribute query \'%s\' failed with error: %s',
                        $this->authId,
                        $attrQueryConfig['query'],
                        $e->getMessage(),
                    ));
                    continue;
                }

                Logger::debug(sprintf(
                    'sqlauth:%s: Attribute query \'%s\' returned %d rows',
                    $this->authId,
                    $attrQueryConfig['query'],
                    count($data),
                ));

                $this->extractAttributes($attributes, $data, []);
            } else {
                Logger::debug(sprintf(
                    'sqlauth:%s: Skipping attribute query \'%s\' because it does not apply'
                    . ' to winning auth query \'%s\'',
                    $this->authId,
                    $attrQueryConfig['query'],
                    $winningAuthQuery,
                ));
            }
        }

        // At the end, disconnect from all databases
        unset($db);

        foreach ($this->databases as $dbname => $dbConfig) {
            if ($dbConfig['_pdo'] !== null) {
                $this->databases[$dbname]['_pdo'] = null;
                Logger::debug(sprintf(
                    'sqlauth:%s: Disconnected from database %s',
                    $this->authId,
                    $dbname,
                ));
            }
        }

        Logger::info(sprintf(
            'sqlauth:%s: Attributes: %s',
            $this->authId,
            implode(',', array_keys($attributes)),
        ));

        return $attributes;
    }
}
