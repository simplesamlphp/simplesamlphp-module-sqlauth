<?php

declare(strict_types=1);

namespace SimpleSAML\Module\sqlauth\Auth\Source;

use Exception;
use PDO;
use PDOException;
use SimpleSAML\Error;
use SimpleSAML\Logger;
use SimpleSAML\Module\core\Auth\UserPassBase;

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
        if (array_key_exists('databases', $config)) {
            if (!is_array($config['databases'])) {
                throw new Exception('Required parameter \'databases\' for authentication source ' .
                    $this->authId . ' was provided and is expected to be an array. Instead it was: ' .
                    var_export($config['databases'], true));
            }

            if (empty($config['databases'])) {
                throw new Exception('Required parameter \'databases\' for authentication source ' .
                    $this->authId . ' was provided but is an empty array.');
            }

            foreach ($config['databases'] as $dbname => $dbConfig) {
                if (!is_array($dbConfig)) {
                    throw new Exception('Each entry in the ' .
                        $dbname . ' \'databases\' parameter for authentication source ' .
                        $this->authId . ' is expected to be an array. Instead it was: ' .
                        var_export($dbConfig, true));
                }
                foreach (['dsn', 'username', 'password'] as $param) {
                    if (!array_key_exists($param, $dbConfig)) {
                        throw new Exception('Database ' .
                            $dbname . ' is missing required attribute \'' .
                            $param . '\' for authentication source ' .
                            $this->authId);
                    }
                    if (!is_string($dbConfig[$param])) {
                        throw new Exception('Expected parameter \'' . $param .
                            '\' for authentication source ' . $this->authId .
                            ' to be a string. Instead it was: ' .
                            var_export($config[$param], true));
                    }
                }

                if (array_key_exists('options', $dbConfig) && !is_array($dbConfig['options'])) {
                    throw new Exception('Optional parameter \'options\' for authentication source ' .
                        $this->authId . ' was provided and is expected to be an array. Instead it was: ' .
                        var_export($dbConfig['options'], true));
                }

                $this->databases[$dbname] = [
                    '_pdo' => null, // Will hold the PDO connection when connected
                    'dsn' => $dbConfig['dsn'],
                    'username' => $dbConfig['username'],
                    'password' => $dbConfig['password'],
                    'options' => $dbConfig['options'] ?? [],
                ];
            }
        } else {
            throw new Exception('Missing required attribute \'databases\' for authentication source ' . $this->authId);
        }

        // Check auth_queries configuration that all required parameters are present
        if (array_key_exists('auth_queries', $config)) {
            if (!is_array($config['auth_queries'])) {
                throw new Exception('Required parameter \'auth_queries\' for authentication source ' .
                    $this->authId . ' was provided and is expected to be an array. Instead it was: ' .
                    var_export($config['auth_queries'], true));
            }

            if (empty($config['auth_queries'])) {
                throw new Exception('Required parameter \'auth_queries\' for authentication source ' .
                    $this->authId . ' was provided but is an empty array.');
            }

            foreach ($config['auth_queries'] as $authQueryName => $authQueryConfig) {
                if (!is_array($authQueryConfig)) {
                    throw new Exception('Each entry in the ' .
                        $authQueryName . ' \'auth_queries\' parameter for authentication source ' .
                        $this->authId . ' is expected to be an array. Instead it was: ' .
                        var_export($authQueryConfig, true));
                }

                foreach (['database', 'query'] as $param) {
                    if (!array_key_exists($param, $authQueryConfig)) {
                        throw new Exception('Auth query ' .
                            $authQueryName . ' is missing required attribute \'' .
                            $param . '\' for authentication source ' .
                            $this->authId);
                    }
                    if (!is_string($authQueryConfig[$param])) {
                        throw new Exception('Expected parameter \'' . $param .
                            '\' for authentication source \'' . $this->authId . '\'' .
                            ' to be a string. Instead it was: ' .
                            var_export($authQueryConfig[$param], true));
                    }
                }

                if (!array_key_exists($authQueryConfig['database'], $this->databases)) {
                    throw new Exception('Auth query ' .
                        $authQueryName . ' references unknown database \'' .
                        $authQueryConfig['database'] . '\' for authentication source ' .
                        $this->authId);
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
                        throw new Exception('Optional parameter \'username_regex\' for authentication source ' .
                            $this->authId . ' was provided and is expected to be a string. Instead it was: ' .
                            var_export($authQueryConfig['username_regex'], true));
                    }
                    $this->authQueries[$authQueryName]['username_regex'] = $authQueryConfig['username_regex'];
                }

                if (array_key_exists('extract_userid_from', $authQueryConfig)) {
                    if (!is_string($authQueryConfig['extract_userid_from'])) {
                        throw new Exception('Optional parameter \'extract_userid_from\' for authentication source ' .
                            $this->authId . ' was provided and is expected to be a string. Instead it was: ' .
                            var_export($authQueryConfig['extract_userid_from'], true));
                    }
                    $this->authQueries[$authQueryName]['extract_userid_from'] = $authQueryConfig['extract_userid_from'];
                }

                if (array_key_exists('password_verify_hash_column', $authQueryConfig)) {
                    if (!is_string($authQueryConfig['password_verify_hash_column'])) {
                        throw new Exception(
                            'Optional parameter \'password_verify_hash_column\' for authentication source ' .
                            $this->authId . ' was provided and is expected to be a string. Instead it was: ' .
                            var_export($authQueryConfig['password_verify_hash_column'], true),
                        );
                    }
                    $this->authQueries[$authQueryName]['password_verify_hash_column'] =
                        $authQueryConfig['password_verify_hash_column'];
                }
            }
        } else {
            throw new Exception(
                'Missing required attribute \'auth_queries\' for authentication source ' .
                $this->authId,
            );
        }

        // attr_queries is optional, but if specified, we need to check the parameters
        if (array_key_exists('attr_queries', $config)) {
            if (!is_array($config['attr_queries'])) {
                throw new Exception('Optional parameter \'attr_queries\' for authentication source ' .
                    $this->authId . ' was provided and is expected to be an array. Instead it was: ' .
                    var_export($config['attr_queries'], true));
            }

            foreach ($config['attr_queries'] as $attrQueryConfig) {
                if (!is_array($attrQueryConfig)) {
                    throw new Exception('\'attr_queries\' parameter for authentication source ' .
                        $this->authId . ' is expected to be an array. Instead it was: ' .
                        var_export($attrQueryConfig, true));
                }

                foreach (['database', 'query'] as $param) {
                    if (!array_key_exists($param, $attrQueryConfig)) {
                        throw new Exception('Attribute query is missing required attribute \'' .
                            $param . '\' for authentication source ' .
                            $this->authId);
                    }
                    if (!is_string($attrQueryConfig[$param])) {
                        throw new Exception('Expected parameter \'' . $param .
                            '\' for authentication source \'' . $this->authId . '\'' .
                            ' to be a string. Instead it was: ' .
                            var_export($attrQueryConfig[$param], true));
                    }
                }

                $currentAttributeQuery = [
                    'database' => $attrQueryConfig['database'],
                    'query' => $attrQueryConfig['query'],
                ];

                if (!array_key_exists($attrQueryConfig['database'], $this->databases)) {
                    throw new Exception('Attribute query references unknown database \'' .
                        $attrQueryConfig['database'] . '\' for authentication source ' .
                        $this->authId);
                }

                if (array_key_exists('only_for_auth', $attrQueryConfig)) {
                    if (!is_array($attrQueryConfig['only_for_auth'])) {
                        throw new Exception('Optional parameter \'only_for_auth\' for authentication source ' .
                            $this->authId . ' was provided and is expected to be an array. Instead it was: ' .
                            var_export($attrQueryConfig['only_for_auth'], true));
                    }
                    foreach ($attrQueryConfig['only_for_auth'] as $authQueryName) {
                        if (!is_string($authQueryName)) {
                            throw new Exception('Each entry in the \'only_for_auth\' array for authentication source ' .
                                $this->authId . ' is expected to be a string. Instead it was: ' .
                                var_export($authQueryName, true));
                        }
                        if (!array_key_exists($authQueryName, $this->authQueries)) {
                            throw new Exception('Attribute query references unknown auth query \'' .
                                $authQueryName . '\' for authentication source ' .
                                $this->authId);
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
            throw new Exception('sqlauth:' . $this->authId . ': Attempt to connect to unknown database \'' .
                $dbname . '\'');
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
            $obfuscated_dsn =
                preg_replace('/(user|password)=(.*?([;]|$))/', '${1}=***', $this->databases[$dbname]['dsn']);

            throw new Exception('sqlauth:' . $this->authId . ': - Failed to connect to \'' .
                $obfuscated_dsn . '\': ' . $e->getMessage());
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

        Logger::debug('sqlauth:' . $this->authId . ': Connected to database ' . $dbname);
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
            throw new Exception('sqlauth:' . $this->authId .
                                ': - Failed to prepare query: ' . $e->getMessage());
        }

        try {
            $sth->execute($params);
        } catch (PDOException $e) {
            throw new Exception('sqlauth:' . $this->authId .
                                ': - Failed to execute query: ' . $e->getMessage());
        }

        try {
            $data = $sth->fetchAll(PDO::FETCH_ASSOC);
            return $data;
        } catch (PDOException $e) {
            throw new Exception('sqlauth:' . $this->authId .
                                ': - Failed to fetch result set: ' . $e->getMessage());
        }
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
        $winning_auth_query = null;

        // Run authentication queries in order until one succeeds.
        foreach ($this->authQueries as $queryname => &$queryConfig) {
            // Check if the username matches the username_regex for this query
            if (
                array_key_exists('username_regex', $queryConfig) &&
                !preg_match($queryConfig['username_regex'], $username)
            ) {
                Logger::debug('sqlauth:' . $this->authId . ': Skipping auth query ' . $queryname .
                             ' because username ' . $username . ' does not match username_regex ' .
                             $queryConfig['username_regex']);
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
                Logger::error('sqlauth:' . $this->authId . ': Auth query ' . $queryname .
                              ' failed with error: ' . $e->getMessage());
                continue;
            }

            // If we got any rows, the authentication succeeded. If not, try the next query.
            if (count($data) > 0) {
                /* This is where we need to run password_verify() if we are using password_verify() to
                 * authenticate hashed passwords that are only stored in the database. */
                if (array_key_exists('password_verify_hash_column', $queryConfig)) {
                    $hashColumn = $queryConfig['password_verify_hash_column'];
                    if (!array_key_exists($hashColumn, $data[0])) {
                        Logger::error('sqlauth:' . $this->authId . ': Auth query ' . $queryname .
                                     ' did not return expected hash column \'' . $hashColumn . '\'');
                        throw new Error\Error('WRONGUSERPASS');
                    }

                    $validPasswordHashFound = false;
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
                        if (($passwordHash === null) && (strlen($row[$hashColumn]) > 0)) {
                            $passwordHash = $row[$hashColumn];
                            $validPasswordHashFound = true;
                        } elseif ($passwordHash != $row[$hashColumn]) {
                            Logger::error(sprintf(
                                'sqlauth:%s: column %s must be THE SAME in every result tuple.',
                                $this->authId,
                                $hashColumn,
                            ));
                            throw new Error\Error('WRONGUSERPASS');
                        } elseif (strlen($row[$hashColumn]) === 0) {
                            Logger::error(sprintf(
                                'sqlauth:%s: column `%s` must contain a valid password hash.',
                                $this->authId,
                                $hashColumn,
                            ));
                            throw new Error\Error('WRONGUSERPASS');
                        }
                    }

                    if ((!$validPasswordHashFound) || (!password_verify($password, $passwordHash))) {
                        Logger::error('sqlauth:' . $this->authId . ': Auth query ' . $queryname .
                                     ' password verification failed');
                        /* Authentication with verify_password() failed, however that only means that
                         * this auth query did not succeed. We should try the next auth query if any. */
                        continue;
                    }

                    Logger::debug('sqlauth:' . $this->authId . ': Auth query ' . $queryname .
                                 ' password verification using password_verify() succeeded');
                }

                Logger::debug('sqlauth:' . $this->authId . ': Auth query ' . $queryname .
                             ' succeeded with ' . count($data) . ' rows');
                $queryConfig['_winning_auth_query'] = true;

                if (array_key_exists('extract_userid_from', $queryConfig)) {
                    $queryConfig['_extracted_userid'] = $data[0][$queryConfig['extract_userid_from']];
                }
                $winning_auth_query = $queryname;

                $forbiddenAttributes = [];
                if (array_key_exists('password_verify_hash_column', $queryConfig)) {
                    $forbiddenAttributes[] = $queryConfig['password_verify_hash_column'];
                }
                $this->extractAttributes($attributes, $data, $forbiddenAttributes);

                // The first auth query that succeeds is the winning one, so we can stop here.
                break;
            } else {
                Logger::debug('sqlauth:' . $this->authId . ': Auth query ' . $queryname .
                             ' returned no rows, trying next auth query if any');
            }
        }

        if (empty($attributes)) {
            // No auth query succeeded
            Logger::error('sqlauth:' . $this->authId . ': No auth query succeeded. Probably wrong username/password.');
            throw new Error\Error('WRONGUSERPASS');
        }

        // Run attribute queries. Each attribute query can specify which auth queries it applies to.
        foreach ($this->attributesQueries as $attrQueryConfig) {
            // If the attribute query is limited to certain auth queries, check if the winning auth query
            // is one of those.
            Logger::debug(
                'sqlauth:' . $this->authId . ': ' .
                'Considering attribute query ' . $attrQueryConfig['query'] .
                ' for winning auth query ' . $winning_auth_query .
                ' with only_for_auth ' . implode(',', $attrQueryConfig['only_for_auth'] ?? []),
            );

            if (
                (!array_key_exists('only_for_auth', $attrQueryConfig)) ||
                in_array($winning_auth_query, $attrQueryConfig['only_for_auth'], true)
            ) {
                Logger::debug('sqlauth:' . $this->authId . ': Running attribute query ' . $attrQueryConfig['query'] .
                             ' for winning auth query ' . $winning_auth_query);

                $db = $this->connect($attrQueryConfig['database']);

                try {
                    $params = ($this->authQueries[$winning_auth_query]['_extracted_userid'] !== null) ?
                        ['userid' => $this->authQueries[$winning_auth_query]['_extracted_userid']] :
                        ['username' => $username];
                    $data = $this->executeQuery($db, $attrQueryConfig['query'], $params);
                } catch (PDOException $e) {
                    Logger::error('sqlauth:' . $this->authId . ': Attribute query ' . $attrQueryConfig['query'] .
                                  ' failed with error: ' . $e->getMessage());
                    continue;
                }

                Logger::debug('sqlauth:' . $this->authId . ': Attribute query ' . $attrQueryConfig['query'] .
                             ' returned ' . count($data) . ' rows');

                $this->extractAttributes($attributes, $data, []);
            } else {
                Logger::debug('sqlauth:' . $this->authId . ': Skipping attribute query ' . $attrQueryConfig['query'] .
                             ' because it does not apply to winning auth query ' . $winning_auth_query);
            }
        }

        // At the end, disconnect from all databases
        foreach ($this->databases as $dbname => $dbConfig) {
            if ($dbConfig['_pdo'] !== null) {
                $this->databases[$dbname]['_pdo'] = null;
                Logger::debug('sqlauth:' . $this->authId . ': Disconnected from database ' . $dbname);
            }
        }

        Logger::info('sqlauth:' . $this->authId . ': Attributes: ' . implode(',', array_keys($attributes)));

        return $attributes;
    }
}
