<?php

namespace Daou\Auth0JwtAuth\Auth;

use Cake\Auth\BaseAuthenticate;
use Cake\Http\ServerRequest;
use Cake\Http\Response;
use Cake\Controller\ComponentRegistry;
use Cake\Core\Configure;
use Cake\Http\Exception\UnauthorizedException;
use Auth0\SDK\JWTVerifier;
use Auth0\SDK\Exception\CoreException;

/**
 * An authentication adapter for authenticating using Auth0's PHP SDK and JSON Web Tokens.
 *
 * ```
 *  $this->Auth->config('authenticate', [
 *      'Daou/Auth0JwtAuth.Auth0' => [
 *          'userModel' => 'Users',
 *          'fields' => [
 *              'username' => 'auth0id'
 *          ],
 *      ]
 *  ]);
 * ```
 *
 * @license MIT
 *
 * @see https://auth0.com/docs/quickstart/webapp/php
 * @see http://jwt.io
 */

class Auth0Authenticate extends BaseAuthenticate
{
    /**
     * Parsed token.
     *
     * @var string|null
     */
    protected $_token;

    /**
     * Payload data.
     *
     * @var object|null
     */
    protected $_payload;

    /**
     * Exception.
     *
     * @var \Exception
     */
    protected $_error;

    /**
     * Constructor.
     *
     * Settings for this object.
     *
     * - `supported_algs` - List of supported verification algorithms.
     *   Defaults to ['RS256', 'HS256'].
     * - `fields` - Key `username` denotes the identifier field for fetching user
     *   record. The `sub` claim of JWT must contain identifier value.
     *   Defaults to ['username' => 'id'].
     * - `auth0ClientSecret` - Needs to be provided if HS256 is getting used
     * - `auth0Audience` - Required for both algorithms
     * - `auth0Domain` - Required for both algorithms
     *
     * @param \Cake\Controller\ComponentRegistry $registry The Component registry
     *   used on this request.
     * @param array $config Array of config to use.
     */
    public function __construct(ComponentRegistry $registry, $config)
    {
        $defaultConfig = [
            'supported_algs' => ['RS256', 'HS256'],
            'fields' => ['username' => 'id'],
            'auth0ClientSecret' => '',
            'auth0Audience' => '',
            'auth0Domain' => ''
        ];

        $this->setConfig($defaultConfig);

        parent::__construct($registry, $config);
    }

    /**
     * Get user record based on info available in JWT.
     *
     * @param \Cake\Http\ServerRequest $request The request object.
     * @param \Cake\Http\Response $response Response object.
     *
     * @return bool|array User record array or false on failure.
     */
    public function authenticate(ServerRequest $request, Response $response)
    {
        return $this->getUser($request);
    }

    /**
     * Get user record based on info available in JWT.
     *
     * @param \Cake\Http\ServerRequest $request Request object.
     *
     * @return bool|array User record array or false on failure.
     */
    public function getUser(ServerRequest $request)
    {
        $payload = $this->_getPayload($request);

        if (empty($payload) || !isset($payload->sub)) {
            return false;
        }

        $user = $this->_findUser($payload->sub);
        if (!$user) {
            return false;
        }

        unset($user[$this->_config['fields']['password']]);

        return $user;
    }

    /**
     * Get payload data.
     *
     * @param \Cake\Http\ServerRequest|null $request Request instance or null
     *
     * @return object|null Payload object on success, null on failure
     */
    protected function _getPayload($request = null)
    {
        if (is_null($request)) {
            return null;
        }

        $payload = null;

        $token = $this->_getToken($request);
        if ($token) {
            $payload = $this->_decode($token);
        }

        return $this->_payload = $payload;
    }

    /**
     * Get token from http header.
     *
     * @param \Cake\Http\ServerRequest|null $request Request object.
     *
     * @return string|null Token string if found else null.
     */
    public function _getToken($request = null)
    {

        if (is_null($request)) {
            return null;
        }

        $token = null;

        $header = $request->getHeaderLine('authorization');
        if ($header && stripos($header, 'bearer') === 0) {
            $token = str_ireplace('bearer ', '', $header);
        }

        return $this->_token = $token;
    }

    /**
     * Decode JWT token.
     *
     * @param string $token JWT token to decode.
     *
     * @return object|null The JWT's payload as a PHP object, null on failure.
     */
    protected function _decode($token)
    {
        $config = $this->_config;

        try {
            $verifier = new JWTVerifier([
                'supported_algs' => $config['supported_algs'],
                'valid_audiences' => [$config['auth0Audience']],
                'authorized_iss' => ['https://' . $config['auth0Domain'] . '/'],
                'client_secret' => $config['auth0ClientSecret']
            ]);

            $this->_token = $token;

            return $verifier->verifyAndDecode($token);

        }
        catch(\Auth0\SDK\Exception\CoreException $e) {
            if (Configure::read('debug')) {
                throw $e;
            }
            $this->_error = $e;
        }
    }

    /**
     * Handles an unauthenticated access attempt. Depending on value of config
     * `unauthenticatedException` either throws the specified exception or returns
     * null.
     *
     * @param \Cake\Http\ServerRequest $request A request object.
     * @param \Cake\Http\Response $response A response object.
     *
     * @throws \Cake\Http\Exception\UnauthorizedException Or any other
     *   configured exception.
     *
     * @return void
     */
    public function unauthenticated(ServerRequest $request, Response $response)
    {
        $message = $this->_error
            ? $this->_error->getMessage()
            : $this->_registry->get('Auth')->getConfig('authError');

        throw new UnauthorizedException($message);
    }
}
