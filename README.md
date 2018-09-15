# cakephp-auth0-jwt-auth
A CakePHP 3 plugin for authenticating using Auth0's PHP SDK

# CakePHP JWT Authenticate plugin
Plugin containing AuthComponent's authenticate class for authenticating using the
[Auth0 PHP SDK](https://github.com/auth0/auth0-PHP) and 
[JSON Web Tokens](http://jwt.io/).

## Installation

```sh
composer require daou/cakephp-auth0-jwt-auth
```

## Usage

In your app's `config/bootstrap.php` add:

```php
// In config/bootstrap.php
Plugin::load('Daou/Auth0JwtAuth');
```

or using cake's console:

```sh
./bin/cake plugin load Daou/Auth0JwtAuth
```

## Configuration:

Setup `AuthComponent`:

```php
    // In your controller, for e.g. src/Api/AppController.php
    public function initialize()
    {
        parent::initialize();

        $this->loadComponent('Auth', [
            'storage' => 'Memory',
            'authenticate' => [
                'Daou/Auth0JwtAuth.Auth0' => [
                    'userModel' => 'Users',
                    'fields' => [
                        'username' => 'auth0id'
                    ]
                ]
            ],

            'unauthorizedRedirect' => false,
            'loginAction' => false
        ]);
    }
```

## Working

The authentication class checks for the token in the `HTTP_AUTHORIZATION` environment variable:

It checks if token is passed using `Authorization` request header.
The value should be of form `Bearer <token>`.

### Known Issue

  Some servers don't populate `$_SERVER['HTTP_AUTHORIZATION']` when
  `Authorization` header is set. So it's up to you to ensure that either
  `$_SERVER['HTTP_AUTHORIZATION']` or `$_ENV['HTTP_AUTHORIZATION']` is set.

  For e.g. for apache you could use the following:

  ```
  RewriteEngine On
  RewriteCond %{HTTP:Authorization} ^(.*)
  RewriteRule .* - [e=HTTP_AUTHORIZATION:%1]
  ```

## Notes

Please see Admad's CakePHP JWT Authenticate plugin if you are interested in JWT without 
Auth0 [here](https://github.com/ADmad/cakephp-jwt-auth).

## License

MIT. See [LICENSE](LICENSE).