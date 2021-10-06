Rate Limiter Component Fork (Compatible with Symfony <=4.4)
============================================================================

The Rate Limiter component provides a Token Bucket implementation to
rate limit input and output in your application.

This is a fork of the [original bundle](https://github.com/symfony/rate-limiter) that makes it
compatible with Symfony <= 4.4.

**This Component is experimental**.
[Experimental features](https://symfony.com/doc/current/contributing/code/experimental.html)
are not covered by Symfony's
[Backward Compatibility Promise](https://symfony.com/doc/current/contributing/code/bc.html).

Getting Started
---------------

```
$ composer require avaibook/symfony-rate-limiter
```

```php
use Symfony\Component\RateLimiter\Storage\InMemoryStorage;
use Symfony\Component\RateLimiter\RateLimiterFactory;

$factory = new RateLimiterFactory([
    'id' => 'login',
    'policy' => 'token_bucket',
    'limit' => 10,
    'rate' => ['interval' => '15 minutes'],
], new InMemoryStorage());

$limiter = $factory->create();

// blocks until 1 token is free to use for this process
$limiter->reserve(1)->wait();
// ... execute the code

// only claims 1 token if it's free at this moment (useful if you plan to skip this process)
if ($limiter->consume(1)->isAccepted()) {
   // ... execute the code
}
```

Resources
---------

 * [Contributing](https://symfony.com/doc/current/contributing/index.html)
 * [Report issues](https://github.com/symfony/symfony/issues) and
   [send Pull Requests](https://github.com/symfony/symfony/pulls)
   in the [main Symfony repository](https://github.com/symfony/symfony)
