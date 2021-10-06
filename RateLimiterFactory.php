<?php

/*
 * This file is part of the Symfony package.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Symfony\Component\RateLimiter;

use \DateInterval;
use Symfony\Component\Lock\LockFactory;
use Symfony\Component\RateLimiter\Lock\NoLock;
use Symfony\Component\OptionsResolver\Options;
use Symfony\Component\OptionsResolver\OptionsResolver;
use Symfony\Component\RateLimiter\Policy\FixedWindowLimiter;
use Symfony\Component\RateLimiter\Policy\NoLimiter;
use Symfony\Component\RateLimiter\Policy\Rate;
use Symfony\Component\RateLimiter\Policy\SlidingWindowLimiter;
use Symfony\Component\RateLimiter\Policy\TokenBucketLimiter;
use Symfony\Component\RateLimiter\Storage\StorageInterface;

/**
 * @author Wouter de Jong <wouter@wouterj.nl>
 *
 * @experimental in 5.3
 */
final class RateLimiterFactory
{
    private $config;
    private $storage;
    private $lockFactory;

    public function __construct(array $config, StorageInterface $storage, LockFactory $lockFactory = null)
    {
        $this->storage = $storage;
        $this->lockFactory = $lockFactory;

        $options = new OptionsResolver();
        self::configureOptions($options);

        $this->config = $options->resolve($config);
    }

    public function create(string $key = null): LimiterInterface
    {
        $id = $this->config['id'].'-'.$key;
        $lock = $this->lockFactory ? $this->lockFactory->createLock($id) : new NoLock();

        switch ($this->config['policy']) {
            case 'token_bucket':
                return new TokenBucketLimiter($id, $this->config['limit'], $this->config['rate'], $this->storage, $lock);

            case 'fixed_window':
                return new FixedWindowLimiter($id, $this->config['limit'], $this->config['interval'], $this->storage, $lock);

            case 'sliding_window':
                return new SlidingWindowLimiter($id, $this->config['limit'], $this->config['interval'], $this->storage, $lock);

            case 'no_limit':
                return new NoLimiter();

            default:
                throw new \LogicException(sprintf('Limiter policy "%s" does not exists, it must be either "token_bucket", "sliding_window", "fixed_window" or "no_limit".', $this->config['policy']));
        }
    }

    protected static function configureOptions(OptionsResolver $options): void
    {
        $intervalNormalizer = static function (Options $options, string $interval): \DateInterval {
            try {
                return (new \DateTimeImmutable())->diff(new \DateTimeImmutable('+'.$interval));
            } catch (\Exception $e) {
                if (!preg_match('/Failed to parse time string \(\+([^)]+)\)/', $e->getMessage(), $m)) {
                    throw $e;
                }

                throw new \LogicException(sprintf('Cannot parse interval "%s", please use a valid unit as described on https://www.php.net/datetime.formats.relative.', $m[1]));
            }
        };

        $options
            ->setDefined(['id', 'policy', 'limit', 'interval', 'rate' ])
            ->setRequired(['id', 'policy'])
            ->setAllowedValues('policy', ['token_bucket', 'fixed_window', 'sliding_window', 'no_limit'])
            ->setAllowedTypes('limit', 'int')
            ->setAllowedTypes('interval', 'string')
            ->setDefault('rate', function (OptionsResolver $rate) use ($intervalNormalizer) {
                $rate
                    ->setDefined(['amount','interval'])
                    ->setDefault('amount', 1)
                    ->setAllowedTypes('amount', 'int')
                    ->setAllowedTypes('interval', 'string')
                    ->addNormalizer('interval', $intervalNormalizer)
                ;
            })
            ->addNormalizer('interval', $intervalNormalizer)
            ->addNormalizer('rate', function (Options $options, array $value): ?Rate {
                if (!isset($value['interval'])) {
                    return null;
                }

                return new Rate($value['interval'], $value['amount']);
            })
        ;

    }
}
