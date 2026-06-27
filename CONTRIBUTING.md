# Contributing

Welcome and thanks for contributing to this project.  
First, please describe your needs in a new [issue](https://github.com/litesaml/saml/issues).

## How to write code

1. Respect [PSR-1](https://www.php-fig.org/psr/psr-1/) and [PSR-12](https://www.php-fig.org/psr/psr-12/)
2. Test your code
3. Keep changes small for easy review

## How to run tests and quality checks

```shell
docker run --rm -it -w /app -v $PWD:/app webdevops/php:8.4 composer install
docker run --rm -it -w /app -v $PWD:/app webdevops/php:8.4 composer test
docker run --rm -it -w /app -v $PWD:/app webdevops/php:8.4 composer phpcs
docker run --rm -it -w /app -v $PWD:/app webdevops/php:8.4 composer phpstan
```
