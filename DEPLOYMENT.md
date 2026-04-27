# Deployment Guide

This project now includes a complete Phase 5 delivery set: integration tests, performance benchmark, CI quality workflow, container smoke checks, and deployment runbooks.

## Deployment Targets

- Docker container on Linux host
- Linux VPS with PHP 8.0+
- Shared hosting with PHP 8.0+

## Local Validation

Run the full quality gate before deployment:

```bash
composer install
composer test:unit
composer test:integration
composer analyze
composer lint
php tests/performance/benchmark.php
docker build -t tinyfilemanager:test .
docker run -d --rm --name tinyfilemanager-test -p 8080:8080 tinyfilemanager:test
./tests/smoke-tests.sh http://127.0.0.1:8080
./tests/health-check.sh http://127.0.0.1:8080
docker stop tinyfilemanager-test
```

## Docker Deployment

```bash
docker build -t tinyfilemanager:latest .
docker compose up -d --build
./tests/health-check.sh http://127.0.0.1:8080
```

Notes:
- The container runs as a non-root user.
- The application listens on port 8080 inside the container.
- Persist data with a bind mount or named volume.

## Rollback

```bash
docker compose down
git checkout <last-known-good-tag>
docker compose up -d --build
./tests/health-check.sh http://127.0.0.1:8080
```

## Release Checklist

- Unit and integration suites pass
- Benchmark stays within targets
- Docker image builds successfully
- Smoke and health checks pass
- Configured credentials are not defaults
- Data backup completed before rollout