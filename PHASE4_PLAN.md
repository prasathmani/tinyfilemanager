# Phase 4: Comprehensive Security Testing

## 📌 Objectives

Implement unit and integration tests to validate all security mechanisms built in Phases 1-3.

## 🧪 Test Categories

### 1. **Unit Tests for Security Functions** (`tests/unit/SecurityTest.php`)
- [ ] Magic bytes validation
  - [ ] Valid file types (jpg, png, pdf, zip, etc.)
  - [ ] Spoofed files (php as jpg)
  - [ ] Corrupted headers
  - [ ] Edge cases (empty files)
  
- [ ] MIME type validation
  - [ ] Valid MIME types
  - [ ] Dangerous types (application/x-php)
  - [ ] Null bytes injection
  
- [ ] Path traversal prevention
  - [ ] Directory traversal attempts (`../../../etc/passwd`)
  - [ ] URL encoding bypasses (`..%2F..%2F`)
  - [ ] Double encoding (`..%252F`)
  - [ ] Symlink attacks
  
- [ ] Input validation
  - [ ] Filename validation (special chars, length)
  - [ ] Username validation
  - [ ] Path validation (realpath checks)

### 2. **Rate Limiting Tests** (`tests/unit/RateLimiterTest.php`)
- [ ] First login attempt succeeds
- [ ] 5th attempt succeeds
- [ ] 6th attempt blocked (lockout)
- [ ] Lockout duration (15 minutes)
- [ ] Different IPs bypass limit
- [ ] Cleanup of old entries

### 3. **Authentication Tests** (`tests/unit/AuthMiddlewareTest.php`)
- [ ] Valid password passes
- [ ] Invalid password fails
- [ ] Correct role assigned
- [ ] Permission check works per role
- [ ] Session timeout enforced
- [ ] IP/UA validation works

### 4. **CSRF Tests** (`tests/unit/CSRFMiddlewareTest.php`)
- [ ] Token generation works
- [ ] Token verification succeeds
- [ ] Invalid token rejected
- [ ] Timing attack prevention
- [ ] Token regeneration works
- [ ] Referer validation works

### 5. **Handler Tests** (`tests/unit/HandlersTest.php`)
- [ ] DeleteHandler.php
  - [ ] Delete file succeeds
  - [ ] Delete directory succeeds
  - [ ] Delete non-existent fails
  - [ ] Batch delete works
  - [ ] Audit log created
  
- [ ] RenameHandler.php
  - [ ] Rename succeeds
  - [ ] Extension protection works
  - [ ] Duplicate detection works
  - [ ] Path validation works
  
- [ ] UploadHandler.php
  - [ ] Valid upload succeeds
  - [ ] Magic bytes check works
  - [ ] MIME validation works
  - [ ] Size limit enforced
  - [ ] Duplicate handling works
  - [ ] Dangerous extensions blocked

### 6. **Service Tests** (`tests/unit/FileManagerTest.php`)
- [ ] List directory works
- [ ] Get file info works
- [ ] Read file works
- [ ] Write file works
- [ ] Create directory works
- [ ] All methods validate paths

### 7. **Router Tests** (`tests/integration/RouterTest.php`)
- [ ] List action works
- [ ] Delete action works
- [ ] Upload action works
- [ ] Invalid action returns 400
- [ ] Unauthorized access returns 401
- [ ] CSRF failure returns 403

### 8. **Integration Tests** (`tests/integration/ApiFlowTest.php`)
- [ ] Complete upload flow
- [ ] Complete delete flow
- [ ] Authentication flow
- [ ] Permission hierarchy enforced
- [ ] Audit logging works end-to-end

## 📁 Test Structure

```
tests/
├── bootstrap.php                    (Test configuration)
├── fixtures/
│   ├── valid_image.jpg
│   ├── spoofed.php.jpg
│   ├── malicious.zip
│   └── large_file.bin
├── unit/
│   ├── SecurityTest.php
│   ├── RateLimiterTest.php
│   ├── AuthMiddlewareTest.php
│   ├── CSRFMiddlewareTest.php
│   ├── HandlersTest.php
│   └── FileManagerTest.php
└── integration/
    ├── RouterTest.php
    ├── ApiFlowTest.php
    └── EndToEndTest.php
```

## 🔨 Testing Tools

- **PHPUnit 10**: Main testing framework
- **Faker**: Generate test data
- **Mockery**: Mock dependencies
- **PHP-CPD**: Code duplication detection

## 📦 Setup Instructions

```bash
# Install test dependencies
composer require --dev phpunit/phpunit ~10.0 \
  fakerphp/faker \
  mockery/mockery

# Run all tests
vendor/bin/phpunit tests/

# Run specific test file
vendor/bin/phpunit tests/unit/SecurityTest.php

# Run with coverage
vendor/bin/phpunit --coverage-html coverage/ tests/

# Run only security tests
vendor/bin/phpunit --group=security tests/
```

## 📊 Test Coverage Goals

| Component | Current | Target |
|-----------|---------|--------|
| security.php | 0% | 95%+ |
| bootstrap.php | 0% | 90%+ |
| handlers/ | 0% | 90%+ |
| services/ | 0% | 90%+ |
| Router.php | 0% | 85%+ |
| middleware/ | 0% | 90%+ |
| **Overall** | **0%** | **90%+** |

## 🎯 Test Execution Plan

### Week 1: Unit Tests
- [ ] Create test bootstrap + fixtures
- [ ] Security functions tests
- [ ] Rate limiter tests
- [ ] Input validation tests

### Week 2: Authentication & CSRF
- [ ] Auth middleware tests
- [ ] CSRF middleware tests
- [ ] Permission hierarchy tests

### Week 3: Handlers & Services
- [ ] Handler tests (all 3)
- [ ] FileManager service tests
- [ ] Path validation tests

### Week 4: Integration
- [ ] Router tests
- [ ] API flow tests
- [ ] End-to-end tests
- [ ] Coverage analysis & fixes

## ⚠️ Security Test Scenarios

### Attack Simulations

1. **Directory Traversal**
   ```php
   // Should be blocked
   $path = '../../../etc/passwd';
   $result = fm_validate_filepath($path);
   $this->assertFalse($result);
   ```

2. **File Type Spoofing**
   ```php
   // Rename .php to .jpg - should block
   // Create fake jpg with php header - should detect as php
   ```

3. **Brute Force Attack**
   ```php
   // 6 rapid login attempts - 6th should fail
   ```

4. **CSRF Attack**
   ```php
   // POST without token - should fail
   // POST with wrong token - should fail
   ```

5. **SQL Injection (Path)**
   ```php
   // Filename with quotes, semicolons - should sanitize
   ```

6. **Null Byte Injection**
   ```php
   // Upload as "shell.php%00.jpg" - should block
   ```

## 📈 Success Criteria

- ✅ All unit tests pass (100%)
- ✅ All integration tests pass (100%)
- ✅ Code coverage > 90%
- ✅ No security vulnerabilities found
- ✅ All edge cases handled
- ✅ Performance acceptable (< 50ms per test)

## 🚀 Phase 4 Deliverables

1. Complete test suite with 100+ test cases
2. Test documentation and examples
3. Coverage report (>90%)
4. Security audit document
5. Performance baseline
6. CI/CD integration (GitHub Actions)

## 📝 Testing Checklist

Before moving to Phase 5 (Deployment):
- [ ] All unit tests pass
- [ ] All integration tests pass
- [ ] Coverage > 90%
- [ ] Security audit passed
- [ ] Performance meets requirements
- [ ] Documentation complete
- [ ] CI/CD pipeline working

---

**Status:** 📋 Planning Phase 4
**Estimated Duration:** 1 week
**Next Phase:** Phase 5 (Deployment & CI/CD)
