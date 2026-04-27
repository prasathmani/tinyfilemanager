# TinyFileManager - Security Refactoring Project

> A comprehensive security-first refactoring of TinyFileManager from monolithic architecture (6600+ lines) to modular, testable components.

## 📊 Project Status

| Phase | Component | Status | Lines | Commit |
|-------|-----------|--------|-------|--------|
| 1 | Security Layer | ✅ Complete | 530+ | [52f09d2](https://github.com/slapiar/tinyfilemanager/commit/52f09d2) |
| 2 | Modularization | ✅ Complete | 810+ | [df2d1b8](https://github.com/slapiar/tinyfilemanager/commit/df2d1b8) |
| 3 | Router & Middleware | ✅ Complete | 760+ | [09b1e13](https://github.com/slapiar/tinyfilemanager/commit/09b1e13) |
| 4 | Security Tests | 📋 Planned | TBD | - |
| 5 | Deployment & CI/CD | 🔮 Pending | TBD | - |

**Total Code Added:** ~2,100 lines of production-ready, modular code

## 🎯 Quick Start

### Use the Existing File Manager
```bash
# The original tinyfilemanager.php still works as before
php -S localhost:8000
# Open http://localhost:8000
```

### Use the New Modular API
```php
<?php
require 'src/bootstrap.php';

// Create router with security
$router = new TFM_Router('/var/www/files', Bootstrap::getLogger());
$router->dispatch();
```

See [api.php.example](api.php.example) for complete example.

## 📚 Phase Documentation

### [Phase 1: Security Layer](PHASE1_README.md)
Comprehensive security foundation including:
- Magic bytes validation (15+ file types)
- MIME type verification with dangerous type blocking
- Rate limiting (5 attempts/15 min lockout)
- Audit logging (all operations tracked)
- Session security (IP + UA validation)
- Input validation (filenames, paths, usernames)

**Key Files:**
- `src/security.php` (530 lines) - All security functions
- Integrated into `tinyfilemanager.php` with fallback loading

### [Phase 2: Modularization](PHASE2_README.md)
Extracted functionality into reusable components:
- `src/bootstrap.php` (170 lines) - Initialization, autoloading, helpers
- `src/handlers/` (4 classes, 280 lines) - Delete, Rename, Upload handlers
- `src/services/FileManager.php` (260 lines) - Core CRUD operations

**Benefits:**
- Isolated responsibility for testing
- Easy to extend and maintain
- Clear separation of concerns

### [Phase 3: Router & Middleware](PHASE3_README.md)
Orchestration layer for secure request handling:
- `src/Router.php` (380 lines) - Central request dispatcher (11 actions)
- `src/middleware/AuthMiddleware.php` (220 lines) - Authentication + authorization
- `src/middleware/CSRFMiddleware.php` (160 lines) - CSRF token validation
- `api.php.example` (90 lines) - Complete API entry point example

**Capabilities:**
- RESTful JSON API with proper HTTP status codes
- Role-based access control (4 roles)
- Automatic CSRF protection
- Comprehensive error handling

### [Phase 4: Security Testing](PHASE4_PLAN.md) - 📋 In Planning
Complete test suite with 100+ test cases:
- Unit tests for all security functions
- Rate limiting verification
- Authentication & authorization tests
- CSRF validation tests
- Handler & service tests
- Integration & end-to-end tests
- Target: >90% code coverage

### Phase 5: Deployment & CI/CD - 🔮 Pending
- Docker optimization
- GitHub Actions CI/CD
- Performance benchmarking
- Security scanning tools
- Documentation site

## 🏗️ Architecture Overview

```
tinyfilemanager.php  ← Original (still works)
        ↓
    [Request]
        ↓
   api.php (new)
        ↓
[Middleware Stack]
   ├── CSRF Validation
   ├── Authentication
   └── Rate Limiting
        ↓
   [Router]
   (dispatches action)
        ↓
[Handlers/Services]
   ├── DeleteHandler
   ├── RenameHandler
   ├── UploadHandler
   └── FileManager Service
        ↓
[Security Layer]
   ├── Path validation
   ├── MIME checking
   ├── Magic bytes verification
   ├── Audit logging
   └── Input sanitization
        ↓
[Response] → JSON
```

## 🔒 Security Features

### 1. **Defense in Depth**
- Multi-layer validation (input → processing → output)
- Magic bytes inspection for file uploads
- MIME type verification with blacklist
- Path traversal prevention with realpath()

### 2. **Brute Force Protection**
- Rate limiting: 5 login attempts per 15 minutes
- Automatic lockout with exponential backoff
- Per-IP and per-username tracking

### 3. **Session Security**
- Secure. flags on cookies
- HttpOnly flag to prevent XSS access
- IP and User-Agent validation
- Configurable timeout (default 3600s)

### 4. **CSRF Protection**
- Token generation for all state-changing requests
- Hash_equals() for timing attack prevention
- Automatic token regeneration support
- Referer validation

### 5. **Audit Trail**
- JSON-based audit logging
- Timestamp, IP, user, action, details
- All file operations logged
- Immutable append-only log

### 6. **Authorization**
- Role-based access control (4 roles)
- Fine-grained permission groups (readonly, managers, admins)
- Per-action permission checking
- Hierarchical role permissions

## 📈 Metrics

### Code Organization
| Layer | Files | Lines | Tests |
|-------|-------|-------|-------|
| Security | 1 | 530 | Planned |
| Bootstrap | 1 | 170 | Planned |
| Handlers | 3 | 380 | Planned |
| Services | 1 | 260 | Planned |
| Router | 1 | 380 | Planned |
| Middleware | 2 | 380 | Planned |
| **Total** | **9** | **2,100** | **100+** |

### Performance (Estimated)
| Operation | Time | Notes |
|-----------|------|-------|
| Router dispatch | ~20ms | Initialization + routing |
| List directory | ~10-30ms | Depends on file count |
| Delete file | ~5ms | Including audit log |
| Upload file | ~50-200ms | Depends on file size |
| CSRF validation | <1ms | Hash comparison |
| Rate limit check | ~2ms | File read + parse |

## 🛠️ Development Workflow

### Setup
```bash
# Clone repository
git clone https://github.com/slapiar/tinyfilemanager.git
cd tinyfilemanager

# Create .env file
cp .env.example .env

# Set permissions
chmod 755 uploads/
chmod 644 tinyfilemanager.php
```

### Running Tests (Phase 4+)
```bash
# Install test dependencies
composer require --dev phpunit/phpunit

# Run all tests
./vendor/bin/phpunit tests/

# Run with coverage
./vendor/bin/phpunit --coverage-html=coverage tests/

# Run security tests only
./vendor/bin/phpunit --group=security tests/
```

### Using the API
```bash
# List files
curl 'http://localhost/api.php?action=list&p=documents'

# Upload file
curl -X POST -F 'file=@test.txt' \
  'http://localhost/api.php?action=upload&p=documents&token=<csrf_token>'

# Delete file
curl -X POST \
  -d 'token=<csrf_token>' \
  'http://localhost/api.php?action=delete&p=documents&file=test.txt'
```

## 🎓 Learning Path

1. **Start with Phase 1** → Understand security foundations
2. **Review Phase 2** → See how code is organized
3. **Study Phase 3** → Learn how everything connects
4. **Examine Tests** → See how components are validated
5. **Deploy** → Use in production with confidence

## 📖 Key Files to Review

**Security Foundation:**
- [src/security.php](src/security.php) - All validation functions

**Modular Components:**
- [src/bootstrap.php](src/bootstrap.php) - Initialization
- [src/handlers/UploadHandler.php](src/handlers/UploadHandler.php) - Upload security
- [src/services/FileManager.php](src/services/FileManager.php) - Core operations

**API Layer:**
- [src/Router.php](src/Router.php) - Request dispatcher
- [src/middleware/AuthMiddleware.php](src/middleware/AuthMiddleware.php) - Auth
- [src/middleware/CSRFMiddleware.php](src/middleware/CSRFMiddleware.php) - CSRF
- [api.php.example](api.php.example) - Integration example

## ⚙️ Configuration

### Basic Setup
```php
// In api.php
$config = [
    'root_path' => '/var/www/files',  // Required
    'auth' => [
        'enabled' => true,             // Enable authentication
        'users' => [                   // User credentials
            'admin' => password_hash('password', PASSWORD_BCRYPT),
        ],
        'readonly' => [],              // Users who can only view
        'managers' => ['admin'],       // Users who can delete
    ],
    'upload' => [
        'max_size' => 100 * 1024 * 1024,  // 100 MB
        'allowed_extensions' => ['jpg', 'png', 'pdf', 'zip'],
    ],
    'rate_limit' => [
        'enabled' => true,
        'attempts' => 5,
        'window' => 900,  // 15 minutes
    ],
];
```

## 🔍 Verification

### Check that security works
```bash
# These should be blocked:
curl 'http://localhost/api.php?action=delete&p=../../../etc&file=passwd'  # Path traversal
curl -X POST 'http://localhost/api.php?action=delete&p=files&file=test'    # No CSRF token
curl 'http://localhost/api.php?action=delete&p=files&file=test'             # Unauthorized
```

### Monitor audit logs
```bash
tail -f logs/audit.json
```

## 🤝 Contributing

To add to this project:

1. Create feature branch
2. Follow code style (PSR-12)
3. Add tests (Phase 4+)
4. Submit PR with description

## 📝 License

Same as original TinyFileManager - [MIT License](LICENSE)

## 🙏 Acknowledgments

- Based on [TinyFileManager](https://github.com/prasathmhn/tinyfilemanager) by Prasath
- Security enhancements inspired by OWASP Top 10
- Architecture patterns from domain-driven design

## 📞 Support

- **Issues:** [GitHub Issues](https://github.com/slapiar/tinyfilemanager/issues)
- **Discussions:** [GitHub Discussions](https://github.com/slapiar/tinyfilemanager/discussions)

---

**Last Updated:** Phase 3 Complete (Commit [09b1e13](https://github.com/slapiar/tinyfilemanager/commit/09b1e13))

**Next:** Phase 4 Security Testing
