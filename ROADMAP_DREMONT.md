# DREMONT File Manager – Development Roadmap

## Purpose
This roadmap defines the phased development plan for DREMONT File Manager after stabilization version 2.9.18. It is the primary planning reference for all future development prompts and is designed to prevent uncontrolled refactoring.

---

## Phases

### 1. Stabilized Foundation
- **2.9.14**: Clean release without standalone admin-users.php
- **2.9.15**: Shared page frame stabilization
- **2.9.16**: Navbar offset fallback
- **2.9.17**: Stray PHP close tag removal
- **2.9.18**: Basic editor CSRF save fix

### 2. Smoke Test and Practical Validation
- **2.9.19**: Smoke test and UI cleanup
  - login/logout
  - upload small/large file
  - download
  - delete
  - preview
  - basic editor
  - permissions
  - mobile test

### 3. Integrated User Administration
- **2.9.20**: Read-only user overview
- **2.9.21**: Add user
- **2.9.22**: Change password
- **2.9.23**: Change access type
- **2.9.24**: Assign directories
- **2.9.25**: Deactivate user

### 4. Mobile Optimization
- Larger controls
- Simplified actions
- Better upload flow
- Readable file names
- Responsive directory path
- Mobile card view for file list

### 5. PWA Lite
- manifest.webmanifest
- Mobile icons
- Standalone display
- start_url
- theme_color
- No offline caching of uploaded files
- Simple installation guide for Android/iPhone

### 6. Field Mode
- Quick upload from construction site
- Camera/photo upload
- Select project/folder
- Optional note
- Date-based naming helper

### 7. Client Access
- Client-specific folders
- Upload/download permissions
- Expiring share links
- Access logs

- Unified layout.php or equivalent
- Partial renderers
- Reusable components
- Cleaner JS structure
- Possible API/PWA frontend later

### Security hardening / Future improvements
- Move user credentials and metadata from config.php to protected server-side users storage.
- Keep config.php as legacy/fallback during migration.
- Never expose password hashes in UI or client-side code.

---

## Guiding Rules
- No standalone admin-users.php.
- No session refactor unless required by a proven bug.
- No layout.php production migration before the current runtime is stable.
- Each phase must produce a small working release.
- Each functional phase must update CHANGELOG.md and PROJECT_STATUS.md.
- PWA Lite must not cache uploaded files.
- Mobile usability is a primary requirement for managers in field and production.
- Prefer practical field usability over architectural elegance.
