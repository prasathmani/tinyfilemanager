# Repository Structure

```
/ (root)
├── DEPLOYMENT.md
├── Dockerfile
├── KatalogMD.webp
├── LICENSE
├── PHASE2_README.md
├── PHASE3_README.md
├── PHASE4_COMPLETE.md
├── PHASE4_PLAN.md
├── PHASE4_PROGRESS.md
├── PHASE5_PLAN.md
├── PROJECT_STATUS.md
├── README.md
├── REFACTORING.md
├── RELEASE_VERSION
├── SECURITY.md
├── TEST_RESULTS.md
├── api.php.example
├── composer.json
├── config.php
├── docker-compose.yml
├── index.php
├── phpunit.xml.dist
├── release.sh
├── releases/
├── screenshot.gif
├── src/
│   ├── ArchiveHelpers.php
│   ├── BootstrapHelpers.php
│   ├── FM_Config.php
│   ├── PathHelpers.php
│   ├── Router.php
│   ├── RuntimeErrorHelpers.php
│   ├── TemplateHelpers.php
│   ├── TranslationHelpers.php
│   ├── assets/
│   │   ├── css/
│   │   │   ├── fm-grid.css
│   │   │   └── fm-navbar-fix.css
│   │   └── js/
│   │       ├── fm-ace.js
│   │       ├── fm-main.js
│   │       └── fm-upload.js
│   ├── bootstrap.php
│   ├── handlers/
│   │   ├── AjaxActionHandler.php
│   │   ├── ArchiveActionHandler.php
│   │   ├── CopyActionHandler.php
│   │   ├── DeleteHandler.php
│   │   ├── DownloadPreviewHandler.php
│   │   ├── FileActionHandler.php
│   │   ├── LegacyUploadHandler.php
│   │   ├── RenameHandler.php
│   │   └── UploadHandler.php
│   ├── middleware/
│   │   ├── AuthMiddleware.php
│   │   └── CSRFMiddleware.php
│   ├── renderers/
│   │   ├── file-editor.php
│   │   ├── file-viewer.php
│   │   └── main-page.php
│   ├── security.php
│   └── services/
│       ├── ChmodPageContextService.php
│       ├── DirectoryListingService.php
│       ├── FileEditorContextService.php
│       ├── FileManager.php
│       ├── FileViewContextService.php
│       └── FileViewInfoService.php
├── tests/
│   ├── TestHelpers.php
│   ├── bootstrap.php
│   ├── health-check.sh
│   ├── integration/
│   │   ├── ApiFlowTest.php
│   │   ├── EndToEndTest.php
│   │   └── RouterTest.php
│   ├── performance/
│   │   └── benchmark.php
│   ├── smoke-tests.sh
│   └── unit/
│       ├── AuthMiddlewareTest.php
│       ├── CSRFMiddlewareTest.php
│       ├── FileManagerTest.php
│       ├── HandlersTest.php
│       ├── RateLimiterTest.php
│       └── SecurityTest.php
├── tinyfilemanager.php
├── translation.json
└── uploads/
    ├── client1/
    ├── client2/
    ├── free/
    ├── supplier1/
    └── supplier2/
```
