# Smoke Test Checklist – Version 2.9.19

## Authentication
- [ ] Login with valid credentials
- [ ] Logout and verify session ends
- [ ] Refresh after login (should remain logged in)

## File Operations
- [ ] Upload a small file (<1MB)
- [ ] Upload a large file (>10MB)
- [ ] Download a file
- [ ] Delete a file

## File Viewing & Editing
- [ ] Preview a file (text/image)
- [ ] Edit a file in basic text editor and save (should succeed)
- [ ] Open advanced editor (ACE) – verify known save issue is reported

## Permissions
- [ ] Verify user can only access their allowed directories
- [ ] Attempt forbidden operation (should be denied)

## Notes
- Advanced editor opens, but save is not reliable (see PROJECT_STATUS.md)
- Report any UI or functional anomalies
