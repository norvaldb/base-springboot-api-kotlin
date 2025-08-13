# GitHub Actions Badge Configuration

Add these badges to your README.md:

## Build Status
```markdown
![CI Pipeline](https://github.com/norvaldb/base-springboot-api-kotlin/workflows/CI%20Pipeline%20with%20Testing%20and%20Reporting/badge.svg)
```

## Test Reports  
```markdown
![Test Reports](https://github.com/norvaldb/base-springboot-api-kotlin/workflows/Test%20Reports%20Only/badge.svg)
```

## Coverage Badge (using Codecov)
```markdown
[![codecov](https://codecov.io/gh/norvaldb/base-springboot-api-kotlin/branch/main/graph/badge.svg)](https://codecov.io/gh/norvaldb/base-springboot-api-kotlin)
```

## Accessing Reports

### JaCoCo Coverage Reports
- **Artifacts**: Download from Actions → Workflow Run → Artifacts section
- **PR Comments**: Automatic coverage report comments on pull requests
- **Codecov**: Visit https://codecov.io/gh/norvaldb/base-springboot-api-kotlin

### Allure Test Reports  
- **Artifacts**: Download from Actions → Workflow Run → Artifacts section
- **GitHub Pages**: Available at https://norvaldb.github.io/base-springboot-api-kotlin (if Pages enabled)

### Setting up GitHub Pages (Optional)
1. Go to repository Settings → Pages
2. Source: Deploy from a branch
3. Branch: gh-pages
4. Folder: / (root)

## Workflow Features

### CI Pipeline (ci.yml)
- ✅ Runs on push/PR to main/develop
- ✅ JaCoCo coverage with PR comments
- ✅ Allure reports with history
- ✅ GitHub Pages deployment
- ✅ Codecov integration
- ✅ OWASP dependency scanning
- ✅ Artifact uploads with retention

### Test Reports Only (test-reports.yml)  
- ✅ Lightweight testing workflow
- ✅ JaCoCo coverage for PRs
- ✅ Allure report generation
- ✅ Test result summaries
- ✅ Artifact uploads
