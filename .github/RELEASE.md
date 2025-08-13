# Automatic Release Workflow

## Overview
This repository uses semantic versioning with automatic releases triggered on every push to the `main` branch.

## Versioning Strategy

### Version Format: `MAJOR.MINOR.PATCH`

- **MAJOR**: Breaking changes (bumped when commit messages contain `BREAKING CHANGE:` or `feat!:`)
- **MINOR**: New features (bumped when commit messages start with `feat:` or `feature:`)
- **PATCH**: Bug fixes and other changes (default bump)

### Commit Message Examples

```bash
# Patch release (1.0.0 → 1.0.1)
git commit -m "fix: resolve authentication issue"
git commit -m "docs: update README"
git commit -m "chore: update dependencies"

# Minor release (1.0.0 → 1.1.0)
git commit -m "feat: add user profile management"
git commit -m "feature: implement email notifications"

# Major release (1.0.0 → 2.0.0)
git commit -m "feat!: redesign API endpoints"
git commit -m "BREAKING CHANGE: remove deprecated methods"
```

## Release Process

### Automatic Workflow
1. **Trigger**: Push to `main` branch
2. **Version Calculation**: Based on commit messages since last tag
3. **Build**: Run tests, generate reports, build JAR
4. **Release**: Create GitHub release with tag and artifacts
5. **Artifacts**: JAR files and test reports attached to release

### What Gets Released
- **Main JAR**: `base-springboot-api-kotlin-{version}.jar` (with dependencies)
- **Original JAR**: `base-springboot-api-kotlin-{version}-original.jar` (without dependencies)
- **Coverage Report**: `coverage-report-{version}.xml` (JaCoCo XML)
- **Release Notes**: Auto-generated from commit messages

### First Release
- The first release will be tagged as `v1.0.0`
- Subsequent releases follow semantic versioning rules

## Important Notes

### Repository State
- **pom.xml version**: Always remains as `0.0.1-SNAPSHOT` in the repository
- **Temporary versioning**: Version is updated only during the build process
- **No version commits**: Release versions are never committed back to the repository

### Excluded Changes
The following changes do NOT trigger releases:
- README.md updates
- Documentation changes in `/docs`
- GitHub Actions workflow changes in `/.github`

## Manual Release Override

If you need to manually create a release or override the automatic versioning:

```bash
# Create a tag manually (this will skip the automatic workflow)
git tag v1.2.3
git push origin v1.2.3

# Or use GitHub's release interface
```

## Troubleshooting

### Failed Release
- Check GitHub Actions logs for build failures
- Ensure all tests pass before pushing to main
- Verify commit message format for proper version bumping

### Missing Artifacts
- JAR files are built during the Maven `package` phase
- Coverage reports require successful test execution
- Check that the Maven build completes successfully

## Best Practices

1. **Use descriptive commit messages** following conventional commits
2. **Test thoroughly** before pushing to main
3. **Group related changes** in single commits when possible
4. **Use feature branches** for development, merge to main when ready for release
