# GitHub Workflows

This directory contains GitHub Actions workflows for the YaugerAIO PowerShell module.

## Workflows Overview

### 1. CI (`ci.yml`)

**Triggers:** Pull requests and pushes to `main` and `dev` branches
**Purpose:** Continuous Integration with code quality checks, testing, and validation

**Jobs:**

- **Code Quality:** Runs PSScriptAnalyzer, validates module manifest, tests module import
- **Test:** Runs Pester tests with code coverage analysis
- **Build Validation:** Tests module build process and creates artifacts

### 2. Publish (`publish.yml`)

**Triggers:**

- Pushes to `main` branch
- Tag pushes (e.g., `v1.2.3`)
- Manual workflow dispatch
  **Purpose:** Publishes the module to PowerShell Gallery

**Features:**

- Runs tests before publishing
- Supports manual version specification
- Creates GitHub releases for tags
- Validates module before publishing

### 3. Version Bump (`version-bump.yml`)

**Triggers:**

- Manual workflow dispatch
- Pushes to `main` branch (auto-detects bump type)
  **Purpose:** Semantic version bumping with automated release management

**Bump Types:**

- **Major:** Breaking changes (e.g., 1.2.3 → 2.0.0)
- **Minor:** New features (e.g., 1.2.3 → 1.3.0)
- **Patch:** Bug fixes (e.g., 1.2.3 → 1.2.4)

### 4. Documentation (`docs.yml`)

**Triggers:** Changes to function files or module files
**Purpose:** Validates and generates documentation

**Features:**

- Validates function documentation
- Checks markdown files for broken links
- Generates function documentation
- Updates README automatically

## Usage Guide

### Manual Version Bump

1. Go to Actions → Semantic Version Bump
2. Click "Run workflow"
3. Select bump type (major/minor/patch)
4. Choose whether to create a tag
5. Choose whether to push changes directly or create a PR

### Publishing a New Version

1. **Option 1:** Create a git tag

   ```bash
   git tag v1.2.3
   git push origin v1.2.3
   ```

2. **Option 2:** Manual workflow dispatch
   - Go to Actions → Publish to PowerShell Gallery
   - Click "Run workflow"
   - Optionally specify a version

### Commit Message Conventions

For automatic version bump detection, use these commit message patterns:

- `[major]` or `[breaking]` or `BREAKING CHANGE` → Major version bump
- `[minor]` or `[feature]` or `feat:` → Minor version bump
- Default → Patch version bump

## Required Secrets

### PSG_TOKEN

Your PowerShell Gallery API key for publishing modules.

**To get your API key:**

1. Go to https://www.powershellgallery.com/account
2. Navigate to API Keys
3. Create a new API key
4. Add it to your repository secrets as `PSG_TOKEN`

## Workflow Dependencies

The workflows are designed to work together:

- **CI** runs on every PR and push
- **Version Bump** can trigger **Publish** (when tags are created)
- **Documentation** runs when function files change
- **Publish** only runs after successful CI

## Troubleshooting

### Common Issues

1. **Tests Fail**

   - Check the test output in the Actions tab
   - Ensure all functions have proper documentation
   - Verify Pester tests are up to date

2. **Publish Fails**

   - Verify PSG_TOKEN secret is set correctly
   - Check that module version is higher than current gallery version
   - Ensure all required manifest fields are present

3. **Version Bump Issues**
   - Check that the current version format is valid (e.g., 1.2.3)
   - Verify git permissions for the workflow
   - Check commit message format for auto-detection

### Debugging

All workflows include detailed logging. Check the Actions tab for:

- Step-by-step execution logs
- Error messages and stack traces
- Test results and coverage reports
- Module validation output

## Customization

### Adding New Workflows

1. Create a new `.yml` file in `.github/workflows/`
2. Follow the existing patterns for consistency
3. Update this README with documentation

### Modifying Existing Workflows

- Test changes in a branch first
- Update documentation accordingly
- Consider backward compatibility

### Environment-Specific Settings

- Use repository secrets for sensitive data
- Use environment variables for configuration
- Consider different settings for different branches

## Best Practices

1. **Always run CI before publishing**
2. **Use semantic versioning consistently**
3. **Keep documentation up to date**
4. **Test workflows in branches before merging**
5. **Monitor workflow performance and optimize as needed**
