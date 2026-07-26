# Contributing to server-deployment

Thank you for your interest in contributing! This project is dual-licensed under MIT OR AGPL-3.0, and we welcome contributions from the community.

## 📋 Contributor License Agreement (CLA)

**⚠️ Important: All contributors must sign our CLA before contributions can be accepted.**

### What You're Agreeing To

By contributing to this project, you agree that:

1. **Copyright Assignment**: You assign all right, title, and interest in your contributions to **Michal Koeckeis-Fresel**
2. **Dual Licensing Rights**: You grant Michal Koeckeis-Fresel the perpetual right to license your contributions under MIT License, AGPL 3.0, or any other license
3. **Representations**: You represent that you own the copyright in your contributions and have the legal authority to make this assignment
4. **Original Work**: Your contributions are your original creation or you have sufficient rights to contribute them

### How to Sign the CLA

**Automatic Process (Recommended):**
1. Submit your Pull Request
2. Our CLA Assistant bot will comment with a link
3. Click the link and sign in with GitHub
4. Your PR status will update automatically

**Manual Process:**
- Comment on your PR: `I have read the CLA Document and I hereby sign the CLA`

## 🚀 Getting Started

### Prerequisites

- Git installed on your system
- [List your specific requirements, e.g., Node.js, Python, etc.]
- GitHub account

### Development Setup

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/server-deployment.git
   cd server-deployment
   ```
3. **Add upstream remote**:
   ```bash
   git remote add upstream https://github.com/Michal-Koeckeis-Fresel/server-deployment.git
   ```
4. **Install dependencies**:
   ```bash
   # Add your specific installation commands
   npm install  # or pip install -r requirements.txt, etc.
   ```

## 🔄 Contribution Workflow

### 1. Create a Feature Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/issue-description
```

### 2. Make Your Changes

- Follow our [coding standards](#coding-standards)
- Write tests for new functionality
- Update documentation as needed
- Ensure all tests pass

### 3. Commit Your Changes

```bash
git add .
git commit -m "feat: add new feature X"
```

**Commit Message Format:**
- `feat:` new features
- `fix:` bug fixes
- `docs:` documentation changes
- `style:` formatting, missing semicolons, etc.
- `refactor:` code restructuring
- `test:` adding tests
- `chore:` maintenance tasks

### 4. Push and Create Pull Request

```bash
git push origin feature/your-feature-name
```

Then create a Pull Request on GitHub with:
- Clear description of changes
- Reference any related issues
- Screenshots/examples if applicable

## 📏 Coding Standards

### General Guidelines

- Write clear, self-documenting code
- Follow existing code style and patterns
- Add comments for complex logic
- Keep functions small and focused

### File Headers

All source files must include the dual-license header:

**For scripts (.sh, .bash):**
```bash
#!/bin/bash
#
# Copyright (c) 2025 Michal Koeckeis-Fresel
# 
# This software is dual-licensed under your choice of:
# - MIT License (see LICENSE-MIT)
# - GNU Affero General Public License v3.0 (see LICENSE-AGPL)
# 
# SPDX-License-Identifier: MIT OR AGPL-3.0-or-later
#
```

**For other languages:**
```javascript
/*
 * Copyright (c) 2025 Michal Koeckeis-Fresel
 * 
 * This software is dual-licensed under your choice of:
 * - MIT License (see LICENSE-MIT)
 * - GNU Affero General Public License v3.0 (see LICENSE-AGPL)
 * 
 * SPDX-License-Identifier: MIT OR AGPL-3.0-or-later
 */
```

### Code Quality

- [ ] All tests pass
- [ ] Code follows project style guidelines
- [ ] Documentation updated if needed
- [ ] No unnecessary dependencies added
- [ ] Security considerations addressed

## 🧪 Testing

```bash
# Run tests
npm test  # or your test command

# Run linting
npm run lint

# Run type checking (if applicable)
npm run type-check
```

## 📖 Documentation

- Update README.md if you change functionality
- Add inline comments for complex code
- Update API documentation if applicable
- Consider adding examples for new features

## 🐛 Reporting Issues

When reporting bugs, please include:

- **Description**: Clear description of the issue
- **Steps to Reproduce**: Detailed steps to recreate the problem
- **Expected Behavior**: What should happen
- **Actual Behavior**: What actually happens
- **Environment**: OS, version numbers, etc.
- **Screenshots**: If applicable

## 💡 Feature Requests

We welcome feature requests! Please:

- Check if the feature already exists
- Search existing issues to avoid duplicates
- Provide a clear use case
- Consider the scope and complexity
- Be open to discussion about implementation

## 📋 Pull Request Checklist

Before submitting your PR, ensure:

- [ ] CLA signed (automatic or manual)
- [ ] Code follows project standards
- [ ] All tests pass
- [ ] Documentation updated
- [ ] Commit messages are clear
- [ ] PR description explains the changes
- [ ] No merge conflicts

## 📞 Getting Help

- **Questions**: Open a [Discussion](../../discussions) or [Issue](../../issues)
- **CLA Issues**: See [CLA Information](/.github/ISSUE_TEMPLATE/cla.md)
- **Security Issues**: Email github-security@koeckeis-fresel.net

## 📄 Legal Information

### Dual Licensing

This project is dual-licensed under:
- **MIT License**: Permissive, allows commercial use
- **AGPL 3.0**: Strong copyleft with network provisions

Users may choose either license. All contributions become available under both licenses through copyright assignment.

### Copyright Assignment

All contributions are assigned to **Michal Koeckeis-Fresel** to:
- Maintain consistent licensing across the project
- Enable dual licensing for maximum flexibility
- Simplify license compliance and enforcement
- Allow for future licensing decisions

### Why Copyright Assignment?

This approach provides:
- **For Users**: Choice between permissive (MIT) and copyleft (AGPL) licensing
- **For Contributors**: Clear legal framework and continued ability to use their contributions
- **For Project**: Long-term sustainability and legal clarity

## 🙏 Recognition

All contributors will be recognized in:
- Git commit history
- [Contributors section](README.md#contributors) of README
- Release notes for significant contributions

---

**Thank you for contributing to make this project better!**

For questions about this contributing guide, please [open an issue](../../issues/new).