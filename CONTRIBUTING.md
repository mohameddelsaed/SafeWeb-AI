# Contributing to SafeWeb AI

First off, thank you for considering contributing to SafeWeb AI! 🎉

## Code of Conduct

This project and everyone participating in it is governed by our Code of Conduct. By participating, you are expected to uphold this code.

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check existing issues to avoid duplicates. When creating a bug report, include:

- **Description**: Clear and concise description of the bug
- **Steps to reproduce**: Detailed steps to reproduce the behavior
- **Expected behavior**: What you expected to happen
- **Screenshots**: If applicable, add screenshots
- **Environment**: OS, browser, Node.js version, etc.

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, include:

- **Clear title**: Use a clear and descriptive title
- **Detailed description**: Provide a step-by-step description of the suggested enhancement
- **Use cases**: Explain why this enhancement would be useful
- **Mockups**: If applicable, include mockups or examples

### Pull Requests

1. **Fork the repo** and create your branch from `main`
2. **Install dependencies**: `npm install`
3. **Make your changes**: Follow the coding standards below
4. **Test your changes**: Ensure the project builds and runs
5. **Run linting**: `npm run lint:fix` and `npm run format`
6. **Commit your changes**: Use clear and descriptive commit messages
7. **Push to your fork** and submit a pull request

#### Pull Request Guidelines

- Keep PRs focused on a single feature or bug fix
- Update documentation as needed
- Add/update tests if applicable
- Follow the existing code style
- Ensure all CI checks pass

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/safeweb-ai.git
cd safeweb-ai

# Install dependencies
npm install

# Start dev server
npm run dev

# Run linting
npm run lint

# Format code
npm run format
```

## Coding Standards

### TypeScript

- Use TypeScript for all new code
- Define proper types/interfaces
- Avoid `any` types when possible
- Use explicit return types for functions

### React

- Use functional components with hooks
- Follow React naming conventions (PascalCase for components)
- Keep components small and focused
- Extract reusable logic into custom hooks

### Styling

- Use Tailwind CSS utility classes
- Follow the existing design system
- Use custom classes sparingly
- Ensure responsive design

### Code Quality

- No `console.log` statements in production code
- Remove commented-out code
- Keep functions small and focused
- Write self-documenting code with clear variable names
- Add comments for complex logic

### Commits

Use conventional commit messages:

```text
feat: add new feature
fix: fix bug
docs: update documentation
style: formatting changes
refactor: code refactoring
test: add tests
chore: maintenance tasks
```

## Project Structure

```text
src/
├── components/
│   ├── ui/              # Reusable UI components
│   ├── layout/          # Layout components
│   └── home/            # Home page specific components
├── pages/               # Page components
├── utils/               # Utility functions
├── types/               # TypeScript type definitions
└── assets/              # Static assets
```

## Testing

(Testing framework to be added in future updates)

## Questions?

Feel free to open an issue with the `question` label if you have any questions!

Thank you for contributing! 🚀
