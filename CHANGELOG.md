# Changelog

All notable changes to SafeWeb AI will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-03-03

### Added

- Admin Contacts page for managing contact form submissions
- Admin Applications page for managing job applications
- Careers URL routing and job application migration
- Reveal.js graduation presentation (35 slides with dark cybersecurity theme)
- Presentation Figma prompt document
- Password strength meter component

### Fixed

- Chatbot: resolved camelCase/snake_case serializer mismatch causing repeated responses
- Chatbot: added response variation and conversation history awareness
- Export report: renamed DRF reserved `format` parameter to `export_format` (PDF/CSV/JSON now working)
- Rescan: fixed page reload for proper re-scan execution
- Export: proper blob handling for CSV and PDF downloads

### Changed

- Updated .gitignore to exclude Python __pycache__, .sqlite3, .venv, and screenshots
- Removed tracked __pycache__ and db.sqlite3 from repository
- Added Quick Admin Links section to Admin Dashboard
- Card component now supports onClick prop

## [1.0.0] - 2026-02-14

### Added

- ESLint configuration with React, TypeScript, and React Hooks rules
- Prettier code formatter with consistent styling rules
- GitHub Actions CI workflow for automated testing and building
- EditorConfig for consistent editor settings across team
- robots.txt file for SEO optimization
- Accessibility improvements: Input, Select, and Textarea components now generate IDs and bind labels with htmlFor
- New npm scripts: `lint:fix`, `format`, and `format:check`
- TypeScript ignoreDeprecations flag to suppress baseUrl warning
- CI badge in README.md

### Fixed

- Removed console.log statements from Login.tsx and Register.tsx
- Fixed Input, Select, and Textarea components to properly link labels with form controls for accessibility
- Fixed markdown linting errors in README.md (missing language tags, blank lines around headings)

### Changed

- Updated package.json with eslint-plugin-react and prettier dependencies
- Enhanced README.md with proper code block language tags and formatting

## [0.1.0] - Initial Release

### Added

- React 18 + TypeScript + Vite project setup
- Tailwind CSS with custom design system
- React Router v6 with 20+ routes
- Comprehensive UI component library (Button, Input, Select, Textarea, Card, Badge)
- Admin dashboard with user, scan, and settings management
- Authentication pages (Login, Register)
- Vulnerability scanning features
- Educational resources and documentation
- Vercel deployment configuration
