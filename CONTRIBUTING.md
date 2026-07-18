# Contributing to Brick

Thank you for your interest in contributing to Brick!

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone <your-fork>`
3. Create a branch: `git checkout -b feature/your-feature`
4. Make changes
5. Push to your fork
6. Create a Pull Request

## Development Setup

```bash
cd brick

# Install backend dependencies
cd backend
go mod download

# Install frontend dependencies
cd ../frontend
npm install
```

## Code Style

### Go
- Follow Go conventions
- Run `go fmt ./...` before committing
- Run `go vet ./...` for linting

### JavaScript/React
- Use ES6+ features
- Use functional components and hooks
- Follow airbnb style guide

## Testing

All tests must pass before PR approval:

```bash
# Backend tests
cd backend
go test ./...

# Frontend tests
cd frontend
npm test
```

## Commit Messages

Use clear, descriptive commit messages:
```
git commit -m "feat: add user authentication"
git commit -m "fix: resolve CORS issues"
git commit -m "docs: update README"
```

## Pull Request Process

1. Update documentation
2. Add/update tests
3. Ensure all tests pass
4. Update CHANGELOG
5. Create PR with clear description

## Reporting Issues

Include:
- Description of issue
- Steps to reproduce
- Expected behavior
- Actual behavior
- Environment details

## License

By contributing, you agree your contributions are licensed under MIT License.

---

For more information, see README.md
