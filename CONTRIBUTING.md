# Contributing to OmniScan

## How to Contribute

1. **Fork** the repository
2. **Create a branch**: `git checkout -b feature/my-feature`
3. **Make your changes**
4. **Run tests**: `go test ./...`
5. **Run vet**: `go vet ./...`
6. **Commit** with a descriptive message
7. **Push** and open a Pull Request

## Development Setup

```bash
git clone https://github.com/Eliahhango/OmniScan.git
cd OmniScan
go build ./...
```

## Code Style

- Follow standard Go conventions (`gofmt`, `go vet`)
- Keep functions focused and small
- Write tests for new functionality
- Use existing patterns in the codebase

## Pull Request Guidelines

- One feature/fix per PR
- Update documentation if needed
- Ensure all CI checks pass
- Link related issues

## Reporting Issues

Use the issue templates for bug reports and feature requests.

## License

By contributing, you agree that your contributions will be licensed under the project's license.
