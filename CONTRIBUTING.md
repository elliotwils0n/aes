# Contributing

## Issues
Pick one of the provided templates for bug reports or feature requests.

## Pull Requests
Before making a pull request make sure the solution satisfies basic requirements for pull requests.
- Code compiles
    ```
    cargo check --all-targets --all-features
    ```
- Code is formatted
    ```
    cargo fmt --all
    ```
- All tests are passing
    ```
    cargo test --all-targets --all-features && cargo test --doc
    ```
