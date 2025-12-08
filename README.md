> [!Warning]
> This repository/project is a university project. It neither has strict quality standards nor had comprehensive security auditing and will not be maintained. If you are interested in the project, it's free software under the AGPL-3.0 license.

# How to run?

```shell
cargo build --release
```

```shell
sudo RUST_LOG=info ./target/release/ids ./example_config.toml
# OR
run0 --setenv RUST_LOG=info ./target/release/ids ./example_config.toml
```
