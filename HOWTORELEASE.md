# Release Procedure

## General steps to cut a release from the main branch

These are the steps to make a release candidate for version `X.X.0`:

1. Make sure you are working on the current tip of the main branch.
2. Update version string in `Cargo.toml` from `version = "X.X.0-dev"` to `version = "X.X.0-rc1"`.
3. Update version hex number in the unit test of `src/versions.rs`.
4. Review the changelog file `CHANGELOG.md` and check if all important changes are described in there.
   - Create a new section `[X.X.0-rc1] - <YYYY-MM-DD>` and move all entries
     from the `[Unreleased]` section to the new section.
   - Make sure all github issues resolved in this release are referenced in the changelog.
   - Update the links at the bottom of the file:

```
[unreleased]: https://github.com/valkey-io/valkey-ldap/compare/X.X.0-rc1...HEAD
[X.X.0_rc1]: https://github.com/valkey-io/valkey-ldap/releases/tag/X.X.0-rc1
```

6. Run `cargo test --features enable-system-alloc` to check that versions match and to update `Cargo.lock` file.
7. Create a commit with title `Bump to X.X.0-rc1` containing the modifications made in the previous steps.
8. Create a branch with name `X.X` and switch to that branch.
8. Create an annotated tag for the above commit: `git tag -s -a X.X.0-rc1 -m"version X.X.0-rc1"`.
9. Push commit and tag to github repo: `git push <remote> X.X --tags`
   - This will trigger a GitHub action that triggers the RPMs build in Copr.
10. Switch back to the main branch.
11. Update version string in `Cargo.toml` from `version = "X.X.0-rc1"` to `version = "Y.Y.0-dev"` where `Y.Y.0 > X.X.0`.
12. Update version hex number in the unit test of `src/versions.rs`.
13. Create a commit with title `Begin of Y.Y.0 development` containing the modifications made in the previous two steps and push it to the remote main branch.
14. Review the GitHub release draft and publish the release when ready.


## Steps for releasing GA version

Assuming that version `X.X.0-rc1` has been cut of the main branch. To create the GA release follow the steps:

1. Make sure you are working on the current tip of the `X.X` branch.
2. Update version string in `Cargo.toml` from `version = "X.X.0-rc1"` to `version = "X.X.0"`.
3. Update version hex number in the unit test of `src/versions.rs`.
4. Review the changelog file `CHANGELOG.md` and check if all important changes are described in there.
   - Create a new section `[X.X.0] - <YYYY-MM-DD>` and move all entries
     from the `[Unreleased]` section to the new section.
   - Make sure all github issues resolved in this release are referenced in the changelog.
   - Update the links at the bottom of the file:

```
[unreleased]: https://github.com/valkey-io/valkey-ldap/compare/X.X.0...HEAD
[X.X.0]: https://github.com/valkey-io/valkey-ldap/releases/tag/X.X.0
[X.X.0_rc1]: https://github.com/valkey-io/valkey-ldap/releases/tag/X.X.0-rc1
```

5. Create a commit with title `Bump to X.X.0` containing the modifications made in the previous steps.
6. Create an annotated tag for the above commit: `git tag -s -a X.X.0 -m"version X.X.0"`.
7. Push commit and tag to github repo: `git push <remote> X.X --tags`
   - This will trigger a GitHub action that will create a draft release for version `X.X.0` and trigger the RPMs build in Copr.

## Steps for doing patch releases

Same has the steps for releasing the GA version by increasing the patch version number of the version string.
