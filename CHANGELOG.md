# Changelog

All notable changes to this project will be documented in this file.

## [0.14.0] - 2026-09-17

### General Notes

Major refactoring work has gone into this release. Please test before using in a production environment.

Any configuration that included `user_id_path` in either subsection of the `OAuth` settings can now remove it as it was 
never used, is no longer supported and will be ignored. A potential bug where `OAuth` related claims that did not
contain relevant data for verifying a User ID would sometimes allow login when `username_type` was declared has been
fixed. `OAuth` configs relying only on `username_type` alone now reject all logins, one of the claims must supply
`localpart_path` or `fq_uid_path`.

If you have multiple `jwk_*` or `enc_jwk*` declared *in the same subsection* this is now an error.

An experimental setting has been added that can allow for a list of fully qualified MXID values to be compared against
in an `OAuth` related claim. Look for `alternative_fq_uids_path` in the README.md file. This is not recommended for
general use at this time.

*Note*: The prior behavior of ignoring unknown configuration changes will change in the future. Check your configuration
for options that do not actually exist in advance.

### Miscellaneous Tasks

- bump: Pin publish wheel workflow to a proper commit hash ([\#95](https://github.com/famedly/synapse-token-authenticator/pull/95)) (Jason Little)
- chore: add tests for registered resources, configs and claims validator ([\#104](https://github.com/famedly/synapse-token-authenticator/pull/104)) (Soyoung Kim)
- chore: move resources and auth classes into dedicated files ([\#94](https://github.com/famedly/synapse-token-authenticator/pull/94)) (Soyoung Kim)
- chore: refactor auth checker functions to deduplicate repeated code ([\#97](https://github.com/famedly/synapse-token-authenticator/pull/97)) (Soyoung Kim)
- chore: refactor http auth ([\#100](https://github.com/famedly/synapse-token-authenticator/pull/100)) (Soyoung Kim)
- chore: refactor claims validator ([\#99](https://github.com/famedly/synapse-token-authenticator/pull/99)) (Soyoung Kim)
- chore: refactor config classes ([\#101](https://github.com/famedly/synapse-token-authenticator/pull/101)) (Soyoung Kim)
- chore: remove duplicated linting in ci, git ignore coverage files and fixes related to new linting ([\#91](https://github.com/famedly/synapse-token-authenticator/pull/91)) (Soyoung Kim)
- chore: update documentation ([\#103](https://github.com/famedly/synapse-token-authenticator/pull/103)) (Soyoung Kim)
- chore: use module api to set `displayname` ([\#92](https://github.com/famedly/synapse-token-authenticator/pull/92)) (Soyoung Kim)
- chore: use proper exception class ([\#98](https://github.com/famedly/synapse-token-authenticator/pull/98)) (Soyoung Kim)
- chore: use `uv` as the dependencies installer ([\#90](https://github.com/famedly/synapse-token-authenticator/pull/90)) (FrenchGithubUser)
- deps: remove pin on jwcrypto and fix tests to use a proper length token ([\#87](https://github.com/famedly/synapse-token-authenticator/pull/87)) (Jason Little)

### Features
- feat: Allow a returned claim to have a list of alternative fully qualified user ids to check on login. Experimental. ([\#107](https://github.com/famedly/synapse-token-authenticator/pull/107)) (Jason Little)
- feat: config accepts only one jwk source ([\#102](https://github.com/famedly/synapse-token-authenticator/pull/102)) (Soyoung Kim)
- feat: drop config option `user_id_path` ([\#105](https://github.com/famedly/synapse-token-authenticator/pull/105)) (Soyoung Kim)

### Bugfixes

- fix: jwk set and enc jwk now parse string and dict format ([\#104](https://github.com/famedly/synapse-token-authenticator/pull/104)) (Soyoung Kim)
- fix: reject oauth logins when neither token references a user id ([\#106](https://github.com/famedly/synapse-token-authenticator/pull/106)) (FrenchGithubUser)

## [0.13.1] - 2026-04-09

### Miscellaneous Tasks

- chore: remove duplicated twisted dependency in pyproject.toml (#80) (FrenchGithubUser)
- chore: Remove hatch scripts and replace with built-in hatch utilities (#84) (Jason Little)
- chore: First re-formatting run (#84) (Jason Little)
- chore: pin jwcrypto to 1.5.6 or lower temporarily (#84) (Jason Little)
- add to .gitignore for .idea based IDE's (#83)

### Bug Fixes

- fix: prevent early return in PathList lookup when intermediate path fails (#81) (Niklas Zender)

## [0.13.0] - 2026-03-26

### Features

- feat: trigger CI actions (that are triggered on PRs) in merge queue (#76) (FrenchGithubUser)

### Miscellaneous Tasks

- chore: bump python version (FrenchGithubUser)
- chore: the synapse team is now the maintainer of this project, update CODEOWNERS and remove obsolete file (FrenchGithubUser)
- chore: twisted dependency doesn't need to be pinned anymore (FrenchGithubUser)
- ci: remove unnecessary branches filter (#77) (FrenchGithubUser)
- fix: update tests to work with breaking changes in recent synapse versions (FrenchGithubUser)

### Refactoring

- refactor: Add more logs (Matheus Zaniolo)

## [0.12.0] - 2025-07-31

### Features

- Make admin_path take multiple paths

### Miscellaneous Tasks

- Add maintainers to codeowners file

### Refactoring

- Fix ruff warnings

## [0.11.0] - 2025-03-11

### Features

- Remove username check and add localpart lowercase

## [0.10.0] - 2025-03-07

### Documentation

- Fix epa flow table in docs

### Features

- Add public key publish endpoint

## [0.9.0] - 2025-02-24

### Bug Fixes

- Fix error when adding email to a new user
- Oauth flow with new user and registration disabled bug

### Documentation

- Add docs for ePa flow

### Features

- Add more attributes to the synapse when a user is created
- Add external id validation
- Add new epa flow

### Refactoring

- Add a few more debug logs

## [0.8.0] - 2025-02-11

### Features

- Add option to oauth to make an user admin on their first login

## [0.7.0] - 2025-02-10

### Features

- Add jwks fetch from idp

## [0.6.0] - 2024-07-02

### Refactoring

- [**breaking**] Refactor custom flow into configurable oauth

## [0.5.0] - 2024-05-24

### Bug Fixes

- Use SimpleHttpClient with proxy enabled
- Account for baseurl with path in oidc metadata
- Post introspection req urlencoded

## [0.4.6] - 2024-05-13

### Documentation

- Custom flow

### Features

- Add jwt custom flow
- Add bearer access token to custom flow

## [0.4.4] - 2024-04-24

### Bug Fixes

- Basic auth utf8

## [0.4.3] - 2024-04-08

### Features

- Refactor http calls to ModuleApi

## [0.4.2] - 2024-01-31

### Bug Fixes

- Correctly define proxies

## [0.4.1] - 2024-01-31

### Bug Fixes

- Ignore system proxy configuration

## [0.4.0] - 2024-01-11

### Documentation

- Document publishing process

### Features

- [**breaking**] Add OIDC login flow

### Miscellaneous Tasks

- Add github action
- Migrate to github

### Refactoring

- Appease linter
- [**breaking**] Rename the 'require_expiracy' option to 'require_expiry'

## [0.3.2] - 2022-11-24

### Bug Fixes

- Add Requester to set_displayname

### Miscellaneous Tasks

- Bump version and update changelog

## [0.3.1] - 2022-11-24

### Bug Fixes

- Allow properly setting the displayname from the token
- Use ProfileHandler for display name

### Miscellaneous Tasks

- Bump version and update changelog

## [0.3.0] - 2022-11-23

### Bug Fixes

- Use correct method name for display name change

### Features

- Handle displayname claim

## [0.2.0] - 2022-11-22

### Features

- Check chatbox login localpart pattern

### Miscellaneous Tasks

- Bump version and update changelog

## [0.1.1] - 2022-10-04

### Miscellaneous Tasks

- Remove jwcrypto version limit

### Refactoring

- Switch to async await
- Use public ModuleApi methods

## [0.1.0] - 2022-09-21

### Bug Fixes

- Fix bug in test-cases surfaced by update in jwcrypto

### Features

- Handle admin claim in JWT
- Update admin status on login

### Miscellaneous Tasks

- [**breaking**] Rename to synapse_token_authenticator
- Update CODEOWNERS
- Package using hatch
- Reformat code and add job for checking in CI
- Add changelog

<!-- generated by git-cliff -->
