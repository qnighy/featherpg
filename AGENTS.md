# AGENTS.md: instructions for coding agents working on this repository

## Overview

This is a PostgreSQL-compatible in-memory database implemented in Rust, focused on use in automated testing environments.

## What and what not

- It is a PostgreSQL-compatible database focused on use in automated testing environments. (Not complete yet.)
- It implements PostgreSQL's wire protocol. (Not implemented yet.)
- It implements PostgreSQL's SQL grammar. (Not complete yet.)
- It implements PostgreSQL's SQL type system and semantics. (Not complete yet.)
- It implements PostgreSQL's standard tables, functions, types, and operators. (Not complete yet.)
- It provides the database features as Rust/C APIs. (Not implemented yet.)
- It also provides the database features through wire protocol. (Not implemented yet.)
- It provides an extra function for fast CoW database cloning. (Not implemented yet.)
- It **does not** persist data to disk. It is an in-memory database only.
- It **does not** implement extension APIs. When there is a need of a well-known extension, it should be implemented as a built-in feature.
- It puts **different criteria** on performance compared to production databases. Startup time and cloning time are more important than query execution time. However, ideally, it should scale in the same way as production databases in terms of asymptotic complexity. The latter requirement has a lower priority than feature parity and simple implementation.

## Implementation priorities

We use tests in [Mastodon](https://github.com/mastodon/mastodon) as an initial implementation target.

Our first aim is to get one test in Mastodon pass while using this database instead of PostgreSQL. Then we aim to get all tests pass.

## Coding guidelines

- Prefer failing with compilation erros or runtime errors over temporary incorrect implementations when you cannot implement a feature completely at once. An incorrect placeholder by you the agents causes a lot of trouble when debugging the system later. The author (human) codes in different criteria, so do not learn from the existing partial implementations in this way.
- When a definition you'd like to use is not `use`'d (imported) yet, propose a most idiomatic code that would work when the definition is imported later. Do not resort to fully qualified names merely because the definition is not imported yet.

## Testing guidelines

- Prefer simple unit tests over complex integration tests. When integration tests are necessary, relax assertions so that the tests break less often.
- Clarify each test's intention (purpuse). It should be expressed in the test name, and if that is not enough, in comments in the test body. As long as the intention is correctly expressed in the test, fixtures and assertions should be kept as simple as possible.
- Test intentions should align what is expected of the interface to be tested, not how it is ultimately used to build a complex feature. For example, you should not write lexer tests like you are testing a parser.
- Do not add arbitrarily many variations of tests for edge cases. Focus on the main use cases first. Edge case tests should align how it is implemented. Edge cases that cannot occur in the current implementation should not be tested.
