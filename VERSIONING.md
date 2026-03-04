# Versioning

## Protocol version
`protocol_version` defines deterministic semantics. Any change to event schema ordering, hash preimages/domains, replay verification logic, or feature-flag meaning requires a protocol version change and matching protocol hash impact.

## Crate/tooling version
`crate_version` tracks implementation and packaging releases (CLI/docs/scripts/CI/container/tooling). Tooling changes can bump crate version without changing protocol semantics.

## Compatibility rule
- Same `protocol_version` + same protocol hash: deterministic compatibility expected.
- Different `protocol_version` or protocol hash: treat as incompatible until explicitly migrated.
