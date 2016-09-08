# `solvere`

A simple Golang package and standalone server for recursive DNS resolution.

## Feature support

- [X] Recursive resolution
- [ ] Response sanitization/validation
  - [ ] DNSSEC validation
    - [X] RRSIG validation
    - [X] DS referral validation
  - [ ] NSEC/NSEC3 validation
- [ ] Safe Question/Answer caching (**Basic impl. complete**)
