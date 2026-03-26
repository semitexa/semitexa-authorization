# semitexa/authorization

Policy-based access control with capability and permission guards and payload-level enforcement.

## Purpose

Evaluates access policies on every guarded request. Resolves merged policies from class hierarchy, checks capabilities and permissions against the authenticated subject, and blocks unauthorized access at the pipeline level.

## Role in Semitexa

Depends on `semitexa/core` and `semitexa/auth`. Used by `semitexa/rbac` and platform packages. Provides the enforcement layer that RBAC and other grant resolvers plug into.

## Key Features

- `#[RequiresCapability]`, `#[RequiresPermission]`, `#[PublicEndpoint]` attributes
- `PayloadAccessPolicyResolver` merging policies from class hierarchy
- `AuthorizationListener` guarding handler execution with 403 on failure
- `AuthenticatedSubject` and `GuestSubject` types
- Extensible via `SubjectGrantResolverInterface` (implemented by RBAC)

## Notes

Authorization uses a `SubjectGrantResolverInterface` to resolve the authenticated subject's grants when an `Authorizer` is registered. If no `SubjectGrantResolverInterface` is available, capability and permission requirements fail closed. If no `Authorizer` is registered at all, the pipeline falls back to public-vs-protected endpoint handling only and skips grant evaluation.
