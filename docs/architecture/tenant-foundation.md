# Tenant Foundation Slice

## Purpose

This document records the first implementation slice for the K3 SIEM customization blueprint's multi-tenancy requirements.

The goal of this slice is to introduce tenant context into the existing application without rewriting the entire data model in one pass.

## Included In This Slice

- A `tenants` table in the backend relational store.
- Default-tenant bootstrap and backfill for existing local databases.
- Tenant context in authenticated user payloads and JWT claims.
- Tenant-aware admin APIs for:
  - tenants
  - teams
  - users
  - agents
  - dashboards
- Tenant-aware frontend admin management view.
- Tenant context surfaced in the application shell.

## Design Choices

### Platform Admin

The existing `admin` role currently acts as the platform-wide administrator for this slice.

That means:

- admins can see and manage all tenants
- non-admin analysts remain restricted by tenant context
- existing team-scoped behavior is preserved inside a tenant

This keeps the current role system usable while leaving room for future role expansion such as MSSP or tenant-admin roles.

### Default Tenant

Existing deployments are backfilled into:

- `tenant-default`

This keeps upgrades additive and avoids forcing destructive reseeds.

### Scope Boundaries

This slice intentionally focuses on foundational ownership surfaces first:

- tenant records
- teams
- users
- agents
- dashboards

Event-level and alert-level tenant isolation still need a later phase because they span ClickHouse ingestion, alert generation pipelines, and historical backfill strategy.

## Next Recommended Steps

1. Add tenant IDs to alerts and incidents.
2. Add tenant IDs to ClickHouse event storage and ingestion APIs.
3. Introduce tenant-scoped ingestion keys.
4. Add tenant-aware dashboard/report filtering across operational pages.
5. Add cross-tenant leakage tests to CI.
