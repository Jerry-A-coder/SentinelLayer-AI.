# SentinelLayer AI — Firestore Security Specification (Phase 0 TDD)

## 1. Data Invariants
1. **Identity Integrity**: Every document in `/scans/{scanId}`, `/policies/{policyId}`, and `/audit_logs/{logId}` must have `ownerId == request.auth.uid` and `request.auth.token.email_verified == true` (or admin status via `/admins/$(request.auth.uid)`).
2. **Path Variable Hardening**: Every single-document ID (`scanId`, `policyId`, `logId`) must match `^[a-zA-Z0-9_\-]+$` and be `<= 128` characters.
3. **Strict Schema & Volumetric Bounds**: No shadow/ghost fields allowed (`hasAll` and `hasOnly`). Every string field has explicit `.size() <= maxLength` matching `firebase-blueprint.json`.
4. **Temporal Integrity**: `createdAt == request.time` on creation; `updatedAt == request.time` on update; `createdAt` and `ownerId` are strictly immutable on update.
5. **Audit Immutability**: `/audit_logs/{logId}` documents are strictly append-only (no updates or deletes permitted by non-admins).
6. **Query Enforcer**: All `allow list` rules explicitly validate `resource.data.ownerId == request.auth.uid || isAdmin()`.

## 2. The "Dirty Dozen" Payloads (Designed to Fail with PERMISSION_DENIED)
1. **Identity Spoofing**: Creating a `scans` doc with `ownerId: "victim-uid-999"` while authenticated as `"attacker-uid-111"`.
2. **Shadow Field Injection**: Updating a `scans` doc with an undeclared field `{"isVerifiedAdmin": true}`.
3. **Unverified Email Write**: Creating a `policies` doc when `request.auth.token.email_verified == false`.
4. **ID Poisoning Attack**: Creating a `scans` doc with a 500-character ID or special characters `scan/../../admin`.
5. **Volumetric String Overflow**: Creating a `scans` doc where `contentPreview` is 50,000 characters (exceeding `maxLength: 2000`).
6. **Timestamp Forgery on Create**: Creating an `audit_logs` doc with a backdated `createdAt` timestamp != `request.time`.
7. **Immutable Field Mutation**: Updating a `scans` doc to change `ownerId` or `createdAt`.
8. **Invalid Enum State**: Creating or updating a `scans` doc with `outcome: "BYPASS_ALL"`.
9. **Audit Log Tampering**: Attempting an `update` or `delete` operation on `/audit_logs/{logId}`.
10. **Blanket List Scraping**: Executing an unconstrained `list` query on `/scans` to read other users' scans.
11. **Value Type Poisoning**: Updating `policies.blockThreshold` with a string `"high"` instead of a number within `[0, 100]`.
12. **Terminal Review State Reversal**: Attempting to update `reviewStatus` on a scan that has already reached terminal state (`APPROVED` or `REJECTED`) without admin privileges.
