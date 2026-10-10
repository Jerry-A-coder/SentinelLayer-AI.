/**
 * SentinelLayer AI — Firestore Security Rules Verification Suite
 * Verifies that all 12 Dirty Dozen adversarial payloads defined in security_spec.md
 * are deterministically blocked by the ruleset invariants.
 */

export interface DirtyDozenAssertion {
  id: number;
  name: string;
  collection: string;
  operation: 'create' | 'update' | 'delete' | 'list';
  payloadDescription: string;
  enforcedGate: string;
  expectedResult: 'PERMISSION_DENIED';
}

export const DIRTY_DOZEN_ASSERTIONS: DirtyDozenAssertion[] = [
  {
    id: 1,
    name: 'Identity Spoofing',
    collection: 'scans',
    operation: 'create',
    payloadDescription: 'ownerId: "victim-uid-999" != request.auth.uid',
    enforcedGate: 'data.ownerId == request.auth.uid',
    expectedResult: 'PERMISSION_DENIED',
  },
  {
    id: 2,
    name: 'Shadow Field Injection',
    collection: 'scans',
    operation: 'update',
    payloadDescription: 'Extra undeclared field {"isVerifiedAdmin": true}',
    enforcedGate: 'data.keys().hasOnly(...) && affectedKeys().hasOnly(...)',
    expectedResult: 'PERMISSION_DENIED',
  },
  {
    id: 3,
    name: 'Unverified Email Write',
    collection: 'policies',
    operation: 'create',
    payloadDescription: 'request.auth.token.email_verified == false',
    enforcedGate: 'isVerifiedUser()',
    expectedResult: 'PERMISSION_DENIED',
  },
  {
    id: 4,
    name: 'ID Poisoning Attack',
    collection: 'scans',
    operation: 'create',
    payloadDescription: 'scanId with path traversal characters or > 128 chars',
    enforcedGate: 'isValidId(scanId)',
    expectedResult: 'PERMISSION_DENIED',
  },
  {
    id: 5,
    name: 'Volumetric String Overflow',
    collection: 'scans',
    operation: 'create',
    payloadDescription: 'contentPreview length > 2000 characters',
    enforcedGate: 'data.contentPreview.size() <= 2000',
    expectedResult: 'PERMISSION_DENIED',
  },
  {
    id: 6,
    name: 'Timestamp Forgery on Create',
    collection: 'audit_logs',
    operation: 'create',
    payloadDescription: 'Backdated createdAt != request.time',
    enforcedGate: 'incoming().createdAt == request.time',
    expectedResult: 'PERMISSION_DENIED',
  },
  {
    id: 7,
    name: 'Immutable Field Mutation',
    collection: 'scans',
    operation: 'update',
    payloadDescription: 'Mutating ownerId or createdAt on update',
    enforcedGate: 'incoming().ownerId == existing().ownerId && incoming().createdAt == existing().createdAt',
    expectedResult: 'PERMISSION_DENIED',
  },
  {
    id: 8,
    name: 'Invalid Enum State',
    collection: 'scans',
    operation: 'create',
    payloadDescription: 'outcome: "BYPASS_ALL"',
    enforcedGate: "data.outcome in ['ALLOW', 'SANITISE', 'QUARANTINE', 'BLOCK', 'REQUIRE_REVIEW']",
    expectedResult: 'PERMISSION_DENIED',
  },
  {
    id: 9,
    name: 'Audit Log Tampering',
    collection: 'audit_logs',
    operation: 'update',
    payloadDescription: 'Attempting to modify or delete an existing audit log',
    enforcedGate: 'allow update, delete: if false;',
    expectedResult: 'PERMISSION_DENIED',
  },
  {
    id: 10,
    name: 'Blanket List Scraping',
    collection: 'scans',
    operation: 'list',
    payloadDescription: 'Querying /scans without ownerId filter matching request.auth.uid',
    enforcedGate: 'resource.data.ownerId == request.auth.uid || isAdmin()',
    expectedResult: 'PERMISSION_DENIED',
  },
  {
    id: 11,
    name: 'Value Type Poisoning',
    collection: 'policies',
    operation: 'update',
    payloadDescription: 'Updating blockThreshold with string "high" instead of number 0..100',
    enforcedGate: 'isValidSecurityPolicy(incoming())',
    expectedResult: 'PERMISSION_DENIED',
  },
  {
    id: 12,
    name: 'Terminal Review State Reversal',
    collection: 'scans',
    operation: 'update',
    payloadDescription: 'Updating a scan whose reviewStatus is already APPROVED or REJECTED',
    enforcedGate: "existing().reviewStatus in ['PENDING', 'NONE']",
    expectedResult: 'PERMISSION_DENIED',
  },
];
