import { initializeApp } from 'firebase/app';
import {
  getAuth,
  GoogleAuthProvider,
  signInWithPopup,
  onAuthStateChanged,
  User,
} from 'firebase/auth';
import {
  getFirestore,
  doc,
  getDocFromServer,
  setDoc,
  updateDoc,
  collection,
  query,
  where,
  orderBy,
  onSnapshot,
  serverTimestamp,
  Timestamp,
} from 'firebase/firestore';
import firebaseConfig from '../firebase-applet-config.json';
import { ScanAnalysisResponse, SecurityPolicyProfile } from './types/sentinel.ts';

// Single shared Firebase App initialization
const app = initializeApp(firebaseConfig);
export const db = getFirestore(app, firebaseConfig.firestoreDatabaseId);
export const auth = getAuth(app);
export const FIREBASE_PROJECT_ID = firebaseConfig.projectId;

// Google OAuth Scopes for Google Chat integration
export const SCOPES = [
  'https://www.googleapis.com/auth/chat.spaces.readonly',
  'https://www.googleapis.com/auth/chat.messages.readonly',
  'https://www.googleapis.com/auth/chat.messages.create',
];

const googleProvider = new GoogleAuthProvider();
for (const scope of SCOPES) {
  googleProvider.addScope(scope);
}

let isSigningIn = false;
let cachedAccessToken: string | null = null;

// Validate connection to Firestore on boot as required by firebase-integration-rpc
async function testConnection() {
  try {
    await getDocFromServer(doc(db, 'test', 'connection'));
  } catch (error) {
    if (error instanceof Error && error.message.includes('the client is offline')) {
      console.error('Please check your Firebase configuration.');
    }
  }
}
testConnection();

export enum OperationType {
  CREATE = 'create',
  UPDATE = 'update',
  DELETE = 'delete',
  LIST = 'list',
  GET = 'get',
  WRITE = 'write',
}

export interface FirestoreErrorInfo {
  error: string;
  operationType: OperationType;
  path: string | null;
  authInfo: {
    userId?: string | null;
    email?: string | null;
    emailVerified?: boolean | null;
    isAnonymous?: boolean | null;
    tenantId?: string | null;
    providerInfo?: {
      providerId?: string | null;
      email?: string | null;
    }[];
  };
}

export function handleFirestoreError(
  error: unknown,
  operationType: OperationType,
  path: string | null
): never {
  const errInfo: FirestoreErrorInfo = {
    error: error instanceof Error ? error.message : String(error),
    authInfo: {
      userId: auth.currentUser?.uid,
      email: auth.currentUser?.email,
      emailVerified: auth.currentUser?.emailVerified,
      isAnonymous: auth.currentUser?.isAnonymous,
      tenantId: auth.currentUser?.tenantId,
      providerInfo:
        auth.currentUser?.providerData?.map((provider) => ({
          providerId: provider.providerId,
          email: provider.email,
        })) || [],
    },
    operationType,
    path,
  };
  console.error('Firestore Error: ', JSON.stringify(errInfo));
  throw new Error(JSON.stringify(errInfo));
}

export const initAuth = (
  onAuthChange: (user: User | null, token: string | null) => void
) => {
  return onAuthStateChanged(auth, (user: User | null) => {
    if (user) {
      onAuthChange(user, cachedAccessToken);
    } else {
      cachedAccessToken = null;
      onAuthChange(null, null);
    }
  });
};

export const googleSignIn = async (): Promise<{ user: User; accessToken: string | null }> => {
  try {
    isSigningIn = true;
    const result = await signInWithPopup(auth, googleProvider);
    const credential = GoogleAuthProvider.credentialFromResult(result);
    cachedAccessToken = credential?.accessToken || null;
    return { user: result.user, accessToken: cachedAccessToken };
  } finally {
    isSigningIn = false;
  }
};

export const getAccessToken = (): string | null => cachedAccessToken;

export const logout = async () => {
  await auth.signOut();
  cachedAccessToken = null;
};

// Defensive Sanitization Helper matching firebase-blueprint.json constraints
function sanitizeId(raw: string): string {
  return raw.replace(/[^a-zA-Z0-9_-]/g, '-').slice(0, 128) || 'ID-DEFAULT';
}

export async function persistScanToFirestore(scan: ScanAnalysisResponse, actorRole: string) {
  if (!auth.currentUser) return;
  const uid = auth.currentUser.uid;
  const safeScanId = sanitizeId(scan.scanId);
  const scanPath = `scans/${safeScanId}`;

  try {
    await setDoc(doc(db, 'scans', safeScanId), {
      scanId: safeScanId,
      ownerId: uid,
      sourceName: (scan.sourceName || 'Untitled Source').slice(0, 200),
      sourceType: (scan.sourceType || 'Plain Text').slice(0, 50),
      contentPreview: (scan.normalisedPreview || '').slice(0, 2000),
      sanitisedContent: (scan.sanitisedContent || '').slice(0, 2000),
      riskScore: Math.max(0, Math.min(100, Number(scan.riskScore) || 0)),
      outcome: ['ALLOW', 'SANITISE', 'QUARANTINE', 'BLOCK', 'REQUIRE_REVIEW'].includes(scan.outcome)
        ? scan.outcome
        : 'QUARANTINE',
      primaryCategory: (scan.primaryCategory || 'Benign / Clean').slice(0, 64),
      findingsCount: Math.max(0, Math.min(500, scan.findings.length)),
      aiMode: (scan.aiMode || 'FULL_AI_ORCHESTRATION').slice(0, 32),
      policyVersion: (scan.policyVersion || 'v2.4-ENT').slice(0, 32),
      reviewStatus: ['PENDING', 'APPROVED', 'REJECTED', 'NONE'].includes(scan.reviewStatus)
        ? scan.reviewStatus
        : 'NONE',
      createdAt: serverTimestamp(),
      updatedAt: serverTimestamp(),
    });
  } catch (err) {
    handleFirestoreError(err, OperationType.CREATE, scanPath);
  }

  // Also record an immutable audit trail log
  const logId = sanitizeId(`LOG-${Date.now().toString(36).toUpperCase()}-${Math.random().toString(36).substring(2, 6).toUpperCase()}`);
  const logPath = `audit_logs/${logId}`;
  try {
    await setDoc(doc(db, 'audit_logs', logId), {
      logId,
      ownerId: uid,
      scanId: safeScanId,
      eventType: scan.automatedRemediation?.triggered
        ? 'AUTOMATED_VENDOR_REMEDIATION_DISPATCHED'
        : scan.toolFirewallDecision
        ? `SCAN_AND_TOOL_${scan.toolFirewallDecision.allowed ? 'ALLOWED' : 'BLOCKED'}`
        : 'CONTENT_GATEWAY_SCAN',
      decision: scan.outcome.slice(0, 32),
      policyVersion: (scan.policyVersion || 'v2.4-ENT').slice(0, 32),
      actorRole: actorRole.slice(0, 32),
      summary: `${scan.sourceType} "${scan.sourceName.slice(0, 60)}" evaluated with risk score ${scan.riskScore}/100 -> ${scan.outcome} (${scan.primaryCategory}).${
        scan.automatedRemediation?.triggered
          ? ` [AUTO-REMEDIATION: Flagged & notified ${scan.automatedRemediation.vendorTeamTarget}]`
          : ''
      }`.slice(0, 500),
      createdAt: serverTimestamp(),
    });
  } catch (err) {
    handleFirestoreError(err, OperationType.CREATE, logPath);
  }
}

export async function updateQuarantineReviewInFirestore(
  scanId: string,
  newReviewStatus: 'APPROVED' | 'REJECTED',
  newOutcome: 'ALLOW' | 'BLOCK',
  actorRole: string
) {
  if (!auth.currentUser) return;
  const uid = auth.currentUser.uid;
  const safeScanId = sanitizeId(scanId);
  const scanPath = `scans/${safeScanId}`;

  try {
    await updateDoc(doc(db, 'scans', safeScanId), {
      reviewStatus: newReviewStatus,
      outcome: newOutcome,
      updatedAt: serverTimestamp(),
    });
  } catch (err) {
    handleFirestoreError(err, OperationType.UPDATE, scanPath);
  }

  const logId = sanitizeId(`LOG-REV-${Date.now().toString(36).toUpperCase()}`);
  try {
    await setDoc(doc(db, 'audit_logs', logId), {
      logId,
      ownerId: uid,
      scanId: safeScanId,
      eventType: 'HUMAN_QUARANTINE_REVIEW',
      decision: newOutcome,
      policyVersion: 'v2.4-ENT',
      actorRole: actorRole.slice(0, 32),
      summary: `Human analyst review marked scan ${safeScanId} as ${newReviewStatus} -> ${newOutcome}.`.slice(0, 500),
      createdAt: serverTimestamp(),
    });
  } catch (err) {
    handleFirestoreError(err, OperationType.CREATE, `audit_logs/${logId}`);
  }
}

export async function saveSecurityPolicyToFirestore(policy: SecurityPolicyProfile, isExisting: boolean) {
  if (!auth.currentUser) return;
  const uid = auth.currentUser.uid;
  const safePolicyId = sanitizeId(policy.policyId);
  const path = `policies/${safePolicyId}`;

  try {
    if (isExisting) {
      await updateDoc(doc(db, 'policies', safePolicyId), {
        name: policy.name.slice(0, 120),
        version: policy.version.slice(0, 32),
        blockThreshold: Math.max(0, Math.min(100, Number(policy.blockThreshold))),
        quarantineThreshold: Math.max(0, Math.min(100, Number(policy.quarantineThreshold))),
        sanitiseThreshold: Math.max(0, Math.min(100, Number(policy.sanitiseThreshold))),
        failClosedOnAiOffline: Boolean(policy.failClosedOnAiOffline),
        enforceStrictToolAllowlist: Boolean(policy.enforceStrictToolAllowlist),
        automatedRemediationEnabled: Boolean(policy.automatedRemediationEnabled ?? true),
        vendorNotificationTarget: (
          policy.vendorNotificationTarget || 'psirt-alerts@external-vendor-sec.io'
        ).slice(0, 200),
        updatedAt: serverTimestamp(),
      });
    } else {
      await setDoc(doc(db, 'policies', safePolicyId), {
        policyId: safePolicyId,
        ownerId: uid,
        name: policy.name.slice(0, 120),
        version: policy.version.slice(0, 32),
        blockThreshold: Math.max(0, Math.min(100, Number(policy.blockThreshold))),
        quarantineThreshold: Math.max(0, Math.min(100, Number(policy.quarantineThreshold))),
        sanitiseThreshold: Math.max(0, Math.min(100, Number(policy.sanitiseThreshold))),
        failClosedOnAiOffline: Boolean(policy.failClosedOnAiOffline),
        enforceStrictToolAllowlist: Boolean(policy.enforceStrictToolAllowlist),
        automatedRemediationEnabled: Boolean(policy.automatedRemediationEnabled ?? true),
        vendorNotificationTarget: (
          policy.vendorNotificationTarget || 'psirt-alerts@external-vendor-sec.io'
        ).slice(0, 200),
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      });
    }
  } catch (err) {
    handleFirestoreError(err, isExisting ? OperationType.UPDATE : OperationType.CREATE, path);
  }
}

export function subscribeUserScans(
  uid: string,
  onData: (scans: any[]) => void
) {
  const q = query(collection(db, 'scans'), where('ownerId', '==', uid));
  return onSnapshot(
    q,
    (snapshot) => {
      const items = snapshot.docs.map((d) => {
        const data = d.data();
        const createdAtIso =
          data.createdAt instanceof Timestamp
            ? data.createdAt.toDate().toISOString()
            : new Date().toISOString();
        return { ...data, createdAtIso };
      });
      items.sort((a, b) => b.createdAtIso.localeCompare(a.createdAtIso));
      onData(items);
    },
    (error) => {
      handleFirestoreError(error, OperationType.LIST, 'scans');
    }
  );
}

export function subscribeUserAuditLogs(
  uid: string,
  onData: (logs: any[]) => void
) {
  const q = query(collection(db, 'audit_logs'), where('ownerId', '==', uid));
  return onSnapshot(
    q,
    (snapshot) => {
      const items = snapshot.docs.map((d) => {
        const data = d.data();
        const createdAtIso =
          data.createdAt instanceof Timestamp
            ? data.createdAt.toDate().toISOString()
            : new Date().toISOString();
        return { ...data, createdAtIso };
      });
      items.sort((a, b) => b.createdAtIso.localeCompare(a.createdAtIso));
      onData(items);
    },
    (error) => {
      handleFirestoreError(error, OperationType.LIST, 'audit_logs');
    }
  );
}

export function subscribeUserPolicies(
  uid: string,
  onData: (policies: SecurityPolicyProfile[]) => void
) {
  const q = query(collection(db, 'policies'), where('ownerId', '==', uid));
  return onSnapshot(
    q,
    (snapshot) => {
      const items = snapshot.docs.map((d) => d.data() as SecurityPolicyProfile);
      onData(items);
    },
    (error) => {
      handleFirestoreError(error, OperationType.LIST, 'policies');
    }
  );
}
