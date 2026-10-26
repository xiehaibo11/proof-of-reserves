/**
 * Browser-side verification of the proof of reserves. The rules are byte-for-byte identical to the backend service/reserves/MerkleTree and ReserveLeafFormat:
 *     balancesText = "coin=amount" entries sorted lexicographically by coin, joined with semicolons, amounts fixed at 18 decimals
 *     balancesHash = SHA-256(UTF-8 of balancesText)
 *   leafHash     = SHA-256(0x00 ‖ uidHash(32B) ‖ balancesHash(32B))
 *     parent node  = SHA-256(0x01 ‖ left(32B) ‖ right(32B))
 * Amounts are handled as strings throughout, never through JS number.
 */
export interface ProofBalance { asset: string; amount: string }
export interface ProofStep { position: 'L' | 'R'; hash: string }
export interface MyProof {
  snapshotId: string | number;
  snapshotTime: string;
  merkleRoot: string;
  formatVersion: number;
  leafIndex: number;
  leafCount: number;
  uidHash: string;
  balances: ProofBalance[];
  balancesText: string;
  balancesHash: string;
  leafHash: string;
  proof: ProofStep[];
}

export type VerifyStepKind = 'balancesText' | 'balancesHash' | 'leaf' | 'level' | 'root' | 'published';
export interface VerifyStep {
  kind: VerifyStepKind;
  /** The value computed in this step (hash or serialized text) */
  value: string;
  /** true = passed; false = mismatch; null = only an intermediate value with nothing to compare against */
  ok: boolean | null;
  /** When kind = level: which level (from 1) and the side the sibling node is on */
  level?: number;
  side?: 'L' | 'R';
}
export interface VerifyReport { ok: boolean; steps: VerifyStep[] }

const AMOUNT_SCALE = 18;
const encoder = new TextEncoder();

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
}

export function fromHex(hex: string): Uint8Array {
  if (!/^[0-9a-fA-F]*$/.test(hex) || hex.length % 2 !== 0) throw new Error('bad hex');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export async function sha256(...parts: Uint8Array[]): Promise<Uint8Array> {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const joined = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) { joined.set(part, offset); offset += part.length; }
  return new Uint8Array(await crypto.subtle.digest('SHA-256', joined));
}

/** Decimal string → fixed 18 decimals. Rejects scientific notation, negative numbers and inputs that would lose precision. */
export function fixedAmount(value: string): string {
  const match = /^(\d+)(?:\.(\d+))?$/.exec(value.trim());
  if (!match) throw new Error(`bad amount: ${value}`);
  const fraction = match[2] ?? '';
  if (fraction.length > AMOUNT_SCALE && /[1-9]/.test(fraction.slice(AMOUNT_SCALE))) throw new Error('amount loses precision');
  return `${match[1]}.${fraction.slice(0, AMOUNT_SCALE).padEnd(AMOUNT_SCALE, '0')}`;
}

export function balancesText(balances: ProofBalance[]): string {
  return [...balances]
    .sort((a, b) => (a.asset < b.asset ? -1 : a.asset > b.asset ? 1 : 0))
    .map(item => `${item.asset}=${fixedAmount(item.amount)}`)
    .join(';');
}

/** Recompute step by step and compare with the values given by the server; publishedRoot is the tree root fetched independently from the public overview (optional). */
export async function verifyProof(proof: MyProof, publishedRoot?: string | null): Promise<VerifyReport> {
  const steps: VerifyStep[] = [];
  const text = balancesText(proof.balances);
  steps.push({ kind: 'balancesText', value: text, ok: text === proof.balancesText });

  const balancesHash = await sha256(encoder.encode(text));
  steps.push({ kind: 'balancesHash', value: toHex(balancesHash), ok: toHex(balancesHash) === proof.balancesHash.toLowerCase() });

  let current = await sha256(new Uint8Array([0x00]), fromHex(proof.uidHash), balancesHash);
  steps.push({ kind: 'leaf', value: toHex(current), ok: toHex(current) === proof.leafHash.toLowerCase() });

  let level = 0;
  for (const step of proof.proof) {
    level += 1;
    const sibling = fromHex(step.hash);
    current = step.position === 'L'
      ? await sha256(new Uint8Array([0x01]), sibling, current)
      : await sha256(new Uint8Array([0x01]), current, sibling);
    steps.push({ kind: 'level', value: toHex(current), ok: null, level, side: step.position });
  }
  const root = toHex(current);
  steps.push({ kind: 'root', value: root, ok: root === proof.merkleRoot.toLowerCase() });
  if (publishedRoot) {
    steps.push({ kind: 'published', value: publishedRoot, ok: publishedRoot.toLowerCase() === proof.merkleRoot.toLowerCase() });
  }
  return { ok: steps.every(step => step.ok !== false), steps };
}
