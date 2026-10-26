import assert from 'node:assert/strict';
import test from 'node:test';
import { balancesText, fixedAmount, fromHex, sha256, toHex, verifyProof, type MyProof } from '../src/reservesProof.ts';

const vector: MyProof = {
  snapshotId: '1', snapshotTime: '2026-09-29T00:05:00Z',
  merkleRoot: '5af433fe78f3bee6710dd299f2cd7d4b19c157a91dc93155502d4a88ec892ca7', formatVersion: 1,
  leafIndex: 2, leafCount: 3,
  uidHash: 'b0f01435a57cf9ccaf472c33f76df605aa5abaf8b1872bae031f85445c4aa522',
  balances: [{ asset: 'BTC', amount: '0.5' }, { asset: 'USDT', amount: '100.25' }],
  balancesText: 'BTC=0.500000000000000000;USDT=100.250000000000000000',
  balancesHash: 'e18eea5c6700970fe3675158e1879fca049f3c7f3951c17e0ca5533c3cec9f79',
  leafHash: '4ccc4a4875b3ae79573dd995382cbd19e835bf1b916685786a7aa42b3dce7255',
  proof: [
    { position: 'R', hash: '4ccc4a4875b3ae79573dd995382cbd19e835bf1b916685786a7aa42b3dce7255' },
    { position: 'L', hash: '6cbd307bf1223a7dd84ee855a63d130939b998efaa0aff2bd21c9af721d81fec' }
  ]
};
const clone = (): MyProof => JSON.parse(JSON.stringify(vector));

test('SHA-256 and canonical balance serialization match published vectors', async () => {
  assert.equal(toHex(await sha256(new TextEncoder().encode('a'))), 'ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb');
  assert.equal(toHex(fromHex('00ff10')), '00ff10');
  assert.equal(fixedAmount('7'), '7.000000000000000000');
  assert.equal(balancesText([{ asset: 'USDT', amount: '100.25' }, { asset: 'BTC', amount: '0.5' }]), vector.balancesText);
  assert.throws(() => fixedAmount('1e-7'));
  assert.throws(() => fixedAmount('-1'));
});

test('valid proof passes every local verification step', async () => {
  const report = await verifyProof(vector, vector.merkleRoot);
  assert.equal(report.ok, true);
  assert.deepEqual(report.steps.map(step => step.kind), ['balancesText', 'balancesHash', 'leaf', 'level', 'level', 'root', 'published']);
});

test('changing one balance unit invalidates the proof', async () => {
  const proof = clone();
  proof.balances[1].amount = '100.250000000000000001';
  assert.equal((await verifyProof(proof)).ok, false);
});

test('tampered sibling, direction, leaf or public root is rejected', async () => {
  const sibling = clone();
  sibling.proof[1].hash = '00'.repeat(32);
  assert.equal((await verifyProof(sibling)).ok, false);
  const direction = clone();
  direction.proof[1].position = 'R';
  assert.equal((await verifyProof(direction)).ok, false);
  const leaf = clone();
  leaf.leafHash = 'cd'.repeat(32);
  assert.equal((await verifyProof(leaf)).ok, false);
  assert.equal((await verifyProof(vector, 'ab'.repeat(32))).ok, false);
});

test('proof verifies without an independently supplied public root', async () => {
  const report = await verifyProof(vector, null);
  assert.equal(report.ok, true);
  assert.equal(report.steps.some(step => step.kind === 'published'), false);
});
