import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { promisify } from 'node:util';

const run = promisify(execFile);
const MAIN = join(import.meta.dirname, '..', 'verify', 'main.ts');
const ROOT = join(import.meta.dirname, '..');
const SUCCESS = 'All proofs verify passed!!!';

// Three-leaf standard vector: leaf 2 is the published vector from reservesProof.test.ts; the expected
// root/intermediate hashes below were computed independently (node:crypto createHash) from these leaf inputs.
const LEAF0 = {
  leafIndex: 0,
  uidHash: '11'.repeat(32),
  balancesText: 'BTC=1.500000000000000000',
  balancesHash: 'c24f8e721d1c07c8e7bfd59258bf070463d4c3b03d50b521ef4f67785abfe36a',
  leafHash: '8077639f9c30c9a0f918a00df712cec697b477eb7de1d6914a890638de804a4b',
};
const LEAF1 = {
  leafIndex: 1,
  uidHash: '22'.repeat(32),
  balancesText: 'ETH=2.000000000000000000;USDT=50.000000000000000000',
  balancesHash: 'd82b1f939746ce7233cd1616fbdaf44e9c72d592851e6275450d54c4c60e7bd3',
  leafHash: '8331f372b3b7548c0866d32a395b86d981718678d680913127341305c7747eab',
};
const LEAF2 = {
  leafIndex: 2,
  uidHash: 'b0f01435a57cf9ccaf472c33f76df605aa5abaf8b1872bae031f85445c4aa522',
  balancesText: 'BTC=0.500000000000000000;USDT=100.250000000000000000',
  balancesHash: 'e18eea5c6700970fe3675158e1879fca049f3c7f3951c17e0ca5533c3cec9f79',
  leafHash: '4ccc4a4875b3ae79573dd995382cbd19e835bf1b916685786a7aa42b3dce7255',
};
const LEVEL1_LEFT = '980a1c47178f9bc77a96f05adfa112c310177100fcb94f5c3e889e64320b3396'; // SHA-256(0x01‖LEAF0‖LEAF1)
const TREE_ROOT = '673348447b40f7537bf827d52f2bb049057eb87c9d859d758645e2c6f89cff2c';   // SHA-256(0x01‖LEVEL1_LEFT‖SHA-256(0x01‖LEAF2‖LEAF2))
const PUBLISHED_ROOT = '5af433fe78f3bee6710dd299f2cd7d4b19c157a91dc93155502d4a88ec892ca7'; // root of the published vector tree

const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T;
const standardTree = () => ({
  formatVersion: 1, snapshotId: 9, snapshotTime: '2026-10-26T00:05:00Z',
  merkleRoot: TREE_ROOT, leafCount: 3, treeDepth: 2,
  leaves: [clone(LEAF0), clone(LEAF1), clone(LEAF2)],
});
// /reserves/my-proof body of the leafIndex=2 user of the standard tree.
const userProof = (treeRoot = TREE_ROOT) => ({
  snapshotId: 9, snapshotTime: '2026-10-26T00:05:00Z',
  merkleRoot: treeRoot, formatVersion: 1, leafIndex: 2, leafCount: 3,
  uidHash: LEAF2.uidHash,
  balances: [{ asset: 'BTC', amount: '0.5' }, { asset: 'USDT', amount: '100.25' }],
  balancesText: LEAF2.balancesText, balancesHash: LEAF2.balancesHash, leafHash: LEAF2.leafHash,
  proof: [{ position: 'R', hash: LEAF2.leafHash }, { position: 'L', hash: LEVEL1_LEFT }],
});

async function tempDir(): Promise<string> {
  return mkdtemp(join(tmpdir(), 'por-verify-'));
}

async function writeJson(path: string, value: unknown): Promise<void> {
  await writeFile(path, JSON.stringify(value, null, 2));
}

interface CliResult { code: number; output: string }
async function cli(args: string[]): Promise<CliResult> {
  try {
    const { stdout, stderr } = await run(process.execPath, [MAIN, ...args], { cwd: ROOT });
    return { code: 0, output: stdout + stderr };
  } catch (err) {
    const failure = err as { code?: number; stdout?: string; stderr?: string };
    return { code: failure.code ?? 1, output: (failure.stdout ?? '') + (failure.stderr ?? '') };
  }
}

const lastLine = (output: string): string => output.trimEnd().split('\n').at(-1) ?? '';

test('verify cex recomputes the three-leaf standard vector root', async () => {
  const dir = await tempDir();
  const treePath = join(dir, 'merkle-tree.json');
  await writeJson(treePath, standardTree());
  const result = await cli(['verify', 'cex', '--tree', treePath]);
  assert.equal(result.code, 0, result.output);
  assert.equal(lastLine(result.output), SUCCESS);
  assert.match(result.output, new RegExp(TREE_ROOT));
});

test('tampering any leafHash makes verify cex fail with exit code 1', async () => {
  const dir = await tempDir();
  const treePath = join(dir, 'merkle-tree.json');
  const tree = standardTree();
  tree.leaves[1].leafHash = `f${LEAF1.leafHash.slice(1)}`; // flip the first character
  await writeJson(treePath, tree);
  const result = await cli(['verify', 'cex', '--tree', treePath]);
  assert.equal(result.code, 1);
  assert.match(result.output, /leafIndex=1/);
  assert.match(result.output, /leafHash 不符/);
  assert.ok(!result.output.includes(SUCCESS), 'failure run must not print the success line');
});

test('a tampered merkleRoot is reported as the mismatch point', async () => {
  const dir = await tempDir();
  const treePath = join(dir, 'merkle-tree.json');
  const tree = standardTree();
  tree.merkleRoot = `e${tree.merkleRoot.slice(1)}`;
  await writeJson(treePath, tree);
  const result = await cli(['verify', 'cex', '--tree', treePath]);
  assert.equal(result.code, 1);
  assert.match(result.output, /merkleRoot 不符/);
  assert.match(result.output, new RegExp(TREE_ROOT)); // recomputed value is shown
  assert.ok(!result.output.includes(SUCCESS));
});

test('leafCount mismatch against the actual leaves array is rejected', async () => {
  const dir = await tempDir();
  const treePath = join(dir, 'merkle-tree.json');
  const tree = standardTree();
  tree.leafCount = 4;
  await writeJson(treePath, tree);
  const result = await cli(['verify', 'cex', '--tree', treePath]);
  assert.equal(result.code, 1);
  assert.match(result.output, /leafCount 与实际条数不符: 声明 4，实际 3/);
  assert.ok(!result.output.includes(SUCCESS));
});

test('a non-canonical balancesText (wrong order) is rejected', async () => {
  const dir = await tempDir();
  const treePath = join(dir, 'merkle-tree.json');
  const tree = standardTree();
  tree.leaves[0].balancesText = 'USDT=1.000000000000000000;BTC=1.500000000000000000';
  await writeJson(treePath, tree);
  const result = await cli(['verify', 'cex', '--tree', treePath]);
  assert.equal(result.code, 1);
  assert.match(result.output, /leafIndex=0: balancesText 未按规范排序\/定标/);
  assert.ok(!result.output.includes(SUCCESS));
});

test('verify user passes against the published vector root from the tree file', async () => {
  const dir = await tempDir();
  const treePath = join(dir, 'merkle-tree.json');
  const userPath = join(dir, 'user-config.json');
  // The published vector's own tree root; the user subcommand only reads merkleRoot for cross-checking.
  await writeJson(treePath, { formatVersion: 1, merkleRoot: PUBLISHED_ROOT });
  await writeJson(userPath, {
    snapshotId: '1', snapshotTime: '2026-09-29T00:05:00Z',
    merkleRoot: PUBLISHED_ROOT, formatVersion: 1, leafIndex: 2, leafCount: 3,
    uidHash: LEAF2.uidHash,
    balances: [{ asset: 'BTC', amount: '0.5' }, { asset: 'USDT', amount: '100.25' }],
    balancesText: LEAF2.balancesText, balancesHash: LEAF2.balancesHash, leafHash: LEAF2.leafHash,
    proof: [
      { position: 'R', hash: LEAF2.leafHash },
      { position: 'L', hash: '6cbd307bf1223a7dd84ee855a63d130939b998efaa0aff2bd21c9af721d81fec' },
    ],
  });
  const result = await cli(['verify', 'user', '--tree', treePath, '--config', userPath]);
  assert.equal(result.code, 0, result.output);
  assert.equal(lastLine(result.output), SUCCESS);
  assert.match(result.output, /leafIndex=2, leafCount=3/);
});

test('verify user passes with the three-leaf fixture proof', async () => {
  const dir = await tempDir();
  const treePath = join(dir, 'merkle-tree.json');
  const userPath = join(dir, 'user-config.json');
  await writeJson(treePath, standardTree());
  await writeJson(userPath, userProof());
  const result = await cli(['verify', 'user', '--tree', treePath, '--config', userPath]);
  assert.equal(result.code, 0, result.output);
  assert.equal(lastLine(result.output), SUCCESS);
  assert.match(result.output, /leafIndex=2, leafCount=3/);
});

test('verify user without a tree file falls back with an explicit notice', async () => {
  const dir = await tempDir();
  const userPath = join(dir, 'user-config.json');
  await writeJson(userPath, userProof());
  const result = await cli(['verify', 'user', '--tree', join(dir, 'missing-tree.json'), '--config', userPath]);
  assert.equal(result.code, 0, result.output);
  assert.match(result.output, /未与公开树文件交叉比对/);
  assert.equal(lastLine(result.output), SUCCESS);
});

test('verify user detects a root mismatch against the published tree', async () => {
  const dir = await tempDir();
  const treePath = join(dir, 'merkle-tree.json');
  const userPath = join(dir, 'user-config.json');
  await writeJson(treePath, { formatVersion: 1, merkleRoot: PUBLISHED_ROOT });
  await writeJson(userPath, userProof()); // proof is self-consistent, but the published tree shows a different root
  const result = await cli(['verify', 'user', '--tree', treePath, '--config', userPath]);
  assert.equal(result.code, 1);
  assert.match(result.output, /公开树文件 merkleRoot 与 user-config 的 merkleRoot 不一致/);
  assert.ok(!result.output.includes(SUCCESS));
});

test('missing files, bad JSON and unknown options give readable errors with exit code 1', async () => {
  const dir = await tempDir();
  const badJson = join(dir, 'bad.json');
  await writeFile(badJson, '{ not json');
  const missing = await cli(['verify', 'cex', '--tree', join(dir, 'nope.json')]);
  assert.equal(missing.code, 1);
  assert.match(missing.output, /错误: 公开树文件不存在/);
  const broken = await cli(['verify', 'cex', '--tree', badJson]);
  assert.equal(broken.code, 1);
  assert.match(broken.output, /JSON 解析失败/);
  const unknown = await cli(['verify', 'cex', '--bogus']);
  assert.equal(unknown.code, 1);
  assert.match(unknown.output, /未知参数: --bogus/);
  const command = await cli(['frobnicate']);
  assert.equal(command.code, 1);
  assert.match(command.output, /未知命令: frobnicate/);
});

test('no arguments and verify help print the usage with exit code 0', async () => {
  const bare = await cli([]);
  assert.equal(bare.code, 0);
  assert.match(bare.output, /用法:/);
  assert.match(bare.output, /node verify\/main\.ts verify cex/);
  const help = await cli(['verify', 'help']);
  assert.equal(help.code, 0);
  assert.match(help.output, /用法:/);
});
