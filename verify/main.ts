/**
 * Offline CLI verifier for the BCB FX proof of reserves (Node 24 runs this file directly: `node verify/main.ts ...`).
 * No dependencies: hashing reuses src/reservesProof.ts (byte-for-byte the same spec as the backend MerkleTree/ReserveLeafFormat),
 * amounts and hashes are handled as strings / Uint8Array only, never through JS number arithmetic.
 *
 * Spec (must stay identical to src/reservesProof.ts and server/.../MerkleTree.java):
 *   balancesText = "ASSET=amount(18 fixed decimals)" entries sorted lexicographically by asset, joined with ';'
 *   balancesHash = SHA-256(UTF-8(balancesText))
 *   leafHash     = SHA-256(0x00 || uidHash(32B) || balancesHash(32B))
 *   inner node   = SHA-256(0x01 || left(32B) || right(32B)); an odd-sized level duplicates its last node
 *   empty tree   = SHA-256(UTF-8("qovf-por:empty"))
 */
import { readFile } from 'node:fs/promises';
import {
  balancesText,
  fixedAmount,
  fromHex,
  sha256,
  toHex,
  verifyProof,
} from '../src/reservesProof.ts';
import type { MyProof, ProofBalance, VerifyStep } from '../src/reservesProof.ts';

const DEFAULT_TREE_PATH = 'config/merkle-tree.json';
const DEFAULT_USER_PATH = 'config/user-config.json';
const SUCCESS_LINE = 'All proofs verify passed!!!';
const HEX64_PATTERN = /^[0-9a-fA-F]{64}$/;

const encoder = new TextEncoder();

/** Readable usage/CLI error (bad arguments, missing file, malformed JSON/shape) -> printed as "错误: ...", exit code 1. */
class UsageError extends Error {}
/** Missing file, so `verify user` can fall back to the proof's own merkleRoot instead of erroring. */
class MissingFileError extends Error {}
/** First failed verification check (which leafIndex, expected vs actual) -> printed as "校验失败: ...", exit code 1. */
class CheckError extends Error {}

interface CliOptions {
  sub: 'cex' | 'user' | 'help';
  treePath: string;
  userPath: string;
}

interface TreeLeaf {
  leafIndex: number;
  uidHash: string;
  balancesText: string;
  balancesHash: string;
  leafHash: string;
}

function usage(): string {
  return `用法:
  node verify/main.ts verify cex   [--tree <path>]                  重算公开 Merkle 树根并与 merkleRoot 交叉比对
  node verify/main.ts verify user  [--tree <path>] [--config <path>] 逐步校验个人证明（/reserves/my-proof 返回体）
  node verify/main.ts verify help                                     显示本帮助

默认路径: 公开树文件 ${DEFAULT_TREE_PATH}，个人证明 ${DEFAULT_USER_PATH}
步骤:
  1. 从官网下载公开树 JSON 保存为 ${DEFAULT_TREE_PATH}；
  2. 个人验证再下载 my-proof JSON 保存为 ${DEFAULT_USER_PATH}；
  3. 运行对应命令，全部通过时最后一行输出: ${SUCCESS_LINE}
     任何一步不通过时打印第一个失败点（leafIndex、期望值与实际值），退出码为 1。`;
}

function parseArgs(argv: string[]): CliOptions {
  let treePath = DEFAULT_TREE_PATH;
  let userPath = DEFAULT_USER_PATH;
  const positional: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--tree' || arg === '--config') {
      const value = argv[++i];
      if (value === undefined || value.startsWith('-')) throw new UsageError(`选项 ${arg} 缺少参数值`);
      if (arg === '--tree') treePath = value;
      else userPath = value;
    } else if (arg === '-h' || arg === '--help') {
      positional.length = 0;
      positional.push('help');
    } else if (arg.startsWith('-')) {
      throw new UsageError(`未知参数: ${arg}`);
    } else {
      positional.push(arg);
    }
  }
  const [command, sub, extra] = positional;
  if (extra !== undefined) throw new UsageError(`多余的位置参数: ${extra}`);
  if (command === undefined || command === 'help') return { sub: 'help', treePath, userPath };
  if (command !== 'verify') throw new UsageError(`未知命令: ${command}（支持 verify cex / verify user / help）`);
  if (sub === undefined) throw new UsageError('verify 需要子命令: cex、user 或 help');
  if (sub !== 'cex' && sub !== 'user' && sub !== 'help') throw new UsageError(`未知子命令: ${sub}（支持 cex / user / help）`);
  return { sub, treePath, userPath };
}

async function loadJson(path: string, label: string): Promise<unknown> {
  let raw: string;
  try {
    raw = await readFile(path, 'utf8');
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === 'ENOENT' || code === 'EISDIR' || code === 'ENOTDIR') {
      throw new MissingFileError(`${label}不存在: ${path}`);
    }
    throw new UsageError(`读取${label}失败: ${path}: ${(err as Error).message}`);
  }
  try {
    return JSON.parse(raw);
  } catch (err) {
    throw new UsageError(`JSON 解析失败: ${path}: ${(err as Error).message}`);
  }
}

function asObject(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new UsageError(`${label} 必须是 JSON 对象`);
  }
  return value as Record<string, unknown>;
}

function asString(value: unknown, label: string): string {
  if (typeof value !== 'string') throw new UsageError(`${label} 必须是字符串，实际: ${JSON.stringify(value)}`);
  return value;
}

/** Lowercased 64-hex string, otherwise a readable error. */
function asHex64(value: unknown, label: string): string {
  return normaliseHex(asString(value, label), label);
}

function normaliseHex(value: string, label: string): string {
  if (!HEX64_PATTERN.test(value)) throw new UsageError(`${label} 必须是 64 位十六进制（32 字节），实际: ${JSON.stringify(value)}`);
  return value.toLowerCase();
}

function asNonNegativeInt(value: unknown, label: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw new UsageError(`${label} 必须是非负整数，实际: ${JSON.stringify(value)}`);
  }
  return value;
}

async function hashLeafHex(uidHash: string, balancesHash: string): Promise<string> {
  return toHex(await sha256(new Uint8Array([0x00]), fromHex(uidHash), fromHex(balancesHash)));
}

async function hashNodeHex(left: string, right: string): Promise<string> {
  return toHex(await sha256(new Uint8Array([0x01]), fromHex(left), fromHex(right)));
}

/** Rebuild the whole tree bottom-up; identical rules to MerkleTree.build (odd level duplicates its last node). */
async function computeRoot(leafHashes: string[]): Promise<{ root: string; depth: number }> {
  if (leafHashes.length === 0) {
    return { root: toHex(await sha256(encoder.encode('qovf-por:empty'))), depth: 0 };
  }
  let level = leafHashes;
  let depth = 0;
  while (level.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      const right = i + 1 < level.length ? level[i + 1] : left;
      next.push(await hashNodeHex(left, right));
    }
    level = next;
    depth += 1;
  }
  return { root: level[0], depth };
}

/** Parse a leaf's balancesText and verify it equals the canonically sorted/rescaled result (order tolerated, spec order required). */
function canonicalBalancesCheck(text: string, leafIndex: number): ProofBalance[] {
  const entries: ProofBalance[] = [];
  if (text !== '') {
    for (const part of text.split(';')) {
      const eq = part.indexOf('=');
      if (eq <= 0 || eq === part.length - 1 || part.indexOf('=', eq + 1) !== -1) {
        throw new CheckError(`leafIndex=${leafIndex}: balancesText 条目无法解析（期望 "ASSET=amount"）: ${JSON.stringify(part)}`);
      }
      entries.push({ asset: part.slice(0, eq), amount: part.slice(eq + 1) });
    }
  }
  let canonical: string;
  try {
    canonical = balancesText(entries);
  } catch (err) {
    throw new CheckError(`leafIndex=${leafIndex}: balancesText 金额不符合 18 位小数规范: ${(err as Error).message} (${JSON.stringify(text)})`);
  }
  if (canonical !== text) {
    throw new CheckError(`leafIndex=${leafIndex}: balancesText 未按规范排序/定标，期望 ${canonical}，实际 ${text}`);
  }
  return entries;
}

function toTreeLeaf(value: unknown, position: number): TreeLeaf {
  const leaf = asObject(value, `leaves[${position}]`);
  return {
    leafIndex: asNonNegativeInt(leaf.leafIndex, `leaves[${position}].leafIndex`),
    uidHash: asHex64(leaf.uidHash, `leaves[${position}].uidHash`),
    balancesText: asString(leaf.balancesText, `leaves[${position}].balancesText`),
    balancesHash: asHex64(leaf.balancesHash, `leaves[${position}].balancesHash`),
    leafHash: asHex64(leaf.leafHash, `leaves[${position}].leafHash`),
  };
}

async function verifyCex(treePath: string): Promise<void> {
  const tree = asObject(await loadJson(treePath, '公开树文件'), treePath);
  const merkleRoot = asHex64(tree.merkleRoot, 'merkleRoot');
  const leafCount = asNonNegativeInt(tree.leafCount, 'leafCount');
  if (!Array.isArray(tree.leaves)) throw new UsageError('leaves 必须是数组');
  console.log(`读取公开树文件: ${treePath}（snapshotId=${JSON.stringify(tree.snapshotId)}, leafCount=${leafCount}, leaves=${tree.leaves.length}）`);

  if (tree.leaves.length !== leafCount) {
    throw new CheckError(`leafCount 与实际条数不符: 声明 ${leafCount}，实际 ${tree.leaves.length}`);
  }
  const leaves = tree.leaves.map(toTreeLeaf);

  // Ascending leafIndex; must cover 0..leafCount-1 exactly once.
  const ordered = [...leaves].sort((a, b) => a.leafIndex - b.leafIndex);
  for (let k = 0; k < ordered.length; k++) {
    if (ordered[k].leafIndex !== k) {
      throw new CheckError(`leafIndex 不连续或重复: 第 ${k} 项（按升序）期望 leafIndex=${k}，实际 ${ordered[k].leafIndex}`);
    }
  }

  // Per leaf: canonical balancesText, balancesHash, leafHash.
  for (const leaf of ordered) {
    canonicalBalancesCheck(leaf.balancesText, leaf.leafIndex);
    const computedBalancesHash = toHex(await sha256(encoder.encode(leaf.balancesText)));
    if (computedBalancesHash !== leaf.balancesHash) {
      throw new CheckError(`leafIndex=${leaf.leafIndex}: balancesHash 不符，期望(重算) ${computedBalancesHash}，实际 ${leaf.balancesHash}`);
    }
    const computedLeafHash = await hashLeafHex(leaf.uidHash, leaf.balancesHash);
    if (computedLeafHash !== leaf.leafHash) {
      throw new CheckError(`leafIndex=${leaf.leafIndex}: leafHash 不符，期望(重算 SHA-256(0x00‖uidHash‖balancesHash)) ${computedLeafHash}，实际 ${leaf.leafHash}`);
    }
  }
  console.log(`叶子校验通过（共 ${leaves.length} 片: balancesText / balancesHash / leafHash）`);

  // Recompute the full tree root from leafHashes ordered by leafIndex.
  const { root, depth } = await computeRoot(ordered.map(leaf => leaf.leafHash));
  if (tree.treeDepth !== undefined && tree.treeDepth !== null) {
    const claimed = asNonNegativeInt(tree.treeDepth, 'treeDepth');
    if (claimed !== depth) {
      throw new CheckError(`treeDepth 不符: 声明 ${claimed}，重算 ${depth}`);
    }
  }
  console.log(`重算 Merkle 根（深度 ${depth}）= ${root}`);
  if (root !== merkleRoot) {
    throw new CheckError(`merkleRoot 不符: 重算 ${root}，文件 ${merkleRoot}`);
  }
  console.log(`与文件 merkleRoot 一致: ${merkleRoot}`);
  console.log(SUCCESS_LINE);
}

function toMyProof(value: unknown): MyProof {
  const raw = asObject(value, 'user-config');
  if (!Array.isArray(raw.balances)) throw new UsageError('balances 必须是数组');
  if (!Array.isArray(raw.proof)) throw new UsageError('proof 必须是数组');
  const balances = raw.balances.map((item, index) => {
    const entry = asObject(item, `balances[${index}]`);
    return { asset: asString(entry.asset, `balances[${index}].asset`), amount: asString(entry.amount, `balances[${index}].amount`) };
  });
  const proof = raw.proof.map((item, index) => {
    const step = asObject(item, `proof[${index}]`);
    const position = asString(step.position, `proof[${index}].position`);
    if (position !== 'L' && position !== 'R') throw new UsageError(`proof[${index}].position 只能是 "L" 或 "R"，实际: ${JSON.stringify(step.position)}`);
    return { position, hash: asHex64(step.hash, `proof[${index}].hash`) };
  });
  const snapshotId = raw.snapshotId;
  if (typeof snapshotId !== 'string' && typeof snapshotId !== 'number') {
    throw new UsageError(`snapshotId 必须是字符串或数字，实际: ${JSON.stringify(snapshotId)}`);
  }
  // Fail early with a readable message if any amount cannot be canonically rescaled (verifyProof would throw otherwise).
  try {
    balances.forEach(entry => fixedAmount(entry.amount));
  } catch (err) {
    throw new UsageError(`balances 金额不合法: ${(err as Error).message}`);
  }
  return {
    snapshotId,
    snapshotTime: asString(raw.snapshotTime, 'snapshotTime'),
    merkleRoot: asHex64(raw.merkleRoot, 'merkleRoot'),
    formatVersion: asNonNegativeInt(raw.formatVersion, 'formatVersion'),
    leafIndex: asNonNegativeInt(raw.leafIndex, 'leafIndex'),
    leafCount: asNonNegativeInt(raw.leafCount, 'leafCount'),
    uidHash: asHex64(raw.uidHash, 'uidHash'),
    balances,
    balancesText: asString(raw.balancesText, 'balancesText'),
    balancesHash: asHex64(raw.balancesHash, 'balancesHash'),
    leafHash: asHex64(raw.leafHash, 'leafHash'),
    proof,
  };
}

function describeFailure(step: VerifyStep, proof: MyProof): string {
  switch (step.kind) {
    case 'balancesText':
      return `balancesText 与按 balances 重排/定标的结果不符，期望(重算) ${step.value}，实际 ${JSON.stringify(proof.balancesText)}`;
    case 'balancesHash':
      return `balancesHash 不符，期望(重算) ${step.value}，实际 ${proof.balancesHash}`;
    case 'leaf':
      return `leafHash 不符，期望(重算 SHA-256(0x00‖uidHash‖balancesHash)) ${step.value}，实际 ${proof.leafHash}`;
    case 'level':
      return `第 ${step.level} 层（兄弟在${step.side === 'L' ? '左' : '右'}侧）校验异常`;
    case 'root':
      return `按证明路径重算的根与 user-config 的 merkleRoot 不符，期望(重算) ${step.value}，实际 ${proof.merkleRoot}`;
    case 'published':
      return `公开树文件 merkleRoot 与 user-config 的 merkleRoot 不一致，公开树 ${step.value}，user-config ${proof.merkleRoot}`;
    default:
      return `步骤 ${step.kind} 未通过`;
  }
}

async function verifyUser(treePath: string, userPath: string): Promise<void> {
  const proof = toMyProof(await loadJson(userPath, '个人证明文件'));
  console.log(`读取个人证明: ${userPath}（snapshotId=${JSON.stringify(proof.snapshotId)}, leafIndex=${proof.leafIndex}, leafCount=${proof.leafCount}, 路径长度=${proof.proof.length}）`);

  let publishedRoot: string | null = null;
  try {
    const tree = asObject(await loadJson(treePath, '公开树文件'), treePath);
    publishedRoot = asHex64(tree.merkleRoot, 'merkleRoot');
    console.log(`公开树文件: ${treePath}，merkleRoot = ${publishedRoot}`);
  } catch (err) {
    if (!(err instanceof MissingFileError)) throw err;
    console.log(`提示: ${err.message}`);
    console.log('提示: 未与公开树文件交叉比对，仅按 user-config 自带的 merkleRoot 校验。');
  }

  const report = await verifyProof(proof, publishedRoot);
  const failed = report.steps.find(step => step.ok === false);
  if (failed) throw new CheckError(describeFailure(failed, proof));
  if (!report.ok) throw new CheckError('存在未通过的校验步骤');

  console.log(`逐步校验通过（balancesText → balancesHash → leafHash → 路径 ${proof.proof.length} 层 → 根）`);
  console.log(`leafIndex=${proof.leafIndex}, leafCount=${proof.leafCount}`);
  console.log(SUCCESS_LINE);
}

async function main(): Promise<void> {
  const options = parseArgs(process.argv.slice(2));
  if (options.sub === 'help') {
    console.log(usage());
    return;
  }
  if (options.sub === 'cex') {
    await verifyCex(options.treePath);
  } else {
    await verifyUser(options.treePath, options.userPath);
  }
}

main().catch((err: unknown) => {
  const message = err instanceof Error ? err.message : String(err);
  if (err instanceof CheckError) console.log(`校验失败: ${message}`);
  else console.error(`错误: ${message}`);
  process.exitCode = 1;
});
