![BCB FX Proof of Reserves](docs/assets/bcb-fx-proof-of-reserves.png)

# BCB FX Proof of Reserves

BCB FX 储备金证明的公开验证代码。用户可以在浏览器本地重算自己的 Merkle 叶子及证明路径，并与公开树根比较，无需把个人证明数据交给第三方验证服务。

在线页面：https://qovf.cn/proof-of-reserves

## 当前证明格式：v1

- 用户标识：服务端使用带密钥的 HMAC-SHA256 生成 32 字节 `uidHash`，密钥不进入本仓库。
- 余额文本：按币种字典序排列，格式为 `ASSET=amount`，金额固定 18 位小数，以分号连接。
- 余额哈希：`SHA-256(UTF-8(balancesText))`。
- 叶子：`SHA-256(0x00 || uidHash || balancesHash)`。
- 内部节点：`SHA-256(0x01 || left || right)`。
- 奇数节点：复制当前层最后一个节点。
- 金额在浏览器中始终使用十进制字符串，不通过 JavaScript `number` 参与计算。

TypeScript 浏览器验证器位于 `src/reservesProof.ts`，对应的 Java 17 实现位于 `server/src/main/java/com/qovf/service/reserves/`。

## 储备地址边界

只有独立配置的金库地址（`VAULT`）可以计入链上储备。用户充值或平台收款地址（`WALLET`）不属于储备证明，不得用于补足储备金额。

客户负债与 Merkle 根对应同一快照；公开储备金额根据独立金库的最新可用余额缓存同步汇总。无法查询、过期或证据不完整的余额必须标为未知，不能按零处理，也不能继续沿用旧值。

## 验证范围

本仓库当前实现 **SHA-256 Merkle 包含证明**。个人验证用于确认某个余额叶子被包含在公开树根中；链上储备与客户负债的覆盖关系可结合金库地址和资产快照核对。

仓库不包含生产地址、用户数据、数据库配置、密钥或证明私钥。

## 运行验证

要求 Node.js 24.22.1 或更高的 24.x，以及 Java 17。

```bash
pnpm test
```

```bash
mkdir -p build
javac -d build \
  server/src/main/java/com/qovf/service/reserves/*.java \
  server/src/test/java/com/qovf/service/reserves/MerkleTreeSelfTest.java
java -cp build com.qovf.service.reserves.MerkleTreeSelfTest
```

测试覆盖标准向量、余额篡改、兄弟节点及方向篡改、公开根不一致和 Java 基础树验证。
