package com.qovf.service.reserves;

import java.nio.charset.StandardCharsets;
import java.util.List;

/** Dependency-free smoke test; run with Java 17 as documented in README. */
public final class MerkleTreeSelfTest {
    private static byte[] leaf(String text) {
        return MerkleTree.sha256(text.getBytes(StandardCharsets.UTF_8));
    }

    public static void main(String[] args) {
        var tree = MerkleTree.build(List.of(leaf("a"), leaf("b"), leaf("c")));
        String expected = "7d49b39582357c19ef3691b619e56418c7a9da4c592cfc980e76ad6c3f3b7884";
        if (!expected.equals(tree.rootHex())) throw new AssertionError("root mismatch");
        for (int i = 0; i < 3; i++) {
            if (!MerkleTree.verify(java.util.HexFormat.of().formatHex(List.of(leaf("a"), leaf("b"), leaf("c")).get(i)), tree.proof(i), expected)) {
                throw new AssertionError("proof mismatch at " + i);
            }
        }
        if (MerkleTree.verify(java.util.HexFormat.of().formatHex(leaf("x")), tree.proof(0), expected)) {
            throw new AssertionError("tampered leaf accepted");
        }
        System.out.println("BCB FX MerkleTree self-test passed");
    }
}
