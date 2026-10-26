package com.qovf.service.reserves;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

/**
 * Merkle tree (SHA-256) for proof of reserves.
 *
 * Rules (the browser side {@code shared/utils/reservesProof.ts} must match byte for byte; change both together):
 * <ul>
 *   <li>leaf          = SHA-256(0x00 ‖ user identifier hash(32B) ‖ balance hash(32B))</li>
 *   <li>inner node = SHA-256(0x01 ‖ left(32B) ‖ right(32B))</li>
 *   <li>when a level has an odd number of nodes, the last node pairs with itself (duplicated)</li>
 *   <li>root of an empty tree = SHA-256("qovf-por:empty")</li>
 * </ul>
 * The 0x00 / 0x01 prefixes separate leaves from inner nodes, preventing an inner node from being passed off as a leaf (second preimage attack).
 */
public final class MerkleTree {

    private static final HexFormat HEX = HexFormat.of();
    private static final byte LEAF_PREFIX = 0x00;
    private static final byte NODE_PREFIX = 0x01;

    /** Whether the sibling is on the left ("L") or the right ("R"). */
    public record Step(boolean siblingOnLeft, String siblingHex) {
        public String encode() {
            return (siblingOnLeft ? "L:" : "R:") + siblingHex;
        }

        public static Step decode(String text) {
            if (text.length() != 66 || text.charAt(1) != ':' || (text.charAt(0) != 'L' && text.charAt(0) != 'R')) {
                throw new IllegalArgumentException("bad proof step");
            }
            return new Step(text.charAt(0) == 'L', text.substring(2));
        }
    }

    private final List<List<byte[]>> levels;

    private MerkleTree(List<List<byte[]>> levels) {
        this.levels = levels;
    }

    /** The order of leafHashes is the leaf index; the caller is responsible for sorting first. */
    public static MerkleTree build(List<byte[]> leafHashes) {
        List<List<byte[]>> levels = new ArrayList<>();
        List<byte[]> level = new ArrayList<>(leafHashes);
        levels.add(level);
        while (level.size() > 1) {
            List<byte[]> next = new ArrayList<>((level.size() + 1) / 2);
            for (int i = 0; i < level.size(); i += 2) {
                byte[] left = level.get(i);
                byte[] right = i + 1 < level.size() ? level.get(i + 1) : left;
                next.add(hashNode(left, right));
            }
            levels.add(next);
            level = next;
        }
        return new MerkleTree(levels);
    }

    public int leafCount() {
        return levels.get(0).size();
    }

    /** Number of levels (excluding the leaf level): 0 for a single-leaf tree. */
    public int depth() {
        return levels.size() - 1;
    }

    public String rootHex() {
        if (leafCount() == 0) {
            return HEX.formatHex(sha256("qovf-por:empty".getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        }
        return HEX.formatHex(levels.get(levels.size() - 1).get(0));
    }

    /** Sibling path from the leaf up to the root. */
    public List<Step> proof(int leafIndex) {
        if (leafIndex < 0 || leafIndex >= leafCount()) {
            throw new IndexOutOfBoundsException("leaf " + leafIndex);
        }
        List<Step> steps = new ArrayList<>();
        int index = leafIndex;
        for (int l = 0; l < levels.size() - 1; l++) {
            List<byte[]> level = levels.get(l);
            boolean isRight = (index & 1) == 1;
            int sibling = isRight ? index - 1 : index + 1;
            byte[] hash = sibling < level.size() ? level.get(sibling) : level.get(index);
            steps.add(new Step(isRight, HEX.formatHex(hash)));
            index >>= 1;
        }
        return steps;
    }

    public static boolean verify(String leafHex, List<Step> proof, String rootHex) {
        byte[] current = HEX.parseHex(leafHex);
        for (Step step : proof) {
            byte[] sibling = HEX.parseHex(step.siblingHex());
            current = step.siblingOnLeft() ? hashNode(sibling, current) : hashNode(current, sibling);
        }
        return HEX.formatHex(current).equals(rootHex);
    }

    public static byte[] hashLeaf(byte[] uidHash, byte[] balancesHash) {
        return sha256(new byte[]{LEAF_PREFIX}, uidHash, balancesHash);
    }

    public static byte[] hashNode(byte[] left, byte[] right) {
        return sha256(new byte[]{NODE_PREFIX}, left, right);
    }

    static byte[] sha256(byte[]... parts) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            for (byte[] part : parts) {
                digest.update(part);
            }
            return digest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
