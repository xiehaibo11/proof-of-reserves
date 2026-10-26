package com.qovf.service.reserves;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.Map;
import java.util.TreeMap;

/**
 * Canonical format of the leaf input.
 *
 * <pre>
 *   uidHash       = HMAC-SHA256(key, "uid:" + userId)                  (hex, 64 characters)
 *   balancesText  = "ASSET=amount;ASSET=amount…", coins in lexicographic order, amounts with a fixed 18 decimal places and no scientific notation
 *   balancesHash  = SHA-256(UTF-8 of balancesText)                        (hex)
 *   leafHash      = SHA-256(0x00 ‖ raw bytes of uidHash ‖ raw bytes of balancesHash)
 * </pre>
 * The user identifier uses a keyed hash: user IDs are consecutive auto-increment numbers, and a bare hash can be reversed by enumeration;
 * the key stays server-side only, so the published tree root does not leak anyone's ID or balance.
 */
public final class ReserveLeafFormat {

    public static final int AMOUNT_SCALE = 18;
    private static final HexFormat HEX = HexFormat.of();

    private ReserveLeafFormat() {
    }

    public record Leaf(String uidHash, String balancesText, String balancesHash, String leafHash) {
    }

    public static String uidHash(byte[] secret, long userId) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret, "HmacSHA256"));
            return HEX.formatHex(mac.doFinal(("uid:" + userId).getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static String balancesText(Map<String, BigDecimal> balances) {
        StringBuilder out = new StringBuilder();
        for (Map.Entry<String, BigDecimal> e : new TreeMap<>(balances).entrySet()) {
            if (out.length() > 0) {
                out.append(';');
            }
            out.append(e.getKey()).append('=').append(amount(e.getValue()));
        }
        return out.toString();
    }

    /** Fixed 18 decimal places; extra digits raise an error instead of being silently truncated. */
    public static String amount(BigDecimal value) {
        return value.setScale(AMOUNT_SCALE, RoundingMode.UNNECESSARY).toPlainString();
    }

    public static Leaf leaf(String uidHash, Map<String, BigDecimal> balances) {
        String text = balancesText(balances);
        byte[] balancesHash = MerkleTree.sha256(text.getBytes(StandardCharsets.UTF_8));
        byte[] leaf = MerkleTree.hashLeaf(HEX.parseHex(uidHash), balancesHash);
        return new Leaf(uidHash, text, HEX.formatHex(balancesHash), HEX.formatHex(leaf));
    }
}
