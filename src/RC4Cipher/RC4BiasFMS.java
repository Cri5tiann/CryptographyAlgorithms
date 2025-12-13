package RC4Cipher;

import java.security.SecureRandom;
import java.sql.SQLOutput;
import java.util.*;

public class RC4BiasFMS {

    /* RC4 implementation */
    public static class RC4 {
        private final int[] S = new int[256];
        private int i = 0;
        private int j = 0;

        public RC4(byte[] key) {
            ksa(key);
        }

        private void ksa(byte[] key) {
            int keylen = key.length;
            for (int idx = 0; idx < 256; idx++) S[idx] = idx;
            int jLocal = 0;
            for (int idx = 0; idx < 256; idx++) {
                int k = key[idx % keylen] & 0xFF;
                jLocal = (jLocal + S[idx] + k) & 0xFF;
                int tmp = S[idx];
                S[idx] = S[jLocal];
                S[jLocal] = tmp;
            }
            this.i = 0;
            this.j = 0;
        }

        public int nextByte() {
            i = (i + 1) & 0xFF;
            j = (j + S[i]) & 0xFF;
            int tmp = S[i];
            S[i] = S[j];
            S[j] = tmp;
            int t = (S[i] + S[j]) & 0xFF;
            return S[t];
        }

        public int[] nextBytes(int n) {
            int[] out = new int[n];
            for (int k = 0; k < n; k++) out[k] = nextByte();
            return out;
        }
    }

    /*  Bias experiment */
    public static class BiasExperiment {
        private final SecureRandom rnd = new SecureRandom();

        private byte[] randomKey(int length) {
            byte[] k = new byte[length];
            rnd.nextBytes(k);
            return k;
        }

        public void run(long numKeys, int keyLen) {
            System.out.printf("Running bias experiment: %d keys, key length=%d bytes%n", numKeys, keyLen);
            long[] freq = new long[256];

            for (long t = 0; t < numKeys; t++) {
                byte[] key = randomKey(keyLen);
                RC4 rc4 = new RC4(key);
                rc4.nextByte(); // discard first
                int second = rc4.nextByte();
                freq[second]++;
            }

            // Top 10
            System.out.println("Top 10 values for the 2nd keystream byte:");
            List<Integer> vals = new ArrayList<>();
            for (int v = 0; v < 256; v++) vals.add(v);
            vals.sort((a, b) -> Long.compare(freq[b], freq[a]));
            for (int k = 0; k < 10; k++) {
                int v = vals.get(k);
                System.out.printf("  0x%02X : %d%n", v, freq[v]);
            }

            double expected = (double) numKeys / 256.0;
            double variance = numKeys * (1.0/256.0) * (255.0/256.0);
            double stddev = Math.sqrt(variance);
            //System.out.printf("Uniform expectation: %.3f ± %.3f (mean ± stddev)%n", expected, stddev);
            System.out.println();
        }
    }

    public static class WEPSimulator {
        private final SecureRandom rnd = new SecureRandom();
        private final byte[] secretKey; // secret key bytes
        private final int ivLength = 3;

        public WEPSimulator(int secretKeyLen) {
            secretKey = new byte[secretKeyLen];
            rnd.nextBytes(secretKey);
        }

        public byte[] getSecretKey() {
            return secretKey.clone();
        }


        private byte[] randomIV() {
            byte[] iv = new byte[3];
            rnd.nextBytes(iv);
            return iv;
        }

        public Capture generateCapture(byte[] iv) {
            byte[] key = new byte[ivLength + secretKey.length];
            System.arraycopy(iv, 0, key, 0, ivLength);
            System.arraycopy(secretKey, 0, key, ivLength, secretKey.length);
            RC4 rc4 = new RC4(key);
            int ks0 = rc4.nextByte(); // first keystream byte
            return new Capture(iv.clone(), ks0 & 0xFF);
        }

        public List<Capture> generateCaptures(int total, double weakIvFraction) {
            List<Capture> captures = new ArrayList<>(total);
            int numWeak = (int)Math.round(total * weakIvFraction);
            for (int i = 0; i < numWeak; i++) {
                byte[] iv = new byte[3];
                iv[0] = 3;
                iv[1] = (byte)0xFF;
                iv[2] = (byte)(rnd.nextInt(256));
                captures.add(generateCapture(iv));
            }
            for (int i = 0; i < total - numWeak; i++) {
                captures.add(generateCapture(randomIV()));
            }
            Collections.shuffle(captures, rnd);
            return captures;
        }
    }

    public static class Capture {
        public final byte[] iv; // 3 bytes
        public final int ks0;

        public Capture(byte[] iv, int ks0) {
            this.iv = iv;
            this.ks0 = ks0;
        }
    }

    public static class FMSAttack {

        public static LinkedHashMap<Integer, Integer> recoverFirstSecretByte(List<Capture> captures) {
            int[] votes = new int[256];

            for (Capture cap : captures) {
                // classic weak IV pattern (3,255,x)
                int iv0 = cap.iv[0] & 0xFF;
                int iv1 = cap.iv[1] & 0xFF;
                if (!(iv0 == 3 && iv1 == 0xFF)) continue;

                int[] S = new int[256];
                for (int i = 0; i < 256; i++) S[i] = i;
                int j = 0;

                for (int i = 0; i <= 2; i++) {
                    int keyByte = cap.iv[i] & 0xFF;
                    j = (j + S[i] + keyByte) & 0xFF;
                    // swap
                    int tmp = S[i];
                    S[i] = S[j];
                    S[j] = tmp;
                }

                int O = cap.ks0 & 0xFF;
                int S3 = S[3] & 0xFF;
                int candidate = (O - j - S3) & 0xFF;
                votes[candidate]++;
            }

            List<Integer> order = new ArrayList<>();
            for (int c = 0; c < 256; c++) order.add(c);
            order.sort((a, b) -> Integer.compare(votes[b], votes[a]));

            LinkedHashMap<Integer, Integer> sorted = new LinkedHashMap<>();
            for (int c : order) sorted.put(c, votes[c]);
            return sorted;
        }
    }

    /* Main demo runner */
    public static void main(String[] args) {

        BiasExperiment be = new BiasExperiment();
        be.run(100000, 8);

        int secretLen = 5;
        int totalCaptures = 10000;      // total synthetic packets
        double weakFraction = 0.05;        // fraction of IVs that are weak (3,255,x)

        System.out.printf("%nWEP simulator: secretLen=%d, totalCaptures=%d, weakFraction=%.2f%n",
                secretLen, totalCaptures, weakFraction);

        WEPSimulator sim = new WEPSimulator(secretLen);
        byte[] secret = sim.getSecretKey();
        System.out.print("Secret key (hex) = ");
        for (byte b : secret) System.out.printf("%02X", b & 0xFF);
        System.out.println();

        List<Capture> captures = sim.generateCaptures(totalCaptures, weakFraction);
        long weakCount = captures.stream().filter(c -> (c.iv[0] & 0xFF) == 3 && (c.iv[1] & 0xFF) == 0xFF).count();
        System.out.printf("Captured %d packets, of which %d are (3,255,x) weak IVs%n", captures.size(), weakCount);

        LinkedHashMap<Integer, Integer> votes = FMSAttack.recoverFirstSecretByte(captures);

        System.out.println("Top candidates for first secret byte (valoare : voturi):");
        int shown = 0;
        int trueFirst = secret[0] & 0xFF;
        for (Map.Entry<Integer, Integer> e : votes.entrySet()) {
            if (shown >= 8) break;
            int cand = e.getKey();
            int v = e.getValue();
            String mark = (cand == trueFirst) ? "" : "";
            System.out.printf("  0x%02X : %d%s%n", cand, v, mark);
            shown++;
        }

        // Report final decision (highest vote)
        int best = votes.entrySet().iterator().next().getKey();
        System.out.printf("%nFMS recovered first secret byte = 0x%02X ; actual = 0x%02X%n",
                best, trueFirst);
        if (best == trueFirst) {
            System.out.println("SUCCESS: recovered the correct first secret byte!");
        } else {
            System.out.println("NOTE: failed to recover the correct byte. Increase captures, weakFraction, or seed randomness.");
        }

        System.out.println("\nDone.");
    }
}
