package SilverPohligHellman;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.*;

public class DH_SPH_Demo_Fallback {
    static final SecureRandom rnd = new SecureRandom();

    // ---------- integer sqrt ----------
    public static BigInteger integerSqrt(BigInteger n) {
        if (n.signum() < 0) throw new ArithmeticException("sqrt of negative");
        if (n.equals(BigInteger.ZERO) || n.equals(BigInteger.ONE)) return n;
        BigInteger two = BigInteger.valueOf(2);
        BigInteger x0 = n.shiftRight(n.bitLength() / 2);
        BigInteger x1 = x0.add(n.divide(x0)).divide(two);
        while (x1.compareTo(x0) < 0) {
            x0 = x1;
            x1 = x0.add(n.divide(x0)).divide(two);
        }
        return x0;
    }

    // ---------- Baby-step Giant-step ----------
    // Solve g^x = h (mod p) for x in [0, order-1] or return null
    public static BigInteger babyStepGiantStep(BigInteger g, BigInteger h, BigInteger p, BigInteger order) {
        BigInteger m = integerSqrt(order);
        if (m.multiply(m).compareTo(order) < 0) m = m.add(BigInteger.ONE);

        int mInt;
        try {
            mInt = m.intValueExact();
        } catch (ArithmeticException ex) {
            throw new IllegalArgumentException("Order too large for BSGS");
        }

        Map<BigInteger, Integer> table = new HashMap<>(Math.max(16, mInt * 2));
        BigInteger baby = BigInteger.ONE;
        for (int j = 0; j < mInt; j++) {
            table.putIfAbsent(baby, j);
            baby = baby.multiply(g).mod(p);
        }

        BigInteger gPowM = g.modPow(m, p);
        BigInteger gPowMInv;
        try {
            gPowMInv = gPowM.modInverse(p);
        } catch (ArithmeticException ex) {
            return null;
        }

        BigInteger cur = h;
        for (int i = 0; i <= mInt; i++) {
            Integer j = table.get(cur);
            if (j != null) {
                BigInteger ans = BigInteger.valueOf(i).multiply(m).add(BigInteger.valueOf(j));
                return ans.mod(order);
            }
            cur = cur.multiply(gPowMInv).mod(p);
        }
        return null;
    }

    // ---------- Trial factor small primes ----------
    public static Map<BigInteger, Integer> factorSmooth(BigInteger n, List<Integer> smallPrimes) {
        BigInteger rem = n;
        Map<BigInteger, Integer> fac = new LinkedHashMap<>();
        for (int pr : smallPrimes) {
            BigInteger bp = BigInteger.valueOf(pr);
            int cnt = 0;
            while (rem.mod(bp).equals(BigInteger.ZERO)) {
                rem = rem.divide(bp);
                cnt++;
            }
            if (cnt > 0) fac.put(bp, cnt);
            if (rem.equals(BigInteger.ONE)) break;
        }
        if (!rem.equals(BigInteger.ONE)) fac.put(rem, 1);
        return fac;
    }

    // ---------- CRT ----------
    public static BigInteger crtCombine(List<BigInteger> residues, List<BigInteger> moduli) {
        BigInteger M = BigInteger.ONE;
        for (BigInteger mi : moduli) M = M.multiply(mi);
        BigInteger result = BigInteger.ZERO;
        for (int i = 0; i < residues.size(); i++) {
            BigInteger ai = residues.get(i);
            BigInteger mi = moduli.get(i);
            BigInteger Mi = M.divide(mi);
            BigInteger ti = Mi.modInverse(mi);
            result = result.add(Mi.multiply(ti).multiply(ai));
        }
        return result.mod(M);
    }

    // ---------- SPH with fallback ----------
    public static BigInteger silverPohligHellman(BigInteger g, BigInteger h, BigInteger p, BigInteger n, Map<BigInteger, Integer> factorization) {
        List<BigInteger> residues = new ArrayList<>();
        List<BigInteger> moduli = new ArrayList<>();

        for (Map.Entry<BigInteger, Integer> ent : factorization.entrySet()) {
            BigInteger q = ent.getKey();
            int e = ent.getValue();
            System.out.println("Solving for prime-power q=" + q + " ^ " + e);

            // constant base for this prime q:
            BigInteger g1 = g.modPow(n.divide(q), p);
            if (!g1.modPow(q, p).equals(BigInteger.ONE)) {
                System.err.println("WARNING: g1^q != 1 for q=" + q + " (g1 may not have order q). Continuing but results may be invalid.");
            }

            BigInteger x = BigInteger.ZERO;
            for (int k = 0; k < e; k++) {
                BigInteger gx = g.modPow(x, p);
                BigInteger gxInv = gx.modInverse(p);
                BigInteger c = h.multiply(gxInv).mod(p);
                BigInteger rhs = c.modPow(n.divide(q.pow(k + 1)), p);

                // Try BSGS
                BigInteger d = null;
                try {
                    d = babyStepGiantStep(g1, rhs, p, q);
                } catch (Exception ex) {
                    // bubble up as runtime with context
                    throw new RuntimeException("BSGS exception for q=" + q + " at stage k=" + k + ": " + ex.getMessage(), ex);
                }

                // If BSGS returns null and q is small, do linear brute force
                if (d == null) {
                    int qInt;
                    try {
                        qInt = q.intValueExact();
                    } catch (ArithmeticException ex) { qInt = Integer.MAX_VALUE; }

                    if (qInt <= 10000) { // fallback threshold (safe to adjust)
                        // brute force: compute g1^t for t=0..q-1
                        BigInteger cur = BigInteger.ONE;
                        boolean found = false;
                        for (int t = 0; t < qInt; t++) {
                            if (cur.equals(rhs)) {
                                d = BigInteger.valueOf(t);
                                found = true;
                                break;
                            }
                            cur = cur.multiply(g1).mod(p);
                        }
                        if (!found) {
                            String msg = "Brute-force also failed for q=" + q + " at stage k=" + k + ".\n" +
                                    "g1 = " + g1 + "\n" +
                                    "rhs = " + rhs + "\n" +
                                    "Try regenerate g or include missing factors of p-1.";
                            throw new RuntimeException(msg);
                        } else {
                            System.out.println("  BSGS failed but brute-force found d=" + d + " for q=" + q + " at stage k=" + k);
                        }
                    } else {
                        String msg = "BSGS returned null for q=" + q + " at stage k=" + k + " and q is large (" + q + ").\n" +
                                "Consider using Pollard Rho DLP or improving factorization.";
                        throw new RuntimeException(msg);
                    }
                }

                x = x.add(d.multiply(q.pow(k)));
            }

            residues.add(x.mod(q.pow(e)));
            moduli.add(q.pow(e));
            System.out.println("  => x (mod " + q.pow(e) + ") = " + x.mod(q.pow(e)));
        }

        BigInteger X = crtCombine(residues, moduli);
        return X.mod(n);
    }

    // ---------- Simple smooth prime generator ----------
    public static BigInteger generateSmoothPrime(int bits, int smallPrimeBound, int maxAttempts) {
        List<Integer> smallPrimes = sievePrimes(smallPrimeBound);
        SecureRandom r = new SecureRandom();

        for (int attempt = 0; attempt < maxAttempts; attempt++) {
            BigInteger n = BigInteger.ONE;
            Collections.shuffle(smallPrimes, r);
            for (int pr : smallPrimes) {
                BigInteger bp = BigInteger.valueOf(pr);
                int e = 1 + r.nextInt(2);
                for (int k = 0; k < e; k++) {
                    n = n.multiply(bp);
                    if (n.bitLength() >= bits - 16) break;
                }
                if (n.bitLength() >= bits - 16) break;
            }
            int maxK = 4000;
            for (int k = 2; k < maxK; k++) {
                BigInteger candidate = n.multiply(BigInteger.valueOf(k)).add(BigInteger.ONE);
                if (candidate.bitLength() != bits) continue;
                if (candidate.isProbablePrime(60)) return candidate;
            }
        }
        throw new RuntimeException("generateSmoothPrime: no candidate found");
    }

    public static List<Integer> sievePrimes(int bound) {
        boolean[] isComp = new boolean[bound + 1];
        List<Integer> primes = new ArrayList<>();
        for (int i = 2; i <= bound; i++) {
            if (!isComp[i]) {
                primes.add(i);
                if ((long)i * i <= bound) {
                    for (int j = i * i; j <= bound; j += i) isComp[j] = true;
                }
            }
        }
        return primes;
    }

    public static boolean isGeneratorForFactors(BigInteger g, BigInteger p, Set<BigInteger> primeFactors) {
        BigInteger phi = p.subtract(BigInteger.ONE);
        for (BigInteger q : primeFactors) {
            if (q.equals(BigInteger.ONE)) continue;
            BigInteger exp = phi.divide(q);
            if (g.modPow(exp, p).equals(BigInteger.ONE)) return false;
        }
        return true;
    }

    // ---------- Demo ----------
    public static void main(String[] args) {
        int bits = 512;               // set to 1024 for real lab (slower)
        int smallPrimeBound = 1000;
        System.out.println("Generating p (" + bits + "-bit) with smooth p-1 (primes up to " + smallPrimeBound + ") ...");
        BigInteger p = generateSmoothPrime(bits, smallPrimeBound, 60);
        System.out.println("Found p (bitlen=" + p.bitLength() + ")");

        BigInteger n = p.subtract(BigInteger.ONE);
        List<Integer> smalls = sievePrimes(smallPrimeBound);
        Map<BigInteger, Integer> fac = factorSmooth(n, smalls);

        System.out.println("Partial factorization of p-1:");
        for (Map.Entry<BigInteger, Integer> e : fac.entrySet()) {
            System.out.println("  " + e.getKey() + " ^ " + e.getValue());
        }

        Set<BigInteger> primeFactors = new LinkedHashSet<>(fac.keySet());

        // find g nontrivial on those prime factors
        BigInteger g = null;
        int tries = 0;
        while (true) {
            tries++;
            BigInteger cand = new BigInteger(p.bitLength() - 1, rnd).mod(p.subtract(BigInteger.ONE)).add(BigInteger.TWO);
            if (isGeneratorForFactors(cand, p, primeFactors)) {
                g = cand;
                break;
            }
            if (tries > 20000) throw new RuntimeException("Failed to find suitable g");
        }
        System.out.println("Selected g after " + tries + " attempts.");

        BigInteger a = new BigInteger(bits / 4, rnd);
        BigInteger A = g.modPow(a, p);
        System.out.println("Public A computed.");

        System.out.println("Attacker: running SPH...");
        BigInteger recovered;
        try {
            recovered = silverPohligHellman(g, A, p, n, fac);
        } catch (RuntimeException ex) {
            System.err.println("SPH failed: " + ex.getMessage());
            ex.printStackTrace();
            return;
        }
        System.out.println("Recovered a (mod p-1) = " + recovered);
        System.out.println("Original a mod p-1 = " + a.mod(n));
        System.out.println("Equality: " + recovered.equals(a.mod(n)));

        BigInteger b = new BigInteger(bits / 4, rnd);
        BigInteger B = g.modPow(b, p);
        BigInteger sLegit = B.modPow(a, p);
        BigInteger sRec = B.modPow(recovered, p);
        System.out.println("Shared secret match? " + sLegit.equals(sRec));
    }
}
