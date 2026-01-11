import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

public class RSACryptoanalysisDemo {

    static SecureRandom rnd = new SecureRandom();

    // =========================
    // MAIN
    // =========================
    public static void main(String[] args) {

        System.out.println("=== RSA CRYPTOANALYSIS DEMO ===\n");

        // Generate weak RSA
        RSAKey key = generateWeakRSA(512);

        System.out.println("Public key:");
        System.out.println("n = " + key.n);
        System.out.println("e = " + key.e);
        System.out.println("\nPrivate key:");
        System.out.println("d = " + key.d);

        // -------------------------
        // WIENER ATTACK
        // -------------------------
        System.out.println("\n=== WIENER ATTACK ===");
        BigInteger recoveredD = wienerAttack(key.e, key.n);

        if (recoveredD != null) {
            System.out.println("Recovered d = " + recoveredD);
        } else {
            System.out.println("Wiener attack failed");
        }

        // -------------------------
        // LENSTRA ATTACK
        // -------------------------
        System.out.println("\n=== LENSTRA ATTACK (CRT FAULT) ===");

        BigInteger message = new BigInteger("42");
        BigInteger correct = crtDecrypt(message, key, false);
        BigInteger faulty  = crtDecrypt(message, key, true);

        BigInteger p = key.n.gcd(correct.subtract(faulty).abs());
        BigInteger q = key.n.divide(p);

        System.out.println("Recovered p = " + p);
        System.out.println("Recovered q = " + q);
    }

    // =========================
    // RSA KEY
    // =========================
    static class RSAKey {
        BigInteger p, q, n, phi, e, d;
    }

    // =========================
    // WEAK RSA GENERATION
    // =========================
    static RSAKey generateWeakRSA(int bits) {
        RSAKey k = new RSAKey();

        k.p = BigInteger.probablePrime(bits / 2, rnd);
        k.q = BigInteger.probablePrime(bits / 2, rnd);
        k.n = k.p.multiply(k.q);
        k.phi = k.p.subtract(BigInteger.ONE).multiply(k.q.subtract(BigInteger.ONE));

        // SMALL d (Wiener vulnerable)
        do {
            k.d = new BigInteger(bits / 4, rnd);
        } while (!k.d.gcd(k.phi).equals(BigInteger.ONE));

        k.e = k.d.modInverse(k.phi);
        return k;
    }

    // =========================
    // WIENER ATTACK
    // =========================
    static BigInteger wienerAttack(BigInteger e, BigInteger n) {
        List<BigInteger> cf = continuedFraction(e, n);
        List<BigInteger[]> conv = convergents(cf);

        for (BigInteger[] f : conv) {
            BigInteger k = f[0];
            BigInteger d = f[1];

            if (k.equals(BigInteger.ZERO)) continue;

            BigInteger phiCand = e.multiply(d).subtract(BigInteger.ONE);
            if (!phiCand.mod(k).equals(BigInteger.ZERO)) continue;

            phiCand = phiCand.divide(k);
            BigInteger b = n.subtract(phiCand).add(BigInteger.ONE);
            BigInteger disc = b.multiply(b).subtract(n.shiftLeft(2));

            if (disc.signum() < 0) continue;
            BigInteger s = sqrt(disc);

            if (s.multiply(s).equals(disc)) return d;
        }
        return null;
    }

    static List<BigInteger> continuedFraction(BigInteger a, BigInteger b) {
        List<BigInteger> res = new ArrayList<>();
        while (!b.equals(BigInteger.ZERO)) {
            res.add(a.divide(b));
            BigInteger t = a.mod(b);
            a = b;
            b = t;
        }
        return res;
    }

    static List<BigInteger[]> convergents(List<BigInteger> cf) {
        List<BigInteger[]> res = new ArrayList<>();

        BigInteger h1 = BigInteger.ONE, h2 = BigInteger.ZERO;
        BigInteger k1 = BigInteger.ZERO, k2 = BigInteger.ONE;

        for (BigInteger a : cf) {
            BigInteger h = a.multiply(h1).add(h2);
            BigInteger k = a.multiply(k1).add(k2);
            res.add(new BigInteger[]{h, k});

            h2 = h1; h1 = h;
            k2 = k1; k1 = k;
        }
        return res;
    }

    static BigInteger sqrt(BigInteger x) {
        BigInteger r = BigInteger.ZERO;
        BigInteger bit = BigInteger.ONE.shiftLeft(x.bitLength() / 2 + 1);

        while (bit.signum() > 0) {
            BigInteger t = r.add(bit);
            if (t.multiply(t).compareTo(x) <= 0) r = t;
            bit = bit.shiftRight(1);
        }
        return r;
    }

    // =========================
    // CRT DECRYPTION (LENSTRA)
    // =========================
    static BigInteger crtDecrypt(BigInteger m, RSAKey k, boolean fault) {
        BigInteger dp = k.d.mod(k.p.subtract(BigInteger.ONE));
        BigInteger dq = k.d.mod(k.q.subtract(BigInteger.ONE));

        BigInteger mp = m.modPow(dp, k.p);
        BigInteger mq = m.modPow(dq, k.q);

        if (fault) {
            // simulate hardware fault
            mp = mp.add(BigInteger.ONE).mod(k.p);
        }

        BigInteger qInv = k.q.modInverse(k.p);
        BigInteger h = qInv.multiply(mp.subtract(mq)).mod(k.p);
        return mq.add(h.multiply(k.q));
    }
}

