package ModernCiphers;

import java.util.*;
import java.security.SecureRandom;


public class DES2_MITM {

    // --- Tables (IP, FP, E, S-boxes, P, PC1, PC2, SHIFTS) ---
    private static final int[] IP = {58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7};
    private static final int[] FP = {40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25};
    private static final int[] E = {32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1};
    private static final int[][][] S = {
            {{14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},{0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},{4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},{15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}},
            {{15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},{3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},{0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},{13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}},
            {{10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},{13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},{13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},{1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}},
            {{7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},{13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},{10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},{3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}},
            {{2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},{14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},{4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},{11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}},
            {{12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},{10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},{9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},{4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}},
            {{4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},{13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},{1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},{6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}},
            {{13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},{1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},{7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},{2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}}
    };
    private static final int[] P = {16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25};
    private static final int[] PC1 = {57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36,63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4};
    private static final int[] PC2 = {14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32};
    private static final int[] SHIFTS = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};

    // --- Bit helpers ---
    private static int getBit64(long val, int pos) { return (int)((val >>> (64 - pos)) & 1L); }
    private static long bytesToLong(byte[] b) { long v=0L; for(int i=0;i<8;i++) v=(v<<8)|(b[i]&0xFFL); return v; }
    private static byte[] longToBytes(long v){ byte[] b=new byte[8]; for(int i=7;i>=0;i--){ b[i]=(byte)(v&0xFF); v>>>=8;} return b; }
    private static int getBit32(int val,int pos){ return (val >>> (32-pos)) & 1; }

    private static long expand32to48(int r){ long out=0L; for(int i=0;i<E.length;i++){ int bit=getBit32(r,E[i]); if(bit==1) out |= (1L << (47 - i)); } return out; }
    private static int sBoxes(long in48){ int out=0; for(int i=0;i<8;i++){ int shift=42-6*i; int six=(int)((in48>>>shift)&0x3F); int row = ((six & 0x20)>>>4) | (six & 0x01); int col=(six>>>1)&0x0F; int sVal=S[i][row][col] & 0x0F; out=(out<<4)|sVal; } return out; }
    private static int permuteP(int in32){ int out=0; for(int i=0;i<P.length;i++){ int bit=getBit32(in32,P[i]); if(bit==1) out |= (1 << (31 - i)); } return out; }

    private static byte setOddParity(byte b){ int unsigned=b&0xFF; int ones=Integer.bitCount(unsigned>>>1); int desired=(ones%2==0)?1:0; unsigned=(unsigned&0xFE)|desired; return (byte)unsigned; }
    public static byte[] makeDESKeyFromByte(byte seed){ byte[] k=new byte[8]; for(int i=0;i<8;i++) k[i]=seed; for(int i=0;i<8;i++) k[i]=setOddParity(k[i]); return k; }

    private static long[] generateSubkeys(byte[] keyBytes){ long key64 = bytesToLong(keyBytes); int[] cd = new int[56]; for(int i=0;i<56;i++) cd[i]=getBit64(key64, PC1[i]); int c=0,d=0; for(int i=0;i<28;i++) if(cd[i]==1) c |= (1 << (27 - i)); for(int i=0;i<28;i++) if(cd[28+i]==1) d |= (1 << (27 - i)); long[] subkeys=new long[16]; for(int round=0;round<16;round++){ int shifts=SHIFTS[round]; c = ((c << shifts) & 0x0FFFFFFF) | (c >>> (28 - shifts)); d = ((d << shifts) & 0x0FFFFFFF) | (d >>> (28 - shifts)); int[] cd56=new int[56]; for(int i=0;i<28;i++) cd56[i]=((c >>> (27 - i)) & 1); for(int i=0;i<28;i++) cd56[28+i]=((d >>> (27 - i)) & 1); long sub=0L; for(int i=0;i<48;i++){ int src=PC2[i]; int bit=cd56[src-1]; if(bit==1) sub |= (1L << (47 - i)); } subkeys[round]=sub; } return subkeys; }

    //
    private static byte[] desBlockWithSubkeys(byte[] block8, long[] subkeys) {
        long block = bytesToLong(block8);
        long ip=0L; for(int i=0;i<64;i++){ int bit=getBit64(block, IP[i]); if(bit==1) ip |= (1L << (63 - i)); }
        int L = (int)(ip >>> 32);
        int R = (int)(ip & 0xFFFFFFFFL);
        for(int round=0; round<16; round++){
            long expanded = expand32to48(R);
            long x = expanded ^ subkeys[round];
            int sOut = sBoxes(x);
            int fOut = permuteP(sOut);
            int newR = L ^ fOut;
            L = R;
            R = newR;
        }
        long preout = (((long)R) & 0xFFFFFFFFL) << 32 | (((long)L) & 0xFFFFFFFFL);
        long fp=0L; for(int i=0;i<64;i++){ int bit=getBit64(preout, FP[i]); if(bit==1) fp |= (1L << (63 - i)); }
        return longToBytes(fp);
    }

    private static byte[] desEncryptBlockPure(byte[] keyBytes, byte[] block8){ long[] subkeys = generateSubkeys(keyBytes); return desBlockWithSubkeys(block8, subkeys); }

    private static byte[] desDecryptBlockPure(byte[] keyBytes, byte[] block8){ long[] subkeys = generateSubkeys(keyBytes); long[] rev = new long[16]; for(int i=0;i<16;i++) rev[i]=subkeys[15-i]; return desBlockWithSubkeys(block8, rev); }

    private static byte[] doubleDesEncryptPure(byte[] k1, byte[] k2, byte[] plaintext){ byte[] inner = desEncryptBlockPure(k1, plaintext); return desEncryptBlockPure(k2, inner); }
    private static byte[] doubleDesDecryptPure(byte[] k1, byte[] k2, byte[] ciphertext){ byte[] inner = desDecryptBlockPure(k2, ciphertext); return desDecryptBlockPure(k1, inner); }

    private static String bytesToHex(byte[] b){ StringBuilder sb=new StringBuilder(); for(byte x:b) sb.append(String.format("%02X", x)); return sb.toString(); }

    private static Map<Integer,Integer> mitmAttackPure(byte[] plaintext8, byte[] ciphertext8){ Map<String,Integer> forward=new HashMap<>(); for(int seed=0; seed<256; seed++){ byte[] k1 = makeDESKeyFromByte((byte)seed); byte[] interm = desEncryptBlockPure(k1, plaintext8); forward.put(bytesToHex(interm), k1[0] & 0xFF); } Map<Integer,Integer> found=new HashMap<>(); for(int seed=0; seed<256; seed++){ byte[] k2 = makeDESKeyFromByte((byte)seed); byte[] dec = desDecryptBlockPure(k2, ciphertext8); String h = bytesToHex(dec); if(forward.containsKey(h)){ found.put(forward.get(h), k2[0] & 0xFF); } } return found; }

    public static void main(String[] args) throws Exception {


        SecureRandom rnd = new SecureRandom();
        int seed1Int, seed2Int;
        if (args.length >= 2 && args[0].matches("^[0-9]$") && args[1].matches("^[0-9]$")){
            seed1Int = Integer.parseInt(args[0]);
            seed2Int = Integer.parseInt(args[1]);
        } else {
            seed1Int = rnd.nextInt(10);
            seed2Int = rnd.nextInt(10);
        }
        byte seed1 = (byte) seed1Int;
        byte seed2 = (byte) seed2Int;

        byte[] k1 = makeDESKeyFromByte(seed1);
        byte[] k2 = makeDESKeyFromByte(seed2);
        byte[] plaintext = "TESTBLK5".getBytes("ASCII");

        System.out.printf("Choose random bytes: k1Byte=0x%02X, k2Byte=0x%02X ", seed1 & 0xFF, seed2 & 0xFF);
                System.out.println("Plaintext (hex):  " + bytesToHex(plaintext));

        byte[] ciphertext = doubleDesEncryptPure(k1, k2, plaintext);
        System.out.println("2DES cypher: " + bytesToHex(ciphertext));

        Map<Integer,Integer> candidates = mitmAttackPure(plaintext, ciphertext);

        System.out.println("--- candidates verification ---");
        boolean confirmed = false;
        for(Map.Entry<Integer,Integer> e : candidates.entrySet()){
            int k1p = e.getKey();
            int k2p = e.getValue();
            byte[] kk1 = makeDESKeyFromByte((byte)k1p);
            byte[] kk2 = makeDESKeyFromByte((byte)k2p);
            byte[] recomputedCipher = doubleDesEncryptPure(kk1, kk2, plaintext);
            byte[] recomputedPlain = doubleDesDecryptPure(kk1, kk2, ciphertext);
            boolean cEq = Arrays.equals(recomputedCipher, ciphertext);
            boolean pEq = Arrays.equals(recomputedPlain, plaintext);
            System.out.printf("Candidate k1_par=0x%02X k2_par=0x%02X  -> cypher reproduced? %s  -> \nPlaintext reproduced after decryption? %s ", k1p, k2p, cEq?"YES":"NO", pEq?"YES":"NO");
            if(cEq && pEq && k1p == (k1[0] & 0xFF) && k2p == (k2[0] & 0xFF)) confirmed = true;
        }

        System.out.println("\nMITM candidates (parity-fixed k1 -> parity-fixed k2) found: " + candidates.size());
        for(Map.Entry<Integer,Integer> e : candidates.entrySet()) System.out.printf("k1_par=0x%02X  k2_par=0x%02X ", e.getKey(), e.getValue());

        if(!candidates.isEmpty()){
            Map.Entry<Integer,Integer> first = candidates.entrySet().iterator().next();
            byte[] kk1 = makeDESKeyFromByte((byte)(int) first.getKey());
            byte[] kk2 = makeDESKeyFromByte((byte)(int) first.getValue());
            byte[] decrypted = doubleDesDecryptPure(kk1, kk2, ciphertext);
            System.out.println("Plaintext before encryption(ASCII): " + new String(plaintext, "ASCII") + "  hex=" + bytesToHex(plaintext));
            System.out.println("Plaintext after decryption (ASCII): " + new String(decrypted, "ASCII") + "  hex=" + bytesToHex(decrypted));
        }
    }
}
