package ClassicCiphers_Sh26_V26;

import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

public class VigenereAttack {

    private static final double[] EN_FREQ = {
            8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966,
            0.153, 0.772, 4.025, 2.406, 6.749, 7.507, 1.929, 0.095, 5.987,
            6.327, 9.056, 2.758, 0.978, 2.360, 0.150, 1.974, 0.074
    };

    public static String onlyLetters(String s) {
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) {
            if (Character.isLetter(c)) sb.append(Character.toUpperCase(c));
        }
        return sb.toString();
    }

    private static String normalize(String text) {
        StringBuilder sb = new StringBuilder();
        for (char c : text.toCharArray()) if (Character.isLetter(c)) sb.append(Character.toUpperCase(c));
        return sb.toString();
    }

    public static String encrypt(String plaintext, String key) {
        plaintext = onlyLetters(plaintext);
        key = onlyLetters(key);
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < plaintext.length(); i++) {
            int p = plaintext.charAt(i) - 'A';
            int k = key.charAt(i % key.length()) - 'A';
            char c = (char) ('A' + (p + k) % 26);
            out.append(c);
        }
        return out.toString();
    }

    public static String decrypt(String ciphertext, String key) {
        ciphertext = onlyLetters(ciphertext);
        key = onlyLetters(key);
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < ciphertext.length(); i++) {
            int c = ciphertext.charAt(i) - 'A';
            int k = key.charAt(i % key.length()) - 'A';
            char p = (char) ('A' + ( (c - k + 26) % 26 ));
            out.append(p);
        }
        return out.toString();
    }


    public static Map<Integer, Integer> kasiskiDistances(String cipher) {
        mapClearCheck: ;
        cipher = onlyLetters(cipher);
        Map<Integer, Integer> gcdCounts = new HashMap<>(); // gcd -> count
        List<Integer> distances = new ArrayList<>();

        for (int L = 3; L <= 8; L++) {
            Map<String, List<Integer>> positions = new HashMap<>();
            for (int i = 0; i + L <= cipher.length(); i++) {
                String sub = cipher.substring(i, i + L);
                positions.computeIfAbsent(sub, k -> new ArrayList<>()).add(i);
            }
            for (Map.Entry<String, List<Integer>> e : positions.entrySet()) {
                List<Integer> pos = e.getValue();
                if (pos.size() > 1) {
                    for (int i = 1; i < pos.size(); i++) {
                        int dist = pos.get(i) - pos.get(i - 1);
                        if (dist > 0) distances.add(dist);
                    }
                }
            }
        }


        for (int i = 0; i < distances.size(); i++) {
            for (int j = i + 1; j < distances.size(); j++) {
                int g = gcd(distances.get(i), distances.get(j));
                if (g > 1) gcdCounts.put(g, gcdCounts.getOrDefault(g, 0) + 1);
            }
        }
        return gcdCounts;
    }

    public static double indexOfCoincidence(String s) {
        s = onlyLetters(s);
        int n = s.length();
        if (n <= 1) return 0.0;
        int[] counts = new int[26];
        for (char c : s.toCharArray()) counts[c - 'A']++;
        double sum = 0;
        for (int f : counts) sum += (double) f * (f - 1);
        return sum / ( (double) n * (n - 1) );
    }

    public static List<Integer> estimateKeyLengths(String cipher, int maxKey) {
        cipher = onlyLetters(cipher);
        Map<Integer, Integer> gcdCounts = kasiskiDistances(cipher);
        List<Integer> kasiskiCandidates = gcdCounts.entrySet().stream()
                .sorted((a,b) -> b.getValue() - a.getValue())
                .map(Map.Entry::getKey)
                .collect(Collectors.toList());

        Map<Integer, Double> icScores = new HashMap<>();
        for (int keyLen = 1; keyLen <= Math.min(maxKey, cipher.length()); keyLen++) {
            double sumIC = 0;
            for (int i = 0; i < keyLen; i++) {
                StringBuilder col = new StringBuilder();
                for (int j = i; j < cipher.length(); j += keyLen) col.append(cipher.charAt(j));
                sumIC += indexOfCoincidence(col.toString());
            }
            double avgIC = sumIC / keyLen;
            icScores.put(keyLen, avgIC);
        }
        // Sortare prin IC descendent
        List<Integer> icCandidates = icScores.entrySet().stream()
                .sorted((a,b) -> Double.compare(b.getValue(), a.getValue()))
                .map(Map.Entry::getKey)
                .collect(Collectors.toList());


        LinkedHashSet<Integer> finalList = new LinkedHashSet<>();
        for (int k : kasiskiCandidates) {
            if (k <= maxKey) finalList.add(k);
        }
        for (int k : icCandidates) {
            finalList.add(k);
        }
        if (finalList.isEmpty()) {
            for (int i = 1; i <= Math.min(maxKey, cipher.length()); i++) finalList.add(i);
        }
        return new ArrayList<>(finalList);
    }

    public static String recoverKeyByLength(String cipher, int keyLen) {
        cipher = onlyLetters(cipher);
        StringBuilder key = new StringBuilder();
        for (int i = 0; i < keyLen; i++) {
            StringBuilder col = new StringBuilder();
            for (int j = i; j < cipher.length(); j += keyLen) col.append(cipher.charAt(j));
            int bestShift = findBestShiftChiSquared(col.toString());
            char keyChar = (char) ('A' + bestShift);
            key.append(keyChar);
        }
        return key.toString();
    }

    private static int findBestShiftChiSquared(String col) {
        int n = col.length();
        if (n == 0) return 0;
        int[] counts = new int[26];
        for (char c : col.toCharArray()) counts[c - 'A']++;

        double bestScore = Double.POSITIVE_INFINITY;
        int bestShift = 0;
        for (int shift = 0; shift < 26; shift++) {

            double chi = 0;
            for (int i = 0; i < 26; i++) {
                int observed = counts[(i + shift) % 26];
                double expected = EN_FREQ[i] * n / 100.0;
                double diff = observed - expected;
                chi += (expected == 0) ? 0 : (diff * diff) / expected;
            }
            if (chi < bestScore) {
                bestScore = chi;
                bestShift = shift;
            }
        }
        return bestShift;
    }

    private static int gcd(int a, int b) {
        a = Math.abs(a); b = Math.abs(b);
        if (a == 0) return b;
        if (b == 0) return a;
        while (b != 0) {
            int t = a % b;
            a = b;
            b = t;
        }
        return Math.abs(a);
    }

    public static Result attack(String cipher, int maxKeyGuess) {
        cipher = onlyLetters(cipher);
        List<Integer> candidates = estimateKeyLengths(cipher, maxKeyGuess);
        List<Candidate> tried = new ArrayList<>();

        for (int keyLen : candidates) {
            if (keyLen <= 0) continue;
            String key = recoverKeyByLength(cipher, keyLen);
            String plain = decrypt(cipher, key);
            double fitness = englishFitnessChiSquare(plain);
            tried.add(new Candidate(keyLen, key, plain, fitness));
        }

        tried.sort(Comparator.comparingDouble(c -> c.fitness));
        Candidate best = tried.get(0);
        return new Result(best.key, best.keyLen, best.plaintext, tried);
    }

    private static double englishFitnessChiSquare(String text) {
        int n = text.length();
        if (n == 0) return Double.POSITIVE_INFINITY;
        int[] counts = new int[26];
        for (char c : text.toCharArray()) counts[c - 'A']++;
        double chi = 0;
        for (int i = 0; i < 26; i++) {
            double expected = EN_FREQ[i] * n / 100.0;
            double diff = counts[i] - expected;
            chi += (expected == 0) ? 0 : (diff * diff) / expected;
        }
        return chi;
    }

    public static class Candidate {
        public int keyLen;
        public String key;
        public String plaintext;
        public double fitness;
        public Candidate(int keyLen, String key, String plaintext, double fitness) {
            this.keyLen = keyLen; this.key = key; this.plaintext = plaintext; this.fitness = fitness;
        }
        @Override public String toString() {
            return String.format("len=%d key=%s fitness=%.2f", keyLen, key, fitness);
        }
    }

    public static class Result {
        public String key;
        public int keyLen;
        public String plaintext;
        public List<Candidate> tried;
        public Result(String key, int keyLen, String plaintext, List<Candidate> tried) {
            this.key = key; this.keyLen = keyLen; this.plaintext = plaintext; this.tried = tried;
        }
    }

    // ---- Example main ----
    public static void main(String[] args) throws IOException {
        String plaintext = "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG AND THEN RUNS INTO THE FOREST AGAIN AND AGAIN GOING TWENTY HOURS AN HOUR TRYING TO FIGURE OUT THE PROPER WAY OF JUMPING OVER THE LAZY RIVER WHICH IS NOT FAR AWAY FROM THE HOUSE AND THEN TO HAVE BREAKFAST AT THE NEAREST PARK. THE FOX CONTINUES THROUGH THE TREES, LEAPING OVER SMALL STREAMS AND HIDDEN ROOTS, SCURRYING UNDER THE THICK BUSHES, AND PAUSING OCCASIONALLY TO LISTEN TO THE BIRDS CHIRPING LOUDLY ABOVE. IT MOVES WITH A GRACEFUL SPEED, NAVIGATING THROUGH NARROW PATHS AND WIDE CLEARINGS, SOMETIMES STOPPING TO SMELL THE FLOWERS OR WATCH A SQUIRREL DASH ACROSS THE GROUND. THE SUN RISES HIGHER IN THE SKY, CASTING LONG SHADOWS OF THE TREES AND CREATING SPARKLING LIGHT ON THE WATER OF THE RIVER. THE FOX THINKS ABOUT HOW TO CROSS THE ROCKY HILLS AND DENSE UNDERGROWTH, PLANING EACH JUMP CAREFULLY TO AVOID FALLING. AFTER HOURS OF RUNNING, IT FINDS A QUIET PLACE BY A LARGE OAK TREE TO REST BRIEFLY, EATING SOME BERRIES AND DRINKING FROM A COOL STREAM. THEN IT SETS OFF AGAIN, MOVING THROUGH MEADOWS FILLED WITH WILD GRASSES AND COLORFUL WILDFLOWERS, HEARING IN THE DISTANCE THE SOUND OF OTHER ANIMALS. THE FOX RECALLS THE PATH TO A SMALL VILLAGE NEAR THE EDGE OF THE FOREST WHERE PEOPLE WALK THEIR DOGS AND CHILDREN PLAY IN THE FIELDS. IT THINKS ABOUT HOW IT CAN LEAP OVER FENCES AND DITCHES TO REACH THE OPEN PARK BEFORE NIGHTFALL, ENJOYING THE ADVENTURE AND THE FREEDOM OF THE WIDE OUTDOORS. THE TREES SWAY WITH THE WIND, AND THE FOX MOVES WITH THE RHYTHM OF THE FOREST, JUMPING OVER OBSTACLES, SLIPPING THROUGH NARROW GAPS, AND SOMETIMES PAUSING TO OBSERVE A DEER OR A RABBIT. AS THE SUN BEGINS TO SET, CASTING ORANGE AND PURPLE HUES ACROSS THE SKY, THE FOX FINDS ITSELF BACK NEAR THE RIVER AND THINKS ABOUT THE NEXT MORNING’S JOURNEY, WHERE IT WILL LEAP AND RUN THROUGH NEW PATHS, CROSS FIELDS, AND EXPLORE MORE OF THE WIDE FOREST, ALWAYS CURIOUS, ALWAYS MOVING, AND ALWAYS ALERT TO THE SOUNDS AND SIGHTS OF THE WILD WORLD AROUND IT. FINALLY, WHEN NIGHT FALLS, IT RETURNS TO A SAFE SPOT NEAR THE EDGE OF THE FOREST, TAKING A MOMENT TO REST, REFLECT ON THE DAY, AND PLAN FOR MORE ADVENTURES, KNOWING THAT TOMORROW WILL BRING MORE JUMPS, MORE DISCOVERIES, AND MORE HOURS OF EXCITING ACTIVITY THROUGH THE TREES, RIVERS, HILLS, AND FIELDS THAT STRETCH FAR BEYOND THE EYE CAN SEE, ALWAYS CHALLENGING, ALWAYS BEAUTIFUL, ALWAYS FULL OF LIFE ";
        String key = "AAAAAAB"; //
        String norm = normalize(plaintext);
        System.out.println("Cheia originala: " + key);
        String cipher = encrypt(norm, key);
        System.out.println("Ciphertext: " + cipher);

        // Atac:
        System.out.println("\nAtacul");
        Result res = attack(cipher, 20); // incercam lungimi pana la 20
        System.out.println("Lungime cheie ghicita: " + res.keyLen);
        System.out.println("Cheia ghicita: " + res.key);
        System.out.println("Textul decriptat(200): " + res.plaintext.substring(0, Math.min(200, res.plaintext.length())));

        System.out.println("\nOptiuni posibile:");
        for (int i = 0; i < Math.min(10, res.tried.size()); i++) {
            System.out.println(res.tried.get(i));
        }
    }
}
