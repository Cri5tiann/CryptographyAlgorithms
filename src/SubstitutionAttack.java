import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.util.stream.Collectors;

public class SubstitutionAttack {

    private static final String ENG_FREQ_ORDER = "ETAOINSHRDLCUMWFGYPBVKJXQZ";

    private static final Map<Character, Double> UNIGRAM_LOG = new HashMap<>();
    private static final Map<String, Double> BIGRAM_LOG = new HashMap<>();
    private static final Map<String, Double> TRIGRAM_LOG = new HashMap<>();

    static {

        double[] freqs = {12.70, 9.06, 8.17, 7.51, 6.97, 6.75, 6.33, 6.09, 5.99, 4.25, 2.78, 2.76, 2.41, 2.23,
                2.02, 1.97, 1.49, 0.98, 0.77, 0.15, 0.15, 0.13, 0.10, 0.09, 0.07, 0.05};
        for (int i = 0; i < 26; i++)
            UNIGRAM_LOG.put((char) ('A' + i), Math.log(freqs[i] / 100.0 + 1e-8));


        String[] bigrams = {"TH", "HE", "IN", "ER", "AN", "RE", "ON", "AT", "EN", "ND", "TI", "ES", "OR", "TE", "OF"};
        double[] bigFreq = {1.52, 1.28, 0.94, 0.94, 0.82, 0.68, 0.57, 0.56, 0.55, 0.53, 0.34, 0.32, 0.31, 0.27, 0.16};
        for (int i = 0; i < bigrams.length; i++)
            BIGRAM_LOG.put(bigrams[i], Math.log(bigFreq[i] + 1e-8));


        String[] trigrams = {"THE", "AND", "ING", "HER", "ERE", "ENT", "THA", "NTH", "WAS", "ETH", "FOR", "DTH"};
        double[] triFreq = {2.0, 0.8, 0.7, 0.45, 0.43, 0.4, 0.33, 0.29, 0.26, 0.25, 0.24, 0.23};
        for (int i = 0; i < trigrams.length; i++)
            TRIGRAM_LOG.put(trigrams[i], Math.log(triFreq[i] + 1e-8));
    }

    private static String normalize(String text) {
        StringBuilder sb = new StringBuilder();
        for (char c : text.toCharArray()) if (Character.isLetter(c)) sb.append(Character.toUpperCase(c));
        return sb.toString();
    }

    private static String encrypt(String plain, String key) {
        char[] map = key.toCharArray();
        StringBuilder sb = new StringBuilder();
        for (char c : plain.toCharArray())
            sb.append(c >= 'A' && c <= 'Z' ? map[c - 'A'] : c);
        return sb.toString();
    }

    private static String decrypt(String cipher, String key) {
        char[] inv = new char[26];
        for (int i = 0; i < 26; i++) inv[key.charAt(i) - 'A'] = (char) ('A' + i);
        StringBuilder sb = new StringBuilder();
        for (char c : cipher.toCharArray())
            sb.append(c >= 'A' && c <= 'Z' ? inv[c - 'A'] : c);
        return sb.toString();
    }

    private static double score(String text) {
        double score = 0;
        for (int i = 0; i < text.length(); i++) {
            score += UNIGRAM_LOG.getOrDefault(text.charAt(i), -12.0);
            if (i < text.length() - 1)
                score += BIGRAM_LOG.getOrDefault(text.substring(i, i + 2), -14.0);
            if (i < text.length() - 2)
                score += TRIGRAM_LOG.getOrDefault(text.substring(i, i + 3), -18.0);
        }
        return score;
    }

    private static String freqInit(String cipher) {
        Map<Character, Integer> freq = new HashMap<>();
        for (char c = 'A'; c <= 'Z'; c++) freq.put(c, 0);
        for (char c : cipher.toCharArray())
            if (c >= 'A' && c <= 'Z') freq.put(c, freq.get(c) + 1);

        List<Character> sorted = freq.entrySet().stream()
                .sorted((a, b) -> b.getValue() - a.getValue())
                .map(Map.Entry::getKey)
                .collect(Collectors.toList());

        char[] key = new char[26];
        for (int i = 0; i < 26; i++)
            key[ENG_FREQ_ORDER.charAt(i) - 'A'] = sorted.get(i);
        return new String(key);
    }

    private static String swap(String key, int i, int j) {
        char[] k = key.toCharArray();
        char tmp = k[i]; k[i] = k[j]; k[j] = tmp;
        return new String(k);
    }

    private static String simulatedAnnealing(String cipher, String key) {
        String current = key;
        double currScore = score(decrypt(cipher, current));
        double temp = 5.0;
        double cooling = 0.97;

        while (temp > 0.1) {
            boolean improved = false;
            for (int i = 0; i < 26; i++) {
                for (int j = i + 1; j < 26; j++) {
                    String testKey = swap(current, i, j);
                    double newScore = score(decrypt(cipher, testKey));
                    double diff = newScore - currScore;
                    if (diff > 0 || diff > -temp) {
                        current = testKey;
                        currScore = newScore;
                        improved = true;
                    }
                }
            }
            temp *= cooling;
            if (!improved) break;
        }
        return current;
    }

    private static int correctLetters(String found, String secret) {
        int correct = 0;
        for (int i = 0; i < 26; i++) if (found.charAt(i) == secret.charAt(i)) correct++;
        return correct;
    }

    public static void main(String[] args) throws IOException {
        String plaintext = "The continuous erosion of classic cryptographic methodologies necessitates a persistent re-evaluation of security primitives. Consider the Feistel network, a ubiquitous structure in block ciphers like DES and some variants of AES, which leverages the simplicity of the XOR operation within its round function to achieve a remarkably strong blend of confusion and diffusion. However, even these well-tested architectures face constant scrutiny from quantum computing models and advanced statistical cryptanalysis. The sheer volume of digital data generated daily—currently estimated in the exabytes—presents an unparalleled target-rich environment for malicious actors and an immense challenge for secure processing The evolution of linguistic models, specifically the shift from simple frequency analysis to sophisticated probabilistic context-free grammars (PCFGs), has profoundly complicated the attack surface against historical ciphers. A polyalphabetic substitution cipher, such as the Vigenère, once considered unbreakable, succumbs relatively quickly to the Kasiski examination and subsequent index of coincidence analysis, provided the key length is manageable and the message length sufficient. Yet, applying these methods to a modern, highly compressed, and linguistically diverse data stream requires computational resources and algorithmic sophistication far exceeding traditional means. The true vulnerability often lies not in the core algorithm, but in the implementation's handling of key management, initialization vectors (IVs), and padding schemes Consider a fictional scenario: a distributed ledger technology (DLT) is secured by a proprietary hashing algorithm based on the principles of irreversible transformation. This algorithm employs a 1024-bit output, iterating through a series of chaotic maps—specifically, a modified Arnold cat map and a pseudo-randomized logistic map—before final reduction. The system’s integrity depends entirely on the mathematical intractability of reversing the chaotic perturbation, an assumption that must hold true even against differential cryptanalysis targeting subtle statistical biases introduced by the floating-point arithmetic utilized in the initial transformations. Furthermore, the inherent need for speed in transaction validation demands optimization, which inevitably introduces trade-offs between execution time and algorithmic resistance This persistent tension between performance and security defines the cutting edge of applied cryptography. Future research must encompass the integration of homomorphic encryption to permit computation on encrypted data, and the deployment of lightweight ciphers for resource-constrained IoT devices, ensuring that security scales both up to the cloud and down to the most rudimentary sensor node. The ultimate objective remains the achievement of perfect secrecy, a standard mathematically proven by Claude Shannon, yet practically unattainable in most real-world applications dueence to the constraints of key distribution and computational feasibility. This pursuit continues to drive innovation across diverse fields, from quantum entanglement protocols to the optimization of finite field arithmetic In summary, the landscape of information security is defined by continuous, dynamic warfare between mathematical ingenuity and computational power. The text you are analyzing is merely one small, complex sample of the data streams that must be protected against all forms of cryptanalysis, from the simplest substitution attack to the most complex differential analysis. The persistent threat is not the simplicity of the method, but the scale and complexity of the modern digital domain THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG AND THEN RUNS INTO THE FOREST AGAIN AND AGAIN GOING TWENTY HOURS AN HOUR TRYING TO FIGURE OUT THE PROPER WAY OF JUMPING OVER THE LAZY RIVER WHICH IS NOT FAR AWAY FROM THE HOUSE AND THEN TO HAVE BREAKFAST AT THE NEAREST PARK. THE FOX CONTINUES THROUGH THE TREES, LEAPING OVER SMALL STREAMS AND HIDDEN ROOTS, SCURRYING UNDER THE THICK BUSHES, AND PAUSING OCCASIONALLY TO LISTEN TO THE BIRDS CHIRPING LOUDLY ABOVE. IT MOVES WITH A GRACEFUL SPEED, NAVIGATING THROUGH NARROW PATHS AND WIDE CLEARINGS, SOMETIMES STOPPING TO SMELL THE FLOWERS OR WATCH A SQUIRREL DASH ACROSS THE GROUND. THE SUN RISES HIGHER IN THE SKY, CASTING LONG SHADOWS OF THE TREES AND CREATING SPARKLING LIGHT ON THE WATER OF THE RIVER. THE FOX THINKS ABOUT HOW TO CROSS THE ROCKY HILLS AND DENSE UNDERGROWTH, PLANING EACH JUMP CAREFULLY TO AVOID FALLING. AFTER HOURS OF RUNNING, IT FINDS A QUIET PLACE BY A LARGE OAK TREE TO REST BRIEFLY, EATING SOME BERRIES AND DRINKING FROM A COOL STREAM. THEN IT SETS OFF AGAIN, MOVING THROUGH MEADOWS FILLED WITH WILD GRASSES AND COLORFUL WILDFLOWERS, HEARING IN THE DISTANCE THE SOUND OF OTHER ANIMALS. THE FOX RECALLS THE PATH TO A SMALL VILLAGE NEAR THE EDGE OF THE FOREST WHERE PEOPLE WALK THEIR DOGS AND CHILDREN PLAY IN THE FIELDS. IT THINKS ABOUT HOW IT CAN LEAP OVER FENCES AND DITCHES TO REACH THE OPEN PARK BEFORE NIGHTFALL, ENJOYING THE ADVENTURE AND THE FREEDOM OF THE WIDE OUTDOORS. THE TREES SWAY WITH THE WIND, AND THE FOX MOVES WITH THE RHYTHM OF THE FOREST, JUMPING OVER OBSTACLES, SLIPPING THROUGH NARROW GAPS, AND SOMETIMES PAUSING TO OBSERVE A DEER OR A RABBIT. AS THE SUN BEGINS TO SET, CASTING ORANGE AND PURPLE HUES ACROSS THE SKY, THE FOX FINDS ITSELF BACK NEAR THE RIVER AND THINKS ABOUT THE NEXT MORNING’S JOURNEY, WHERE IT WILL LEAP AND RUN THROUGH NEW PATHS, CROSS FIELDS, AND EXPLORE MORE OF THE WIDE FOREST, ALWAYS CURIOUS, ALWAYS MOVING, AND ALWAYS ALERT TO THE SOUNDS AND SIGHTS OF THE WILD WORLD AROUND IT. FINALLY, WHEN NIGHT FALLS, IT RETURNS TO A SAFE SPOT NEAR THE EDGE OF THE FOREST, TAKING A MOMENT TO REST, REFLECT ON THE DAY, AND PLAN FOR MORE ADVENTURES, KNOWING THAT TOMORROW WILL BRING MORE JUMPS, MORE DISCOVERIES, AND MORE HOURS OF EXCITING ACTIVITY THROUGH THE TREES, RIVERS, HILLS, AND FIELDS THAT STRETCH FAR BEYOND THE EYE CAN SEE, ALWAYS CHALLENGING, ALWAYS BEAUTIFUL, ALWAYS FULL OF LIFE AFTER HOURS OF RUNNING, IT FINDS A QUIET PLACE BY A LARGE OAK TREE TO REST BRIEFLY, EATING SOME BERRIES AND DRINKING FROM A COOL STREAM. THEN IT SETS OFF AGAIN, MOVING THROUGH MEADOWS FILLED WITH WILD GRASSES AND COLORFUL WILDFLOWERS, HEARING IN THE DISTANCE THE SOUND OF OTHER ANIMALS. THE FOX RECALLS THE PATH TO A SMALL VILLAGE NEAR THE EDGE OF THE FOREST WHERE PEOPLE WALK THEIR DOGS AND CHILDREN PLAY IN THE FIELDS. IT THINKS ABOUT HOW IT CAN LEAP OVER FENCES AND DITCHES TO REACH THE OPEN PARK BEFORE NIGHTFALL, ENJOYING THE ADVENTURE AND THE FREEDOM OF THE WIDE OUTDOORS. THE TREES SWAY WITH THE WIND, AND THE FOX MOVES WITH THE RHYTHM OF THE FOREST, JUMPING OVER OBSTACLES, SLIPPING THROUGH NARROW GAPS, AND SOMETIMES PAUSING TO OBSERVE A DEER OR A RABBIT. AS THE SUN BEGINS TO SET, CASTING ORANGE";
        plaintext = plaintext.toUpperCase().replaceAll("[^A-Z]", "");
        String secretKey = "QFZRCYUIJPASDWGHBKLEXTVONM";

        String norm = normalize(plaintext);
        String cipher = encrypt(norm, secretKey);

        System.out.println("Ciphertext: " + cipher.substring(0, Math.min(120, cipher.length())) + "...");

        String start = freqInit(cipher);
        String resultKey = simulatedAnnealing(cipher, start);
        String recovered = decrypt(cipher, resultKey);

        int correct = correctLetters(resultKey, secretKey);
        System.out.printf("\nLitere corecte: %d / 26 (%.2f%%)\n", correct, correct * 100.0 / 26);
        System.out.println("\ntext decriptat:\n" +
                recovered.substring(0, Math.min(400, recovered.length())) + (recovered.length() > 400 ? "..." : ""));
    }
}
