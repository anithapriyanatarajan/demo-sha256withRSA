import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

/**
 * Educational Java Application demonstrating SHA256 hashing and RSA digital signatures
 * 
 * This application shows:
 * 1. Why we need SHA256 hashing
 * 2. How digital signatures work with RSA
 * 3. Sender and receiver interaction
 * 4. Why these algorithms are not quantum-safe
 */
public class CryptoEducationApp {
    
    private static KeyPair keyPair;
    private static Scanner scanner = new Scanner(System.in);
    
    public static void main(String[] args) {
        System.out.println("=== CRYPTOGRAPHY EDUCATION: SHA256 & RSA DIGITAL SIGNATURES ===\n");
        
        try {
            // Generate RSA key pair for demonstration
            generateKeyPair();
            
            boolean continueApp = true;
            while (continueApp) {
                displayMenu();
                int choice = getMenuChoice();
                
                switch (choice) {
                    case 1:
                        explainSHA256();
                        break;
                    case 2:
                        demonstrateSHA256();
                        break;
                    case 3:
                        explainDigitalSignatures();
                        break;
                    case 4:
                        demonstrateDigitalSignature();
                        break;
                    case 5:
                        explainSenderReceiverInteraction();
                        break;
                    case 6:
                        simulateSenderReceiverCommunication();
                        break;
                    case 7:
                        explainQuantumThreat();
                        break;
                    case 8:
                        continueApp = false;
                        break;
                    default:
                        System.out.println("Invalid choice. Please try again.\n");
                }
            }
            
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
        
        System.out.println("Thank you for learning about cryptography!");
        scanner.close();
    }
    
    private static void generateKeyPair() throws NoSuchAlgorithmException {
        System.out.println("🔑 Generating RSA key pair (2048 bits)...");
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        keyPair = keyGen.generateKeyPair();
        System.out.println("✅ Key pair generated successfully!\n");
    }
    
    private static void displayMenu() {
        System.out.println("Choose an option:");
        System.out.println("1. Learn about SHA256 hashing");
        System.out.println("2. Demonstrate SHA256 hashing");
        System.out.println("3. Learn about Digital Signatures");
        System.out.println("4. Demonstrate RSA Digital Signature");
        System.out.println("5. Learn about Sender-Receiver Interaction");
        System.out.println("6. Simulate Sender-Receiver Communication");
        System.out.println("7. Learn about Quantum Threat");
        System.out.println("8. Exit");
        System.out.print("Enter your choice (1-8): ");
    }
    
    private static int getMenuChoice() {
        try {
            return Integer.parseInt(scanner.nextLine());
        } catch (NumberFormatException e) {
            return -1;
        }
    }
    
    private static void explainSHA256() {
        System.out.println("\n📚 UNDERSTANDING SHA256 HASHING");
        System.out.println("=" + "=".repeat(35));
        
        System.out.println("\n🔍 What is SHA256?");
        System.out.println("SHA256 (Secure Hash Algorithm 256) is a cryptographic hash function that:");
        System.out.println("• Takes any input (message) of any size");
        System.out.println("• Produces a fixed-size 256-bit (32-byte) hash output");
        System.out.println("• Is deterministic: same input always produces same hash");
        System.out.println("• Is irreversible: cannot recover original message from hash");
        
        System.out.println("\n🎯 Why do we need SHA256?");
        System.out.println("1. DATA INTEGRITY: Detect if data has been modified");
        System.out.println("   - Even tiny changes in input create completely different hash");
        System.out.println("2. DIGITAL SIGNATURES: Create compact representation of large documents");
        System.out.println("   - Instead of signing entire document, we sign its hash");
        System.out.println("3. PASSWORD STORAGE: Store password hashes instead of plaintext");
        System.out.println("4. BLOCKCHAIN: Create tamper-proof chains of data blocks");
        
        System.out.println("\n⚡ Key Properties:");
        System.out.println("• Avalanche Effect: Small input change → drastically different output");
        System.out.println("• Collision Resistance: Extremely hard to find two inputs with same hash");
        System.out.println("• Pre-image Resistance: Cannot reverse-engineer input from hash");
        
        System.out.println("\nPress Enter to continue...");
        scanner.nextLine();
    }
    
    private static void demonstrateSHA256() throws NoSuchAlgorithmException {
        System.out.println("\n🧪 SHA256 DEMONSTRATION");
        System.out.println("=" + "=".repeat(25));
        
        System.out.print("Enter a message to hash: ");
        String message = scanner.nextLine();
        
        // Calculate SHA256 hash
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = digest.digest(message.getBytes());
        String hash = bytesToHex(hashBytes);
        
        System.out.println("\n📝 Original Message: " + message);
        System.out.println("📊 Message Length: " + message.length() + " characters");
        System.out.println("🔐 SHA256 Hash: " + hash);
        System.out.println("📏 Hash Length: " + hash.length() + " characters (always 64 hex chars = 256 bits)");
        
        // Demonstrate avalanche effect
        if (message.length() > 0) {
            String modifiedMessage = message + "!";
            byte[] modifiedHashBytes = digest.digest(modifiedMessage.getBytes());
            String modifiedHash = bytesToHex(modifiedHashBytes);
            
            System.out.println("\n🔬 AVALANCHE EFFECT DEMONSTRATION:");
            System.out.println("Original:  " + message);
            System.out.println("Modified:  " + modifiedMessage + " (just added '!')");
            System.out.println("Hash 1:    " + hash);
            System.out.println("Hash 2:    " + modifiedHash);
            System.out.println("Notice how completely different the hashes are!");
        }
        
        System.out.println("\nPress Enter to continue...");
        scanner.nextLine();
    }
    
    private static void explainDigitalSignatures() {
        System.out.println("\n📚 UNDERSTANDING DIGITAL SIGNATURES");
        System.out.println("=" + "=".repeat(37));
        
        System.out.println("\n🔐 What is a Digital Signature?");
        System.out.println("A digital signature is like a handwritten signature but much more secure:");
        System.out.println("• Proves WHO sent the message (Authentication)");
        System.out.println("• Proves the message wasn't changed (Integrity)");
        System.out.println("• Sender cannot deny they sent it (Non-repudiation)");
        
        System.out.println("\n🔄 How RSA Digital Signatures Work:");
        System.out.println("1. SENDER SIDE:");
        System.out.println("   📄 Take the document/message");
        System.out.println("   🔐 Calculate SHA256 hash of the document");
        System.out.println("   🔑 Encrypt the hash with sender's PRIVATE key = Digital Signature");
        System.out.println("   📤 Send: Original Document + Digital Signature + Public Key");
        
        System.out.println("\n2. RECEIVER SIDE:");
        System.out.println("   📥 Receive: Document + Signature + Sender's Public Key");
        System.out.println("   🔓 Decrypt signature with sender's PUBLIC key = Original Hash");
        System.out.println("   🔐 Calculate SHA256 hash of received document = New Hash");
        System.out.println("   ✅ Compare: If Original Hash = New Hash → Signature Valid!");
        
        System.out.println("\n🎯 Why This Works:");
        System.out.println("• Only sender has the private key to create the signature");
        System.out.println("• Anyone can verify with the public key");
        System.out.println("• If document changed, hashes won't match");
        System.out.println("• RSA ensures signature can't be forged without private key");
        
        System.out.println("\n💡 Why Hash First?");
        System.out.println("• RSA can only sign small data (< key size)");
        System.out.println("• SHA256 creates fixed small representation of any document");
        System.out.println("• Faster processing for large documents");
        
        System.out.println("\nPress Enter to continue...");
        scanner.nextLine();
    }
    
    private static void demonstrateDigitalSignature() throws Exception {
        System.out.println("\n🧪 DIGITAL SIGNATURE DEMONSTRATION");
        System.out.println("=" + "=".repeat(35));
        
        System.out.print("Enter a message to sign: ");
        String message = scanner.nextLine();
        
        // Step 1: Calculate SHA256 hash
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] messageHash = digest.digest(message.getBytes());
        String hashHex = bytesToHex(messageHash);
        
        System.out.println("\n📝 SIGNING PROCESS:");
        System.out.println("1. Original Message: " + message);
        System.out.println("2. SHA256 Hash: " + hashHex);
        
        // Step 2: Sign the hash with private key
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(keyPair.getPrivate());
        signature.update(message.getBytes());
        byte[] digitalSignature = signature.sign();
        String signatureHex = bytesToHex(digitalSignature);
        
        System.out.println("3. Digital Signature: " + signatureHex.substring(0, 64) + "... (truncated)");
        System.out.println("   Signature Length: " + digitalSignature.length + " bytes");
        
        // Step 3: Verify the signature
        System.out.println("\n🔍 VERIFICATION PROCESS:");
        signature.initVerify(keyPair.getPublic());
        signature.update(message.getBytes());
        boolean isValid = signature.verify(digitalSignature);
        
        System.out.println("4. Verification Result: " + (isValid ? "✅ VALID" : "❌ INVALID"));
        
        // Demonstrate tampering detection
        System.out.println("\n🚨 TAMPERING DETECTION TEST:");
        String tamperedMessage = message + " [MODIFIED]";
        signature.initVerify(keyPair.getPublic());
        signature.update(tamperedMessage.getBytes());
        boolean tamperedValid = signature.verify(digitalSignature);
        
        System.out.println("Tampered Message: " + tamperedMessage);
        System.out.println("Verification Result: " + (tamperedValid ? "✅ VALID" : "❌ INVALID"));
        System.out.println("Notice: Signature verification fails for modified message!");
        
        System.out.println("\nPress Enter to continue...");
        scanner.nextLine();
    }
    
    private static void explainSenderReceiverInteraction() {
        System.out.println("\n📚 SENDER-RECEIVER INTERACTION");
        System.out.println("=" + "=".repeat(32));
        
        System.out.println("\n🎭 Real-World Scenario: Alice sends a contract to Bob");
        
        System.out.println("\n👩‍💼 ALICE (SENDER) PROCESS:");
        System.out.println("1. 📄 Writes important contract document");
        System.out.println("2. 🔐 Calculates SHA256 hash of the contract");
        System.out.println("3. 🔑 Signs the hash with her PRIVATE key");
        System.out.println("4. 📤 Sends to Bob:");
        System.out.println("   • Original contract");
        System.out.println("   • Digital signature");
        System.out.println("   • Alice's PUBLIC key (or certificate)");
        
        System.out.println("\n👨‍💼 BOB (RECEIVER) PROCESS:");
        System.out.println("1. 📥 Receives the package from Alice");
        System.out.println("2. 🔓 Uses Alice's PUBLIC key to decrypt the signature");
        System.out.println("3. 🔐 Calculates SHA256 hash of received contract");
        System.out.println("4. ⚖️ Compares the two hashes:");
        System.out.println("   • Hash from signature (what Alice signed)");
        System.out.println("   • Hash of received contract (what Bob calculated)");
        System.out.println("5. ✅ If hashes match: Contract is authentic and unmodified");
        System.out.println("6. ❌ If hashes differ: Contract was tampered with or forged");
        
        System.out.println("\n🔒 SECURITY GUARANTEES:");
        System.out.println("• AUTHENTICATION: Bob knows the contract came from Alice");
        System.out.println("  (Only Alice has the private key to create valid signatures)");
        System.out.println("• INTEGRITY: Bob knows the contract wasn't modified");
        System.out.println("  (Any change would make hash verification fail)");
        System.out.println("• NON-REPUDIATION: Alice can't deny she sent it");
        System.out.println("  (Her private key was needed to create the signature)");
        
        System.out.println("\n🌐 PUBLIC KEY DISTRIBUTION:");
        System.out.println("• Alice's public key must be shared safely");
        System.out.println("• Usually done through Certificate Authorities (CAs)");
        System.out.println("• Or through secure key exchange protocols");
        System.out.println("• Public keys can be shared openly (hence 'public')");
        
        System.out.println("\nPress Enter to continue...");
        scanner.nextLine();
    }
    
    private static void simulateSenderReceiverCommunication() throws Exception {
        System.out.println("\n🎭 SENDER-RECEIVER SIMULATION");
        System.out.println("=" + "=".repeat(31));
        
        System.out.println("You are Alice (sender). Bob will verify your message.\n");
        
        // Alice (sender) side
        System.out.print("Alice, enter your message to send to Bob: ");
        String aliceMessage = scanner.nextLine();
        
        System.out.println("\n👩‍💼 ALICE'S ACTIONS:");
        System.out.println("1. Message: " + aliceMessage);
        
        // Calculate hash
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] messageHash = digest.digest(aliceMessage.getBytes());
        System.out.println("2. Calculated SHA256 hash");
        
        // Sign with Alice's private key
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(keyPair.getPrivate());
        signature.update(aliceMessage.getBytes());
        byte[] digitalSignature = signature.sign();
        System.out.println("3. Signed hash with private key");
        System.out.println("4. 📤 Sending to Bob: Message + Signature + Public Key");
        
        // Simulate network transmission
        System.out.println("\n🌐 TRANSMISSION OVER NETWORK...");
        System.out.println("📡 Data packet sent to Bob");
        
        // Bob (receiver) side
        System.out.println("\n👨‍💼 BOB'S VERIFICATION:");
        System.out.println("1. 📥 Received message: " + aliceMessage);
        System.out.println("2. 📥 Received digital signature");
        System.out.println("3. 📥 Received Alice's public key");
        
        // Verify signature
        signature.initVerify(keyPair.getPublic());
        signature.update(aliceMessage.getBytes());
        boolean isValid = signature.verify(digitalSignature);
        
        System.out.println("4. 🔍 Verifying signature...");
        System.out.println("5. 🔐 Calculated hash of received message");
        System.out.println("6. 🔓 Decrypted signature using Alice's public key");
        System.out.println("7. ⚖️ Comparing hashes...");
        
        if (isValid) {
            System.out.println("\n✅ BOB'S CONCLUSION:");
            System.out.println("• Message is authentic (came from Alice)");
            System.out.println("• Message is intact (not modified)");
            System.out.println("• Alice cannot deny sending this message");
            System.out.println("• ✅ SIGNATURE VERIFICATION: SUCCESS");
        } else {
            System.out.println("\n❌ BOB'S CONCLUSION:");
            System.out.println("• Something is wrong!");
            System.out.println("• Message may be forged or tampered with");
            System.out.println("• ❌ SIGNATURE VERIFICATION: FAILED");
        }
        
        // Simulate tampering
        System.out.println("\n🚨 SIMULATION: What if someone tampers with the message?");
        String tamperedMessage = aliceMessage + " [HACKED]";
        signature.initVerify(keyPair.getPublic());
        signature.update(tamperedMessage.getBytes());
        boolean tamperedValid = signature.verify(digitalSignature);
        
        System.out.println("Tampered message: " + tamperedMessage);
        System.out.println("Verification result: " + (tamperedValid ? "✅ VALID" : "❌ INVALID"));
        System.out.println("☝️ This shows how digital signatures detect tampering!");
        
        System.out.println("\nPress Enter to continue...");
        scanner.nextLine();
    }
    
    private static void explainQuantumThreat() {
        System.out.println("\n📚 QUANTUM THREAT TO SHA256 & RSA");
        System.out.println("=" + "=".repeat(34));
        
        System.out.println("\n⚠️ Why are SHA256 and RSA NOT Quantum-Safe?");
        
        System.out.println("\n🔐 RSA VULNERABILITY:");
        System.out.println("• RSA security relies on the difficulty of factoring large numbers");
        System.out.println("• Classical computers need exponential time to factor large numbers");
        System.out.println("• 🚨 Shor's Algorithm (1994) can factor numbers efficiently on quantum computers");
        System.out.println("• A sufficiently large quantum computer could break RSA in hours/days");
        System.out.println("• Current RSA keys (2048, 4096 bits) would be useless against quantum attacks");
        
        System.out.println("\n🔐 SHA256 VULNERABILITY:");
        System.out.println("• SHA256 has 256-bit security against classical computers");
        System.out.println("• 🚨 Grover's Algorithm (1996) provides quadratic speedup for search problems");
        System.out.println("• Quantum computers could effectively reduce SHA256 to 128-bit security");
        System.out.println("• While not broken, this significantly reduces security margin");
        System.out.println("• SHA512 or SHA3-256 might be better quantum-resistant choices");
        
        System.out.println("\n⏰ TIMELINE CONCERNS:");
        System.out.println("• Google's quantum computers: 70+ qubits (2023)");
        System.out.println("• IBM's roadmap: 1000+ qubit systems by 2030");
        System.out.println("• Cryptographically relevant quantum computer: estimated 2030-2040");
        System.out.println("• 🚨 'Y2Q' (Years to Quantum): When quantum computers break current crypto");
        
        System.out.println("\n🛡️ POST-QUANTUM CRYPTOGRAPHY SOLUTIONS:");
        System.out.println("• NIST Post-Quantum Cryptography Competition (2016-2022)");
        System.out.println("• Selected algorithms:");
        System.out.println("  - CRYSTALS-Kyber (Key encapsulation)");
        System.out.println("  - CRYSTALS-Dilithium (Digital signatures)");
        System.out.println("  - FALCON (Digital signatures)");
        System.out.println("  - SPHINCS+ (Digital signatures)");
        
        System.out.println("\n🔄 MIGRATION STRATEGY:");
        System.out.println("• Hybrid approach: Use both classical and post-quantum algorithms");
        System.out.println("• Crypto-agility: Design systems to easily update cryptographic algorithms");
        System.out.println("• Start planning migration now (before quantum computers arrive)");
        System.out.println("• Update certificates, protocols, and implementations");
        
        System.out.println("\n📊 COMPARISON:");
        System.out.println("Algorithm    | Classical Security | Quantum Security | Status");
        System.out.println("-------------|-------------------|------------------|------------------");
        System.out.println("RSA-2048     | ~112 bits         | ~0 bits          | Quantum-vulnerable");
        System.out.println("SHA256       | 256 bits          | ~128 bits        | Quantum-weakened");
        System.out.println("Kyber-768    | ~192 bits         | ~192 bits        | Quantum-safe");
        System.out.println("Dilithium-3  | ~190 bits         | ~190 bits        | Quantum-safe");
        
        System.out.println("\n💡 KEY TAKEAWAY:");
        System.out.println("Current cryptography (RSA, ECDSA, DH) will be obsolete in quantum era.");
        System.out.println("Organizations must start transitioning to post-quantum cryptography NOW!");
        
        System.out.println("\nPress Enter to continue...");
        scanner.nextLine();
    }
    
    private static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }
}
