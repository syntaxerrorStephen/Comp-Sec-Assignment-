import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.Scanner;

public class App {

    private static final String AES = "AES";
    private static SecretKey secretKey;

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        // Create an AES key when the program starts
        System.out.println("Creating an AES encryption key...");
        secretKey = generateKey();

        while (true) {
            // Show menu options
            System.out.println("\n=== AES Encryption Menu ===");
            System.out.println("1. Encrypt text");
            System.out.println("2. Decrypt text");
            System.out.println("3. Exit");
            System.out.print("Choose an option: ");

            // Use the helper method to get a valid integer input
            int choice = getValidIntegerInput(scanner); 

            switch (choice) {
                case 1:
                    System.out.print("Enter the text to encrypt: ");
                    String textToEncrypt = scanner.nextLine();
                    String encryptedText = encrypt(textToEncrypt, secretKey);
                    System.out.println("Encrypted: " + encryptedText);
                    break;

                case 2:
                    System.out.print("Enter the text to decrypt: ");
                    String textToDecrypt = scanner.nextLine();
                    String decryptedText = decrypt(textToDecrypt, secretKey);
                    System.out.println("Decrypted: " + decryptedText);
                    break;

                case 3:
                    System.out.println("Exiting... Goodbye!");
                    System.exit(0);

                default:
                    System.out.println("Invalid option. Please select again.");
            }
        }
    }

    // Helper method to safely get a valid integer input
    private static int getValidIntegerInput(Scanner scanner) {
        while (true) {
            try {
                // This parses the input as an integer and returns it
                return Integer.parseInt(scanner.nextLine()); 
            } catch (NumberFormatException e) {
                System.out.print("Invalid input. Please enter a number: ");
            }
        }
    }

    // Generates an AES encryption key
    private static SecretKey generateKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(AES);
            // Using a 128 bit key becaue of it was better supported
            // Also Chris said it was fine
            keyGen.init(128); 
            return keyGen.generateKey();
        } catch (Exception e) {
            throw new RuntimeException("Key generation failed: " + e.getMessage());
        }
    }

    // Encrypts a plaintext string using AES
    private static String encrypt(String plainText, SecretKey key) {
        try {
            Cipher cipher = Cipher.getInstance(AES);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            throw new RuntimeException("Encryption failed: " + e.getMessage());
        }
    }

    // Decrypts an AES-encrypted string
    private static String decrypt(String encryptedText, SecretKey key) {
        try {
            Cipher cipher = Cipher.getInstance(AES);
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
            return new String(decryptedBytes);
        } catch (Exception e) {
            return "Decryption failed. Please verify the input.";
        }
    }
}
