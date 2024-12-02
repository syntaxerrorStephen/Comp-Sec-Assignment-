// Stephen Flynn
// D00270479

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;
import java.nio.file.Files;
import java.util.Base64;
import java.util.Scanner;

public class App {

    // Define that we are using AES
    private static final String AES = "AES"; 
     // Store the AES key used for encryption and decryption
    private static SecretKey secretKey;
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        // Generate the AES key when the program starts
        System.out.println("Creating an AES encryption key...");
        secretKey = generateKey();

        // Main loop for the menu, broken when the user chooses to exit
        while (true) {
            // Display menu options to the user
            System.out.println("\n=== AES File Encryption Menu ===");
            System.out.println("1. Encrypt file");
            System.out.println("2. Decrypt file");
            System.out.println("3. Exit");
            System.out.print("Choose an option: ");

            // Get user input and ensure it's a valid integer
            int choice = getValidIntegerInput(scanner); 

            switch (choice) {
                case 1:
                    // Handle file encryption
                    System.out.print("Enter the path to the file to encrypt: ");
                    String filePathToEncrypt = scanner.nextLine();
                    System.out.print("Enter the path to save the encrypted file: ");
                    String encryptedFilePath = scanner.nextLine();
                    if (encryptFile(filePathToEncrypt, encryptedFilePath, secretKey)) {
                        System.out.println("File successfully encrypted and saved to: " + encryptedFilePath);
                    } else {
                        System.out.println("File encryption failed. Please check the file path and try again.");
                    }
                    break;

                case 2:
                    // Handle file decryption
                    System.out.print("Enter the path to the encrypted file: ");
                    String filePathToDecrypt = scanner.nextLine();
                    System.out.print("Enter the path to save the decrypted file: ");
                    String decryptedFilePath = scanner.nextLine();
                    if (decryptFile(filePathToDecrypt, decryptedFilePath, secretKey)) {
                        System.out.println("File successfully decrypted and saved to: " + decryptedFilePath);
                    } else {
                        System.out.println("File decryption failed. Please check the file path and try again.");
                    }
                    break;

                case 3:
                    // Exit the program
                    System.out.println("Exiting... Goodbye!");
                    System.exit(0);

                default:
                    // Handle invalid menu options
                    System.out.println("Invalid option. Please select again.");
            }
        }
    }

    // Helper method to safely get a valid integer input from the user
    private static int getValidIntegerInput(Scanner scanner) {
        while (true) {
            try {
                // Read user input and parse it as an integer
                return Integer.parseInt(scanner.nextLine());
            } catch (NumberFormatException e) {
                // If input is not a valid number, prompt the user to try again
                System.out.print("Invalid input. Please enter a number: ");
            }
        }
    }

    // Generates a new AES encryption key
    private static SecretKey generateKey() {
        try {
            // Use the AES algorithm to generate a 128-bit key
            // Cheers Chris :)
            KeyGenerator keyGen = KeyGenerator.getInstance(AES);
            keyGen.init(128);
            return keyGen.generateKey();
        } catch (Exception e) {
            // Handle any errors during key generation
            throw new RuntimeException("Key generation failed: " + e.getMessage());
        }
    }

    // Encrypts the content of a file and saves the encrypted data to a new file
    private static boolean encryptFile(String inputFilePath, String outputFilePath, SecretKey key) {
        try {
            // Read the entire content of the input file
            byte[] fileData = Files.readAllBytes(new File(inputFilePath).toPath());

            // Initialize the AES cipher in encryption mode
            Cipher cipher = Cipher.getInstance(AES);
            cipher.init(Cipher.ENCRYPT_MODE, key);

            // Encrypt the file data
            byte[] encryptedBytes = cipher.doFinal(fileData);

            // Encode the encrypted data as Base64 and write it to the output file
            Files.write(new File(outputFilePath).toPath(), Base64.getEncoder().encode(encryptedBytes));
            return true;
        } catch (Exception e) {
            // Handle any errors during file encryption
            System.err.println("Encryption error: " + e.getMessage());
            return false;
        }
    }

    // Decrypts the content of an encrypted file and saves the plaintext data to a new file
    private static boolean decryptFile(String inputFilePath, String outputFilePath, SecretKey key) {
        try {
            // Read the entire content of the encrypted input file
            byte[] fileData = Files.readAllBytes(new File(inputFilePath).toPath());

            // Decode the Base64-encoded data
            byte[] decodedData = Base64.getDecoder().decode(fileData);

            // Initialize the AES cipher in decryption mode
            Cipher cipher = Cipher.getInstance(AES);
            cipher.init(Cipher.DECRYPT_MODE, key);

            // Decrypt the data
            byte[] decryptedBytes = cipher.doFinal(decodedData);

            // Write the decrypted data to the output file
            Files.write(new File(outputFilePath).toPath(), decryptedBytes);
            return true;
        } catch (Exception e) {
            // Handle any errors during file decryption (had previous issues with file paths not being entered correct)
            System.err.println("Decryption error: " + e.getMessage());
            return false;
        }
    }
}
