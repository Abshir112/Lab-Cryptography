package Lab1Exercise;

import java.security.*;
import java.security.cert.CertificateFactory;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;

public class Lab1Exercise {
    public static void main(String[] args) throws Exception {
        // Define file paths
        String keystorePath = "lab1Store";
        String encryptedFilePath = "ciphertext.enc";
        String signaturePath1 = "ciphertext.enc.sig1";
        String signaturePath2 = "ciphertext.enc.sig2";
        String certificatePath = "lab1Sign.cert";
        String macFilePath1 = "ciphertext.mac1.txt";
        String macFilePath2 = "ciphertext.mac2.txt";

        // Read the encrypted file content
        byte[] encryptedFileContent = Files.readAllBytes(Paths.get(encryptedFilePath));

        // Divide into  128 bytes for each part
        byte[] rsaEncryptedKey = Arrays.copyOfRange(encryptedFileContent, 0, 128);
        byte[] rsaEncryptedIV = Arrays.copyOfRange(encryptedFileContent, 128, 256);
        byte[] rsaEncryptedHmacKey = Arrays.copyOfRange(encryptedFileContent, 256, 384);
        byte[] aesEncryptedData = Arrays.copyOfRange(encryptedFileContent, 384, encryptedFileContent.length);

        // Load the keystore
        KeyStore keyStore = KeyStore.getInstance("JKS");
        try (FileInputStream keystoreFis = new FileInputStream(keystorePath)) {
            keyStore.load(keystoreFis, "lab1StorePass".toCharArray());
        }
        PrivateKey privateKey = (PrivateKey) keyStore.getKey("lab1EncKeys", "lab1KeyPass".toCharArray());


        // RSA decryption
        Cipher rsaCipher = Cipher.getInstance("RSA");
        rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] key1 = rsaCipher.doFinal(rsaEncryptedKey);
        byte[] iv = rsaCipher.doFinal(rsaEncryptedIV);
        byte[] key2 = rsaCipher.doFinal(rsaEncryptedHmacKey);

        // AES decryption
        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aesCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key1, "AES"), new IvParameterSpec(iv));
        byte[] plaintext = aesCipher.doFinal(aesEncryptedData);


        // Output results
        System.out.println("Decrypted message: \n" + new String(plaintext));


        // Lab 2
        // Reading HMACs from files
        // Reading MAC strings and convert them to byte arrays
        String mac1String = new String(Files.readAllBytes(Paths.get(macFilePath1)));
        String mac2String = new String(Files.readAllBytes(Paths.get(macFilePath2)));
        byte[] hmac1 = hexStringToByteArray(mac1String);
        byte[] hmac2 = hexStringToByteArray(mac2String);

        // Verify HMAC
        boolean hmacVerified1 = verifyHmac(plaintext, key2, hmac1);
        boolean hmacVerified2 = verifyHmac(plaintext, key2, hmac2);

        // Read public key from certificate

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        PublicKey publicKey = cf.generateCertificate(new FileInputStream(certificatePath)).getPublicKey();

        // Read signatures
        byte[] signature1 = Files.readAllBytes(Paths.get(signaturePath1));
        byte[] signature2 = Files.readAllBytes(Paths.get(signaturePath2));

        // Verify signatures
        boolean signatureVerified1 = verifySignature(plaintext, signature1, publicKey);
        boolean signatureVerified2 = verifySignature(plaintext, signature2, publicKey);

        // Output results
        System.out.println("HMAC 1 verification: " + hmacVerified1);
        System.out.println("HMAC 2 verification: " + hmacVerified2);
        System.out.println("Signature 1 verification: " + signatureVerified1);
        System.out.println("Signature 2 verification: " + signatureVerified2);
    }

    private static boolean verifyHmac(byte[] data, byte[] key, byte[] expectedHmac) throws Exception {
        Mac mac = Mac.getInstance("HmacMD5");
        mac.init(new SecretKeySpec(key, "HmacMD5"));
        byte[] computedHmac = mac.doFinal(data);
        return Arrays.equals(computedHmac, expectedHmac);
    }

    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    private static boolean verifySignature(byte[] plaintext, byte[] signature, PublicKey publicKey) throws Exception {
        Signature sig = Signature.getInstance("SHA1withRSA");
        sig.initVerify(publicKey);
        sig.update(plaintext);
        return sig.verify(signature);
    }

    /**
     why it's not advisable to simply encrypt plaintext with the receiver's public key and the reasons for
     generating Key1, IV, and encrypting them:

     - Performance Issues:
     - Encrypting large data directly with public key cryptography (like RSA) is significantly slower
     compared to symmetric encryption methods (like AES).
     - Generating and using a symmetric key (Key1) for bulk data encryption is much more efficient.

     - Key Management and Flexibility:
     - Using a symmetric key (Key1) allows for easier key management.
     The same public-private key pair can be used to encrypt multiple symmetric keys for different sessions or recipients.
     - This adds flexibility in communication, allowing one public-private key pair to secure multiple conversations or data transfers.

     - Security Considerations:
     - Symmetric encryption with a secret key (Key1) and IV (Initialization Vector) provides strong security when properly implemented.
     - IV adds an extra layer of security by ensuring that the same plaintext block encrypts to different
     ciphertext blocks across different encryptions, thus preventing pattern leakage.

     - Resource Constraints:
     - In many practical scenarios, especially in environments with limited computational resources (like IoT devices),
     using symmetric encryption is more feasible due to lower resource requirements.

     In summary, using a symmetric key (Key1) with an IV for the bulk of data encryption, and
     then encrypting these symmetric keys with the receiver's public key, provides a balance of efficiency, security, and flexibility,
     overcoming the limitations of using public key encryption directly for the entire plaintext.







     - MAC Verification Without Pre-shared Secret:
     - A MAC, like HmacMD5, relies on a shared secret key between sender and receiver.
     - If the receiver doesn't have a pre-shared secret with the sender, they can't independently verify the MAC.
     - In this scenario, the MAC alone doesn't authenticate the sender or confirm the message's origin.
     - Without a pre-shared secret, the MAC could be computed by anyone with access to the message and key, compromising authenticity.

     - Trust and Origin Authentication:
     - Without a pre-shared secret or digital signature, trust in the message origin is limited.
     - The MAC verifies data integrity (unchanged data), not the sender's identity.
     - The security of the message is compromised if the encryption keys or MAC key are intercepted.

     - Importance of Digital Signature:
     - Digital signatures, which are not used in this case, provide sender authentication and non-repudiation.
     - Without digital signatures, there's no reliable way to verify the sender's identity or
     ensure the message wasn't altered in transit by a third party.

     In summary, a correct MAC without a pre-shared secret and digital signatures does not authenticate the sender or
     fully ensure the trustworthiness of the message's origin. It only ensures the integrity of the message.
     Sender authentication and non-repudiation are not provided in this scenario.
     */
}



