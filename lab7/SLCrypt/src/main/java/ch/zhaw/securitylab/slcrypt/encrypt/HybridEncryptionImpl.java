package ch.zhaw.securitylab.slcrypt.encrypt;

import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import ch.zhaw.securitylab.slcrypt.FileHeader;
import ch.zhaw.securitylab.slcrypt.Helpers;

/**
 * A concrete implementation of the abstract class HybridEncryption.
 */
public class HybridEncryptionImpl extends HybridEncryption {

    /**
     * Creates a secret key.
     *
     * @param cipherAlgorithm The cipher algorithm to use
     * @param keyLength The key length in bits
     * @return The secret key
     */
    @Override
    protected byte[] generateSecretKey(String cipherAlgorithm, int keyLength) {
        System.out.println("Generating secret key...");

        KeyGenerator generator;
        SecretKey key = null;
        try {
            generator = KeyGenerator.getInstance(Helpers.getCipherName(cipherAlgorithm));
            generator.init(keyLength);
            key = generator.generateKey();
        } catch (NoSuchAlgorithmException e) {
            System.err.println(
                "The algorithm: "
                + cipherAlgorithm
                + " does not exist or is not supported!"
            );
            System.exit(1);
        }
        return key.getEncoded();
    }

    /**
     * Encrypts the secret key with a public key.
     *
     * @param secretKey The secret key to encrypt
     * @param certificateEncrypt An input stream from which the certificate with
     *                           the public key for encryption can be read
     * @return The encrypted secret key
     */
    @Override
    protected byte[] encryptSecretKey(
        byte[] secretKey,
        InputStream certificateEncrypt
    ) {
        System.out.println("Encrypting secret key...");

        byte[] encryptedKey = null;

        try {
            CertificateFactory certificateReader = CertificateFactory.getInstance("X.509");
            Certificate certificate = certificateReader.generateCertificate(certificateEncrypt);
            // This algorithm was specified in the task
            Cipher RSACipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
            // We don't specify an IV because ECB does not use an IV
            RSACipher.init(Cipher.ENCRYPT_MODE, certificate);
            encryptedKey = RSACipher.doFinal(secretKey);
        } catch (CertificateException e) {
            System.err.println("An error occured when trying to read the Certicate that contains the public key");
            System.exit(1);
        } catch (InvalidKeyException e) {
            System.err.println("Could not encrypt the secret key because the public has an invalid format.");
            System.exit(1);
        }  catch(Exception e){
            System.err.println("Unexpected error" + e);
            System.exit(1);
        }
        return encryptedKey;
    }

    /**
     * Creates a file header object and fills it with the cipher algorithm name,
     * the authentication and integrity protection type and name, and the
     * encrypted secret key.
     *
     * @param cipherAlgorithm The cipher algorithm to use
     * @param authIntType The type to use for authentication and integrity
     *                    protection (M for MAC, S for signature, N for none)
     * @param authIntAlgorithm The algorithm to use for authentication and
     *                         integrity protection
     * @param certificateVerify An input stream from which the certificate for
     *                          signature verification can be read
     * @param encryptedSecretKey The encrypted secret key
     * @return The new file header object
     */
    @Override
    protected FileHeader generateFileHeader(String cipherAlgorithm,
            char authIntType, String authIntAlgorithm,
            InputStream certificateVerify, byte[] encryptedSecretKey) {
        System.out.println("Generating file header...");

        FileHeader fileHeader = new FileHeader();
        fileHeader.setCipherAlgorithm(cipherAlgorithm);
        fileHeader.setAuthIntType(authIntType);
        fileHeader.setEncryptedSecretKey(encryptedSecretKey);
        if (authIntType == Helpers.NONE) {
            fileHeader.setAuthIntAlgorithm("");
        } else {
            fileHeader.setAuthIntAlgorithm(authIntAlgorithm);
        }
        if (authIntType == Helpers.SIGNATURE) {
            fileHeader.setCertificate(Helpers.inputStreamToByteArray(certificateVerify));
        } else {
            fileHeader.setCertificate(new byte[]{});
        }
        if (Helpers.hasIV(cipherAlgorithm)){

            SecureRandom random = new SecureRandom();
            byte IV[] = new byte[Helpers.getIVLength(cipherAlgorithm)];
            random.nextBytes(IV);
            fileHeader.setIV(IV);
        } else {
            
            fileHeader.setIV(new byte[]{});
        }
        return fileHeader;
    }

    /**
     * Encrypts a document with a secret key. If GCM is used, the file header is
     * added as additionally encrypted data.
     *
     * @param document The document to encrypt
     * @param fileHeader The file header that contains information for
     * encryption
     * @param secretKey The secret key used for encryption
     * @return A byte array that contains the encrypted document
     */
    @Override
    protected byte[] encryptDocument(InputStream document,
            FileHeader fileHeader, byte[] secretKey) {
        System.out.println("Encrypting document...");

        byte[] encryptedDocument = null;
        Cipher cipher = null;
        String algorithmName = fileHeader.getCipherAlgorithm();

        try {
            cipher = Cipher.getInstance(algorithmName);
            SecretKeySpec key = new SecretKeySpec(secretKey, algorithmName);
            System.out.println("Algorithm:" + algorithmName);
            if (Helpers.isCBC(algorithmName) || Helpers.isCTR(algorithmName)) {
                cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(fileHeader.getIV()));
            } else if (Helpers.isCHACHA20(algorithmName)) {

                cipher.init(
                    Cipher.ENCRYPT_MODE,
                    key,
                    new ChaCha20ParameterSpec(fileHeader.getIV(), 1)
                );
            } else if (Helpers.isGCM(algorithmName)) {
                GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(Helpers.AUTH_TAG_LENGTH, fileHeader.getIV());
                cipher.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);
                cipher.updateAAD(fileHeader.encode());
            } else {
                cipher.init(Cipher.ENCRYPT_MODE, key);
            }
        } catch (NoSuchAlgorithmException e) {
            System.err.println(
                "The algorithm "
                + Helpers.getCipherName(algorithmName)
                + " does not exist or is not supported!"
            );
            System.exit(1);
        } catch (NoSuchPaddingException e) {
            System.err.println("The specified padding alogirithm does not exist!");
            System.exit(1);
        } catch (Exception e){
            System.err.println("Unexpected error" + e);
            System.exit(1);
        }

        try (CipherInputStream chiperStream = new CipherInputStream(document, cipher)) {
            encryptedDocument = chiperStream.readAllBytes();
        } catch (IOException e) {
            System.err.println("Unexpected error when trying to encrypt the document!");
            System.err.println(e.toString());
            System.exit(1);
        }

        return encryptedDocument;
    }

    /**
     * Computes the HMAC over a byte array.
     *
     * @param dataToProtect The input over which to compute the MAC
     * @param macAlgorithm The MAC algorithm to use
     * @param password The password to use for the MAC
     * @return The byte array that contains the MAC
     */
    @Override
    protected byte[] computeMAC(byte[] dataToProtect, String macAlgorithm,
            byte[] password) {
        System.out.println("Computing MAC...");

        byte[] computedHash = null;

        try {
            SecretKeySpec keyGenerator = new SecretKeySpec(password, macAlgorithm);
            Mac macGenerator = Mac.getInstance(macAlgorithm);
            macGenerator.init(keyGenerator);
            computedHash = macGenerator.doFinal(dataToProtect);
        } catch (NoSuchAlgorithmException e) {
            System.err.println(
                "The MAC algorithm"
                + macAlgorithm
                + "does not exist or is not supported!");
            System.exit(1);
        } catch (Exception e){
            System.err.println("unexpected error" +e );
        }
        return computedHash;
    }

    /**
     * Computes the signature over a byte array.
     *
     * @param dataToProtect The input over which to compute the signature
     * @param signatureAlgorithm The signature algorithm to use
     * @param privateKeySign An input stream from which the private key to sign
     *                       can be read
     * @return The byte array that contains the signature
     */
    @Override
    protected byte[] computeSignature(byte[] dataToProtect,
            String signatureAlgorithm, InputStream privateKeySign) {
        System.out.println("Computing signature...");

        byte[] computedSignature = null;
        try {
            Signature signatureGenerator = Signature.getInstance(signatureAlgorithm);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Helpers.inputStreamToByteArray(privateKeySign));
            KeyFactory rsaKeyFactory = KeyFactory.getInstance("RSA");
            signatureGenerator.initSign(rsaKeyFactory.generatePrivate(keySpec));
            signatureGenerator.update(dataToProtect);
            computedSignature = signatureGenerator.sign();
        } catch (NoSuchAlgorithmException e) {
            System.err.println(
                "The signature algorithm"
                + signatureAlgorithm
                + "does not exist or is not supported!");
            System.exit(1);
        } catch (Exception e){
            System.err.println("unexpected error" +e );
        }
        return computedSignature;
    }
}