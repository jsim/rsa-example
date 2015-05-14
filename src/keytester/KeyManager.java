package keytester;

import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 *
 * @author jsim
 */
public class KeyManager {

    private final String FILENAME_PRIVATE_KEY = "key1.pk";
    private final String FILENAME_PUBLIC_KEY = "key1.pub";

    private final int KEY_BITS = 2048;

    private PublicKey publicKey;
    private PrivateKey privateKey;

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public void load() {
        final String base64private = loadFromFile(FILENAME_PRIVATE_KEY);
        final String base64public = loadFromFile(FILENAME_PUBLIC_KEY);

        final byte[] privateKeyBytes = Base64.decode(base64private);
        final byte[] publicKeyBytes = Base64.decode(base64public);

        privateKey = bytesToPrivate(privateKeyBytes);
        publicKey = bytesToPublic(publicKeyBytes);
    }

    public void generateNewKeys() {
        final KeyPair keyPair = createKeyPair();

        final String base64private = Base64.encode(keyPair.getPrivate().getEncoded());  // PKCS8 for a private key
        final String base64public = Base64.encode(keyPair.getPublic().getEncoded());  // X509 for a public key

        saveToFile(FILENAME_PRIVATE_KEY, base64private);
        saveToFile(FILENAME_PUBLIC_KEY, base64public);
    }

    private KeyPair createKeyPair() {
        try {
            final SecureRandom sr = new SecureRandom();

            final KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(KEY_BITS, sr);

            return generator.generateKeyPair();
        } catch (NoSuchAlgorithmException ex) {
            ex.printStackTrace();
            return null;
        }
    }

    private PublicKey bytesToPublic(byte[] bytes) {
        try {
            return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(bytes));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            ex.printStackTrace();
            return null;
        }
    }

    private PrivateKey bytesToPrivate(byte[] bytes) {
        try {
            return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(bytes));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            ex.printStackTrace();
            return null;
        }
    }

    private String loadFromFile(String filename) {

        final StringBuilder sb = new StringBuilder();

        final Path path = Paths.get(filename);

        try (BufferedReader reader = Files.newBufferedReader(path)) {
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }
        } catch (IOException ex) {
            ex.printStackTrace();
        }

        return sb.toString();
    }

    private void saveToFile(String filename, String keyData) {

        final File file = new File(filename);

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(file))) {
            writer.write(keyData);
            writer.flush();
            writer.close();
        } catch (IOException ex) {
            ex.printStackTrace();
        }

    }

}
