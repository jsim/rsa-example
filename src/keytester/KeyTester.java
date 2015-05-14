package keytester;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 *
 * @author jsim
 */
public class KeyTester {

    public static void main(String[] args) {

        final KeyManager keyManager = new KeyManager();

        //keyManager.generateNewKeys();
        keyManager.load();

        final String original = "Toto je moje husta testovaci zprava.";

        final byte[] encrypted = encrypt(original, keyManager.getPublicKey());
        final String decrypted = decrypt(encrypted, keyManager.getPrivateKey());

        System.out.println("Original  : " + original);
        System.out.println("Decrypted : " + decrypted);
    }

    public static byte[] encrypt(String text, PublicKey key) {
        byte[] cipherText = null;
        try {

            final Cipher cipher = Cipher.getInstance("RSA");

            cipher.init(Cipher.ENCRYPT_MODE, key);
            cipherText = cipher.doFinal(text.getBytes());
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        return cipherText;
    }

    public static String decrypt(byte[] text, PrivateKey key) {
        byte[] dectyptedText = null;
        try {
            final Cipher cipher = Cipher.getInstance("RSA");

            cipher.init(Cipher.DECRYPT_MODE, key);
            dectyptedText = cipher.doFinal(text);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
            ex.printStackTrace();
        }

        return new String(dectyptedText);
    }

}
