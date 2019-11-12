import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import java.util.Base64;
import java.util.Arrays;

public class Main {

    public static class AESCBC {

        /**
         * 
         * @param data
         * @param key
         * @return base64EncryptedIVData
         * @throws Exception
         */
        public static String encrypt(String data, String key) throws Exception {
            byte[] clean = data.getBytes("UTF-8");

            // Generating IV.
            byte[] iv = new byte[16];
            SecureRandom random = new SecureRandom();
            random.nextBytes(iv);

            System.out.printf("iv: %s\n", Arrays.toString(iv));
            // Encrypt.
            Cipher cipher = getCipher(Cipher.ENCRYPT_MODE, key, iv);
            byte[] encrypted = cipher.doFinal(clean);

            // Combine IV and encrypted part.
            byte[] encryptedIVAndText = new byte[iv.length + encrypted.length];
            System.arraycopy(iv, 0, encryptedIVAndText, 0, iv.length);
            System.arraycopy(encrypted, 0, encryptedIVAndText, iv.length, encrypted.length);

            return Base64.getEncoder().encodeToString(encryptedIVAndText);
        }

        /**
         * 
         * @param base64EncryptedIVData
         * @param key
         * @return
         * @throws Exception
         */
        public static String decrypt(String base64EncryptedIVData, String key) throws Exception {
            byte[] iv = new byte[16];
            byte[] cipherTextCombined = Base64.getDecoder().decode(base64EncryptedIVData);

            // Extract IV.
            System.arraycopy(cipherTextCombined, 0, iv, 0, iv.length);

            // Extract encrypted part.
            int encryptedSize = cipherTextCombined.length - iv.length;
            byte[] encryptedBytes = new byte[encryptedSize];
            System.arraycopy(cipherTextCombined, iv.length, encryptedBytes, 0, encryptedSize);

            System.out.printf("iv: %s\n", Arrays.toString(iv));
            // Decrypt.
            Cipher cipherDecrypt = getCipher(Cipher.DECRYPT_MODE, key, iv);

            byte[] decrypted = cipherDecrypt.doFinal(encryptedBytes);

            return new String(decrypted);
        }

        static Cipher getCipher(int mode, String key, byte[] iv) throws Exception {
            // Hashing key.
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(key.getBytes("UTF-8"));
            SecretKeySpec secretKeySpec = new SecretKeySpec(messageDigest.digest(), "AES");

            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(mode, secretKeySpec, ivParameterSpec);
            return cipher;
        }
    }

    /**
     * Main rutine
     */
    public static void main(String[] args) throws Exception {
        // PrivateKey shared over languages (KEEP always server side)
        String key = "J1M6sncXwq1NEWLRbqpp4SixZ6fphrcO";

        // System.out.println(AESCBC.encrypt("Message", key));
        System.out.println("Java");
        System.out.println(AESCBC.decrypt("88/qWM1tDOsU7BhYWxXQH/jTt9fD17ryDSFuGk6YlPY=", key));
        System.out.println("----");
        System.out.println("C#");
        System.out.println(AESCBC.decrypt("vDvzP32YQbNhSNphM7uas95lMVR0vUs2vJCfEQaDzMo=", key));
        System.out.println("----");
        System.out.println("NodeJs");
        System.out.println(AESCBC.decrypt("+nDpo7CTEfsc7I3eOctVNKM57Ai++DzzOlwohKaMU8c=", key));
    }
}