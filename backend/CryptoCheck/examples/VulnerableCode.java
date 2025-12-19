import java.util.Random;
import java.security.MessageDigest;
import javax.crypto.Cipher;

/**
 * Exemple de code vulnérable pour tester le scanner CryptoCheck.
 * Ce fichier contient intentionnellement plusieurs vulnérabilités cryptographiques.
 */
public class VulnerableCode {
    
    public void vulnerableAES() throws Exception {
        // Vulnérabilité: AES/ECB
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        
        // Vulnérabilité: AES sans padding
        Cipher cipher2 = Cipher.getInstance("AES/CBC/NoPadding");
    }
    
    public void vulnerableRandom() {
        // Vulnérabilité: Random au lieu de SecureRandom
        Random random = new Random();
        int value = random.nextInt();
    }
    
    public void vulnerableHashing() throws Exception {
        // Vulnérabilité: MD5
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        
        // Vulnérabilité: SHA-1
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
    }
}

