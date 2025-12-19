import java.security.SecureRandom;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Exemple de code sécurisé pour comparaison.
 * Ce code utilise les bonnes pratiques cryptographiques.
 */
public class SafeCode {
    
    public void secureAES() throws Exception {
        // Sécurisé: AES/GCM
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        
        // Sécurisé: AES/CBC avec padding
        Cipher cipher2 = Cipher.getInstance("AES/CBC/PKCS5Padding");
    }
    
    public void secureRandom() {
        // Sécurisé: SecureRandom
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[16];
        random.nextBytes(bytes);
    }
    
    public void secureHashing() throws Exception {
        // Sécurisé: SHA-256
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        
        // Sécurisé: SHA-512
        MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
    }
}

