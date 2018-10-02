package org.wso2.carbon.crypto.hsmbasedcryptoprovider.cryptoprovider.operators;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.Key;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.crypto.api.CryptoException;
import org.wso2.carbon.crypto.hsmbasedcryptoprovider.cryptoprovider.util.HSMCryptoException;

/**
 * This class is responsible for carrying out encrypt/decrypt operations.
 */
public class Cipher {

    private static Log log  = LogFactory.getLog(Cipher.class);

    /**
     * Constructor of a Cipher instance.
     */
    public Cipher() {
    }

    /**
     * Method to encrypt a given set of data using a given key.
     *
     * @param session             : Instance of the session used for encryption.
     * @param dataToBeEncrypted   : Byte array of data to be encrypted.
     * @param encryptionKey       : Key used for encryption.
     * @param encryptionMechanism : Encrypting mechanism.
     * @return : Byte array of encrypted data.
     * @throws CryptoException
     */
    public byte[] encrypt(Session session, byte[] dataToBeEncrypted,
                          Key encryptionKey, Mechanism encryptionMechanism) throws CryptoException {

        byte[] encryptedData = null;
        if (encryptionMechanism.isSingleOperationEncryptDecryptMechanism()
                || encryptionMechanism.isFullEncryptDecryptMechanism()) {
            try {
                session.encryptInit(encryptionMechanism, encryptionKey);
                encryptedData = session.encrypt(dataToBeEncrypted);
            } catch (TokenException e) {
                String errorMessage = String.format("Error occurred while encrypting data using algorithm '%s' .",
                        encryptionMechanism.getName());
                if (log.isDebugEnabled()) {
                    log.debug(errorMessage, e);
                }
                throw new HSMCryptoException(errorMessage, e);
            }
        }
        return encryptedData;
    }

    /**
     * Method to decrypt a given set of data using a given key.
     *
     * @param session             : Instance of the session used for decryption.
     * @param dataToBeDecrypted   : Byte array of data to be decrypted.
     * @param decryptionKey       : Key used for decryption.
     * @param decryptionMechanism : Decrypting mechanism.
     * @return : Byte array of decrypted data
     * @throws CryptoException
     */
    public byte[] decrypt(Session session, byte[] dataToBeDecrypted,
                          Key decryptionKey, Mechanism decryptionMechanism) throws CryptoException {

        byte[] decryptedData = null;
        if (decryptionMechanism.isSingleOperationEncryptDecryptMechanism()
                || decryptionMechanism.isFullEncryptDecryptMechanism()) {
            try {
                session.decryptInit(decryptionMechanism, decryptionKey);
                decryptedData = session.decrypt(dataToBeDecrypted);
            } catch (TokenException e) {
                String errorMessage = String.format("Error occurred while decrypting data using algorithm '%s'.",
                        decryptionMechanism.getName());
                if (log.isDebugEnabled()) {
                    log.debug(errorMessage, e);
                }
                throw new HSMCryptoException(errorMessage, e);
            }
        }
        return decryptedData;
    }
}
