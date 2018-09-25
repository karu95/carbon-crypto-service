package org.wso2.carbon.crypto.hsmbasedcryptoprovider.cryptoprovider.operators;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.Key;
import org.wso2.carbon.crypto.api.CryptoException;

/**
 *
 */
public class Cipher {

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
                throw new CryptoException("Data encryption error occurred.", e);
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
     * @return
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
                throw new CryptoException("Data decryption error occurred.", e);
            }
        }
        return decryptedData;
    }
}
