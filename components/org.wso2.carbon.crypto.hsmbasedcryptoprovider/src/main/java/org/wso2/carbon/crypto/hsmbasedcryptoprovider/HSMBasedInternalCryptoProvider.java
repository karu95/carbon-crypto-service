package org.wso2.carbon.crypto.hsmbasedcryptoprovider;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.objects.Key;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.api.ServerConfigurationService;
import org.wso2.carbon.crypto.api.CryptoException;
import org.wso2.carbon.crypto.api.InternalCryptoProvider;
import org.wso2.carbon.crypto.hsmbasedcryptoprovider.cryptoprovider.objecthandlers.KeyHandler;
import org.wso2.carbon.crypto.hsmbasedcryptoprovider.cryptoprovider.operators.Cipher;
import org.wso2.carbon.crypto.hsmbasedcryptoprovider.cryptoprovider.util.MechanismResolver;
import org.wso2.carbon.crypto.hsmbasedcryptoprovider.cryptoprovider.util.SessionHandler;

import static org.wso2.carbon.crypto.hsmbasedcryptoprovider.cryptoprovider.util.CryptoConstants.DECRYPT_MODE;
import static org.wso2.carbon.crypto.hsmbasedcryptoprovider.cryptoprovider.util.CryptoConstants.ENCRYPT_MODE;

/**
 *
 */
public class HSMBasedInternalCryptoProvider implements InternalCryptoProvider {

    private static Log log = LogFactory.getLog(HSMBasedInternalCryptoProvider.class);

    private static final String INTERNAL_PROVIDER_SLOT_PROPERTY_PATH =
            "CryptoService.HSMBasedCryptoProviderConfig.InternalProvider.InternalProviderSlotID";
    private static final String HSM_BASED_INTERNAL_PROVIDER_KEY_ALIAS_PATH =
            "CryptoService.HSMBasedCryptoProviderConfig.InternalProvider.InternalProviderKeyAlias";

    private ServerConfigurationService serverConfigurationService;
    private String keyAlias;
    private SessionHandler sessionHandler;
    private MechanismResolver mechanismResolver;
    private Cipher cipher;

    /**
     * @param serverConfigurationService
     */
    public HSMBasedInternalCryptoProvider(ServerConfigurationService serverConfigurationService)
            throws CryptoException {
        this.serverConfigurationService = serverConfigurationService;
        this.keyAlias = serverConfigurationService.getFirstProperty(HSM_BASED_INTERNAL_PROVIDER_KEY_ALIAS_PATH);
        if (StringUtils.isBlank(keyAlias)) {
            throw new CryptoException();
        }
        sessionHandler = SessionHandler.getDefaultSessionHandler(serverConfigurationService);
        mechanismResolver = new MechanismResolver();
        this.cipher = new Cipher();
    }

    @Override
    public byte[] encrypt(byte[] cleartext, String algorithm, String javaSecurityAPIProvider) throws CryptoException {

        failIfMethodParametersInvalid(algorithm, javaSecurityAPIProvider, cleartext);

        Key keyTemplate = new Key();
        keyTemplate.getLabel().setCharArrayValue(keyAlias.toCharArray());
        Key encryptionKey = retrieveKey(keyTemplate);
        Session session = initiateSession();
        Mechanism encryptionMechanism = mechanismResolver.resolveMechanism(ENCRYPT_MODE, algorithm, cleartext);
        byte[] cipherData = cipher.encrypt(session, cleartext, encryptionKey, encryptionMechanism);
        return cipherData;
    }

    @Override
    public byte[] decrypt(byte[] ciphertext, String algorithm, String javaSecurityAPIProvider) throws CryptoException {
        failIfMethodParametersInvalid(algorithm, javaSecurityAPIProvider, ciphertext);

        Key keyTemplate = new Key();
        keyTemplate.getLabel().setCharArrayValue(keyAlias.toCharArray());
        Key decryptionKey = retrieveKey(keyTemplate);
        Session session = initiateSession();
        Mechanism decryptionMechanism = mechanismResolver.resolveMechanism(DECRYPT_MODE, algorithm, ciphertext);
        byte[] clearText = cipher.decrypt(session, ciphertext, decryptionKey, decryptionMechanism);
        return clearText;
    }

    private Session initiateSession() throws CryptoException {
        return sessionHandler.initiateSession(
                Integer.valueOf(serverConfigurationService.getFirstProperty(INTERNAL_PROVIDER_SLOT_PROPERTY_PATH)));
    }


    private void failIfMethodParametersInvalid(String algorithm, String javaSecurityProvider, byte[] data)
            throws CryptoException {
        if (!(javaSecurityProvider != null && javaSecurityProvider.equals("HSMBasedProvider"))) {
            String errorMessage = "Cryptographic operation provider is invalid.";
            if (log.isErrorEnabled()) {
                log.error(errorMessage);
            }
            throw new CryptoException(errorMessage);
        }

        if (!(algorithm != null && MechanismResolver.getMechanisms().containsKey(algorithm))) {
            String errorMessage = "Requested algorithm is not valid/not supported by the provider.";
            if (log.isErrorEnabled()) {
                log.error(errorMessage);
            }
            throw new CryptoException(errorMessage);
        }

        if (data == null || data.length == 0) {
            String errorMessage = "Data sent for cryptographic operation is not valid.";
            if (log.isErrorEnabled()) {
                log.error(errorMessage);
            }
            throw new CryptoException(errorMessage);
        }
    }

    private Key retrieveKey(Key keyTemplate) throws CryptoException {
        KeyHandler keyHandler = new KeyHandler();
        Session session = initiateSession();
        Key retrievedKey = (Key) keyHandler.retrieveKey(session, keyTemplate);
        sessionHandler.closeSession(session);
        return retrievedKey;
    }
}
