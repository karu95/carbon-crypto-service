package org.wso2.carbon.crypto.hsmbasedcryptoprovider;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.objects.Key;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.PublicKey;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.api.ServerConfigurationService;
import org.wso2.carbon.crypto.api.CryptoException;
import org.wso2.carbon.crypto.api.ExternalCryptoProvider;
import org.wso2.carbon.crypto.api.InternalCryptoProvider;
import org.wso2.carbon.crypto.hsmbasedcryptoprovider.cryptoprovider.objecthandlers.KeyHandler;
import org.wso2.carbon.crypto.hsmbasedcryptoprovider.cryptoprovider.operators.Cipher;
import org.wso2.carbon.crypto.hsmbasedcryptoprovider.cryptoprovider.util.MechanismResolver;
import org.wso2.carbon.crypto.hsmbasedcryptoprovider.cryptoprovider.util.SessionHandler;

import static org.wso2.carbon.crypto.hsmbasedcryptoprovider.cryptoprovider.util.CryptoConstants.DECRYPT_MODE;
import static org.wso2.carbon.crypto.hsmbasedcryptoprovider.cryptoprovider.util.CryptoConstants.ENCRYPT_MODE;

/**
 * Implementation of {@link InternalCryptoProvider} to provide cryptographic operations using Hardware Security Modules.
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
        PublicKey publicKeyTemplate = new PublicKey();
        publicKeyTemplate.getLabel().setCharArrayValue(keyAlias.toCharArray());
        publicKeyTemplate.getObjectClass().setLongValue(PKCS11Constants.CKO_PUBLIC_KEY);
        PublicKey encryptionKey = (PublicKey) retrieveKey(publicKeyTemplate);
        Mechanism encryptionMechanism = mechanismResolver.resolveMechanism(ENCRYPT_MODE, algorithm, cleartext);
        Session session = initiateSession();
        try {
            return cipher.encrypt(session, cleartext, encryptionKey, encryptionMechanism);
        } finally {
            sessionHandler.closeSession(session);
        }
    }

    @Override
    public byte[] decrypt(byte[] ciphertext, String algorithm, String javaSecurityAPIProvider) throws CryptoException {

        failIfMethodParametersInvalid(algorithm, javaSecurityAPIProvider, ciphertext);

        PrivateKey privateKeyTemplate = new PrivateKey();
        privateKeyTemplate.getLabel().setCharArrayValue(keyAlias.toCharArray());
        privateKeyTemplate.getObjectClass().setLongValue(PKCS11Constants.CKO_PRIVATE_KEY);
        PrivateKey decryptionKey = (PrivateKey) retrieveKey(privateKeyTemplate);
        Mechanism decryptionMechanism = mechanismResolver.resolveMechanism(DECRYPT_MODE, algorithm, ciphertext);
        Session session = initiateSession();
        try {
            return cipher.decrypt(session, ciphertext, decryptionKey, decryptionMechanism);
        } finally {
            sessionHandler.closeSession(session);
        }
    }

    protected Session initiateSession() throws CryptoException {

        return sessionHandler.initiateSession(
                Integer.parseInt(serverConfigurationService.getFirstProperty(INTERNAL_PROVIDER_SLOT_PROPERTY_PATH)));
    }


    protected void failIfMethodParametersInvalid(String algorithm, String javaSecurityProvider, byte[] data)
            throws CryptoException {

        if (!(javaSecurityProvider != null && javaSecurityProvider.equals("BC"))) {
            String errorMessage = String.format("Cryptographic operation provider '%s' is not supported by the " +
                    "provider.", javaSecurityProvider);
            if (log.isDebugEnabled()) {
                log.debug(errorMessage);
            }
            throw new CryptoException(errorMessage);
        }

        if (!(algorithm != null && MechanismResolver.getMechanisms().containsKey(algorithm))) {
            String errorMessage = String.format("Requested algorithm '%s' is not valid/not supported by the " +
                    "provider '%s'.", algorithm, javaSecurityProvider);
            if (log.isDebugEnabled()) {
                log.debug(errorMessage);
            }
            throw new CryptoException(errorMessage);
        }

        if (data == null || data.length == 0) {
            String errorMessage = String.format("Data sent for cryptographic operation is null/empty.");
            if (log.isDebugEnabled()) {
                log.debug(errorMessage);
            }
            throw new CryptoException(errorMessage);
        }
    }

    protected Key retrieveKey(Key keyTemplate) throws CryptoException {

        KeyHandler keyHandler = new KeyHandler();
        Session session = initiateSession();
        Key retrievedKey;
        try {
            retrievedKey = (Key) keyHandler.retrieveKey(session, keyTemplate);
        } finally {
            sessionHandler.closeSession(session);
        }
        return retrievedKey;
    }
}
