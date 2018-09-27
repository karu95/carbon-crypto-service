package org.wso2.carbon.crypto.hsmbasedcryptoprovider.cryptoprovider.objecthandlers;

import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.Key;
import iaik.pkcs.pkcs11.objects.Object;
import org.wso2.carbon.crypto.api.CryptoException;
import org.wso2.carbon.crypto.hsmbasedcryptoprovider.cryptoprovider.util.HSMCryptoException;

/**
 * This class is responsible to retrieve keys from the HSM.
 */
public class KeyHandler {

    public KeyHandler() {
    }

    /**
     * Method to retrieve key when template of the key is given.
     *
     * @param session     : Session to retrieve the key.
     * @param keyTemplate : Template of the key to be retrieved.
     * @return retrieved key
     * @throws TokenException
     */
    public Object retrieveKey(Session session, Key keyTemplate) throws CryptoException {

        Object key = null;
        try {
            session.findObjectsInit(keyTemplate);
            Object[] secretKeyArray = session.findObjects(1);
            if (secretKeyArray.length > 0) {
                key = secretKeyArray[0];
            }
        } catch (TokenException e) {
            String errorMessage = String.format("Error occurred while retrieving key for key alias '%s'.",
                    new String(keyTemplate.getLabel().getCharArrayValue()));
            throw new HSMCryptoException(errorMessage, e);
        }
        return key;
    }
}
