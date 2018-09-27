package org.wso2.carbon.crypto.hsmbasedcryptoprovider.cryptoprovider.objecthandlers;

import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.Certificate;
import iaik.pkcs.pkcs11.objects.Object;
import org.wso2.carbon.crypto.api.CryptoException;
import org.wso2.carbon.crypto.hsmbasedcryptoprovider.cryptoprovider.util.HSMCryptoException;

/**
 * This class is responsible to retrieve certificates from the HSM.
 */
public class CertificateHandler {

    public CertificateHandler() {
    }

    /**
     * Method to retrieve a given certificate from the HSM.
     *
     * @param session             : Session to retrieve the certificate
     * @param certificateTemplate : Template of the certificate to be retrieved
     * @return retrievedCertificate
     */
    public Object getCertificate(Session session, Certificate certificateTemplate) throws CryptoException {

        Object certificate = null;
        try {
            session.findObjectsInit(certificateTemplate);
            Object[] secretKeyArray = session.findObjects(1);
            if (secretKeyArray.length > 0) {
                certificate = secretKeyArray[0];
            }
        } catch (TokenException e) {
            String errorMessage = String.format("Error occurred during retrieving certificate with alias '%s'",
                    String.valueOf(certificateTemplate.getLabel().getCharArrayValue()));
            throw new HSMCryptoException(errorMessage, e);
        }
        return certificate;
    }
}
