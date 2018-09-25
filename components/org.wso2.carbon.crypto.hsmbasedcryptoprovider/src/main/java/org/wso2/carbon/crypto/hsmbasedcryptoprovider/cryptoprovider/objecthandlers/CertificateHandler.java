package org.wso2.carbon.crypto.hsmbasedcryptoprovider.cryptoprovider.objecthandlers;

import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.Certificate;
import iaik.pkcs.pkcs11.objects.Object;
import org.wso2.carbon.crypto.api.CryptoException;

/**
 *
 */
public class CertificateHandler {

    /**
     * Method to retrieve a given certificate from the HSM.
     *
     * @param session             : Session to retrieve the certificate
     * @param certificateTemplate : Template of the certificate to be retrieved
     * @return
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
            throw new CryptoException("Certificate '" +
                    String.valueOf(certificateTemplate.getLabel().getCharArrayValue()) +
                    "' retrieval error.", e);
        }
        if (certificate == null) {
            throw new CryptoException("Unable to find requested certificate.");
        }
        return certificate;
    }
}
