package org.wso2.carbon.crypto.hsmbasedcryptoprovider.cryptoprovider.operators;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.PublicKey;
import org.wso2.carbon.crypto.api.CryptoException;

/**
 *
 */
public class SignatureHandler {

    /**
     * Constructor for signature handler.
     */
    public SignatureHandler() {
    }

    /**
     * Method to digitally sign a given data with the given mechanism.
     *
     * @param session       : Session used to perform signing.
     * @param dataToSign    : Data to be signed.
     * @param signMechanism : Signing mechanism
     * @param signKey       : Key used for signing.
     * @return signature as a byte array.
     * @throws TokenException
     */
    public byte[] sign(Session session, byte[] dataToSign,
                       PrivateKey signKey, Mechanism signMechanism) throws CryptoException {
        byte[] signature = null;
        if (signMechanism.isFullSignVerifyMechanism() ||
                signMechanism.isSingleOperationSignVerifyMechanism()) {
            try {
                session.signInit(signMechanism, signKey);
                signature = session.sign(dataToSign);
            } catch (TokenException e) {
                throw new CryptoException("Sign generation error.", e);
            }
        }
        return signature;
    }

    /**
     * Method to verify a given data with given mechanism.
     *
     * @param session         : Session used to perform verifying.
     * @param dataToVerify    : Data to be verified.
     * @param signature       : Signature of the data.
     * @param verifyMechanism : verifying mechanism.
     * @param verificationKey : Key used for verification.
     * @return True if verified.
     */
    public boolean verify(Session session, byte[] dataToVerify, byte[] signature,
                          PublicKey verificationKey, Mechanism verifyMechanism) throws CryptoException {
        boolean verified = false;
        if (verifyMechanism.isFullSignVerifyMechanism()) {
            try {
                session.verifyInit(verifyMechanism, verificationKey);
                session.verify(dataToVerify, signature);
                verified = true;
            } catch (TokenException e) {
                if (!e.getMessage().equals("")) {
                    throw new CryptoException("Sign verification error.", e);
                }
            }
        }
        return verified;
    }
}
