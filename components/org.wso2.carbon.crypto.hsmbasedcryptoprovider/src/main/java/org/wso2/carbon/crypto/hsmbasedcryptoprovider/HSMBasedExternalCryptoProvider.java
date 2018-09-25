package org.wso2.carbon.crypto.hsmbasedcryptoprovider;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.objects.*;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.api.ServerConfigurationService;
import org.wso2.carbon.crypto.api.*;
import org.wso2.carbon.crypto.hsmbasedcryptoprovider.cryptoprovider.objecthandlers.CertificateHandler;
import org.wso2.carbon.crypto.hsmbasedcryptoprovider.cryptoprovider.objecthandlers.KeyHandler;
import org.wso2.carbon.crypto.hsmbasedcryptoprovider.cryptoprovider.operators.Cipher;
import org.wso2.carbon.crypto.hsmbasedcryptoprovider.cryptoprovider.operators.SignatureHandler;
import org.wso2.carbon.crypto.hsmbasedcryptoprovider.cryptoprovider.util.MechanismResolver;
import org.wso2.carbon.crypto.hsmbasedcryptoprovider.cryptoprovider.util.SessionHandler;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;

import static org.wso2.carbon.crypto.hsmbasedcryptoprovider.cryptoprovider.util.CryptoConstants.*;

/**
 *
 */
public class HSMBasedExternalCryptoProvider implements ExternalCryptoProvider {

    private static final String EXTERNAL_PROVIDER_SLOT_PROPERTY_PATH =
            "CryptoService.HSMBasedCryptoProviderConfig.ExternalProvider.ExternalProviderSlotID";

    private static Log log = LogFactory.getLog(HSMBasedExternalCryptoProvider.class);

    private ServerConfigurationService serverConfigurationService;
    private SessionHandler sessionHandler;
    private MechanismResolver mechanismResolver;

    public HSMBasedExternalCryptoProvider(ServerConfigurationService serverConfigurationService)
            throws CryptoException {
        sessionHandler = SessionHandler.getDefaultSessionHandler(serverConfigurationService);
        this.serverConfigurationService = serverConfigurationService;
        mechanismResolver = new MechanismResolver();
    }

    @Override
    public byte[] sign(byte[] data, String algorithm, String javaSecurityAPIProvider, CryptoContext cryptoContext,
                       PrivateKeyInfo privateKeyInfo) throws CryptoException {

        failIfMethodParametersInvalid(algorithm, javaSecurityAPIProvider);

        PrivateKey privateKeyTemplate = new PrivateKey();
        privateKeyTemplate.getLabel().setCharArrayValue(privateKeyInfo.getKeyAlias().toCharArray());
        PrivateKey signingKey = (PrivateKey) retrieveKey(privateKeyTemplate);
        Mechanism signMechanism = mechanismResolver.resolveMechanism(SIGN_MODE, algorithm, data);
        Session session = initiateSession();
        SignatureHandler signatureHandler = new SignatureHandler();
        byte[] sign = signatureHandler.sign(session, data, signingKey, signMechanism);
        return sign;
    }

    @Override
    public byte[] decrypt(byte[] ciphertext, String algorithm, String javaSecurityAPIProvider,
                          CryptoContext cryptoContext, PrivateKeyInfo privateKeyInfo) throws CryptoException {

        failIfMethodParametersInvalid(algorithm, javaSecurityAPIProvider);

        PrivateKey privateKeyTemplate = new PrivateKey();
        privateKeyTemplate.getLabel().setCharArrayValue(privateKeyInfo.getKeyAlias().toCharArray());
        PrivateKey decryptionKey = (PrivateKey) retrieveKey(privateKeyTemplate);
        Mechanism decryptionMechanism = mechanismResolver.resolveMechanism(DECRYPT_MODE, algorithm, ciphertext);
        Session session = initiateSession();
        Cipher cipher = new Cipher();
        byte[] clearText = cipher.decrypt(session, ciphertext, decryptionKey, decryptionMechanism);
        return clearText;
    }

    @Override
    public byte[] encrypt(byte[] data, String algorithm, String javaSecurityAPIProvider,
                          CryptoContext cryptoContext, CertificateInfo certificateInfo) throws CryptoException {

        failIfMethodParametersInvalid(algorithm, javaSecurityAPIProvider);
        X509PublicKeyCertificate certificate = (X509PublicKeyCertificate)
                retrieveCertificate(certificateInfo.getCertificateAlias());
        PublicKey publicKeyTemplate = new PublicKey();
        publicKeyTemplate.getSubject().setByteArrayValue(certificate.getSubject().getByteArrayValue());
        publicKeyTemplate.getObjectClass().setLongValue(PKCS11Constants.CKO_PUBLIC_KEY);
        PublicKey encryptionKey = (PublicKey) retrieveKey(publicKeyTemplate);
        Mechanism encryptionMechanism = mechanismResolver.resolveMechanism(ENCRYPT_MODE, algorithm, data);
        Cipher cipher = new Cipher();
        Session session = initiateSession();
        byte[] cipherText = cipher.encrypt(session, data, encryptionKey, encryptionMechanism);
        return cipherText;
    }

    @Override
    public boolean verifySignature(byte[] data, byte[] signature, String algorithm, String javaSecurityAPIProvider,
                                   CryptoContext cryptoContext, CertificateInfo certificateInfo) throws CryptoException {

        failIfMethodParametersInvalid(algorithm, javaSecurityAPIProvider);

        X509PublicKeyCertificate certificate = (X509PublicKeyCertificate)
                retrieveCertificate(certificateInfo.getCertificateAlias());
        PublicKey publicKeyTemplate = new PublicKey();
        publicKeyTemplate.getSubject().setByteArrayValue(certificate.getValue().getByteArrayValue());
        publicKeyTemplate.getObjectClass().setLongValue(PKCS11Constants.CKO_PUBLIC_KEY);
        PublicKey verificationKey = (PublicKey) retrieveKey(publicKeyTemplate);
        Mechanism verifyMechanism = mechanismResolver.resolveMechanism(VERIFY_MODE, algorithm, data);
        SignatureHandler signatureHandler = new SignatureHandler();
        Session session = initiateSession();
        boolean verification = signatureHandler.verify(session, data, signature, verificationKey, verifyMechanism);

        return verification;
    }

    @Override
    public java.security.cert.Certificate getCertificate(CryptoContext cryptoContext,
                                                         CertificateInfo certificateInfo) throws CryptoException {

        failIfContextInformationIsMissing(cryptoContext);

        java.security.cert.Certificate certificate = null;
        Certificate retrievedCertificate = retrieveCertificate(certificateInfo.getCertificateAlias());
        try {
            if (retrievedCertificate instanceof X509PublicKeyCertificate) {
                byte[] x509Certificate = ((X509PublicKeyCertificate) retrievedCertificate)
                        .getValue().getByteArrayValue();

                certificate = CertificateFactory.getInstance("X.509").generateCertificate(
                        new ByteArrayInputStream(x509Certificate));
            }
        } catch (CertificateException e) {
            throw new CryptoException();
        }
        if (certificate == null) {
            throw new CryptoException();
        }
        return certificate;
    }

    @Override
    public java.security.PrivateKey getPrivateKey(CryptoContext cryptoContext,
                                                  PrivateKeyInfo privateKeyInfo) throws CryptoException {

        failIfContextInformationIsMissing(cryptoContext);

        java.security.PrivateKey privateKey = null;

        PrivateKey privateKeyTemplate = new PrivateKey();
        privateKeyTemplate.getLabel().setCharArrayValue(privateKeyInfo.getKeyAlias().toCharArray());
        privateKeyTemplate.getObjectClass().setLongValue(PKCS11Constants.CKO_PRIVATE_KEY);
        PrivateKey retrievedKey = (PrivateKey) retrieveKey(privateKeyTemplate);
        try {
            if (!retrievedKey.getSensitive().getBooleanValue() && retrievedKey.getExtractable().getBooleanValue()) {

                if (retrievedKey instanceof RSAPrivateKey) {
                    RSAPrivateKey retrievedRSAKey = (RSAPrivateKey) retrievedKey;
                    BigInteger privateExponent = new BigInteger(retrievedRSAKey.
                            getPrivateExponent().getByteArrayValue());
                    BigInteger modulus = new BigInteger(retrievedRSAKey.getModulus().getByteArrayValue());
                    privateKey = KeyFactory.getInstance("RSA").generatePrivate(new
                            RSAPrivateKeySpec(modulus, privateExponent));
                }
            } else {
                throw new CryptoException();
            }
        } catch (InvalidKeySpecException e) {
            throw new CryptoException();
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException();
        }
        return privateKey;
    }

    private Session initiateSession() throws CryptoException {
        return sessionHandler.initiateSession(
                Integer.valueOf(serverConfigurationService.getFirstProperty(EXTERNAL_PROVIDER_SLOT_PROPERTY_PATH)));
    }

    private void failIfContextInformationIsMissing(CryptoContext cryptoContext) throws CryptoException {
        if (cryptoContext.getTenantId() == 0 || StringUtils.isBlank(cryptoContext.getTenantDomain())) {
            throw new CryptoException("Tenant information is missing in the crypto context.");
        }
    }

    private void failIfMethodParametersInvalid(String algorithm, String javaSecurityProvider) throws CryptoException {
        if (!(javaSecurityProvider != null && javaSecurityProvider.equals("HSMBasedProvider"))) {
            throw new CryptoException();
        }

        if (!(algorithm != null && MechanismResolver.getMechanisms().containsKey(algorithm))) {
            throw new CryptoException();
        }
    }

    private Key retrieveKey(Key keyTemplate) throws CryptoException {
        KeyHandler keyHandler = new KeyHandler();
        Session session = initiateSession();
        Key retrievedKey = (Key) keyHandler.retrieveKey(session, keyTemplate);
        sessionHandler.closeSession(session);
        return retrievedKey;
    }

    private Certificate retrieveCertificate(String label) throws CryptoException {
        Session session = initiateSession();
        CertificateHandler certificateHandler = new CertificateHandler();
        Certificate certificateTemplate = new Certificate();
        certificateTemplate.getLabel().setCharArrayValue(label.toCharArray());
        Certificate retrievedCertificate =
                (Certificate) certificateHandler.getCertificate(session, certificateTemplate);
        if (retrievedCertificate == null) {
            throw new CryptoException();
        }
        return retrievedCertificate;
    }
}