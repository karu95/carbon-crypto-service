package org.wso2.carbon.crypto.hsmbasedcryptoprovider.cryptoprovider.util;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.parameters.InitializationVectorParameters;
import iaik.pkcs.pkcs11.parameters.RSAPkcsOaepParameters;
import iaik.pkcs.pkcs11.parameters.RSAPkcsPssParameters;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import org.wso2.carbon.crypto.api.CryptoException;

import java.util.HashMap;
import java.util.Random;

/**
 * This class is used to resolve JCE standard mechanism names to PKCS #11 mechanisms.
 */
public class MechanismResolver {

    private static final HashMap<String, Long> mechanisms = new HashMap<String, Long>() {{
        /**
         * Encrypt/Decrypt mechanisms
         */
        //DES mechanisms
        put("DES/CBC/NoPadding", PKCS11Constants.CKM_DES_CBC);
        put("DES/CBC/PKCS5Padding", PKCS11Constants.CKM_DES_CBC_PAD);
        put("DES/ECB/NoPadding", PKCS11Constants.CKM_DES_ECB);

        //DES3 mechanisms
        put("DESede/CBC/NoPadding", PKCS11Constants.CKM_DES3_CBC);
        put("DESede/CBC/PKCS5Padding", PKCS11Constants.CKM_DES3_CBC_PAD);
        put("DESede/ECB/NoPadding", PKCS11Constants.CKM_DES3_ECB);

        //AES mechanisms
        put("AES/CBC/NoPadding", PKCS11Constants.CKM_AES_CBC);
        put("AES_128/CBC/NoPadding", PKCS11Constants.CKM_AES_CBC);
        put("AES_192/CBC/NoPadding", PKCS11Constants.CKM_AES_CBC);
        put("AES_256/CBC/NoPadding", PKCS11Constants.CKM_AES_CBC);
        put("AES/CBC/PKCS5Padding", PKCS11Constants.CKM_AES_CBC_PAD);
        put("AES_128/CBC/PKCS5Padding", PKCS11Constants.CKM_AES_CBC_PAD);
        put("AES_192/CBC/PKCS5Padding", PKCS11Constants.CKM_AES_CBC_PAD);
        put("AES_256/CBC/PKCS5Padding", PKCS11Constants.CKM_AES_CBC_PAD);
        put("AES/ECB/NoPadding", PKCS11Constants.CKM_AES_ECB);
        put("AES_128/ECB/NoPadding", PKCS11Constants.CKM_AES_ECB);
        put("AES_192/ECB/NoPadding", PKCS11Constants.CKM_AES_ECB);
        put("AES_256/ECB/NoPadding", PKCS11Constants.CKM_AES_ECB);
        put("AES/CCM/NoPadding", PKCS11Constants.CKM_AES_CCM);
        put("AES_128/CCM/NoPadding", PKCS11Constants.CKM_AES_CCM);
        put("AES_192/CCM/NoPadding", PKCS11Constants.CKM_AES_CCM);
        put("AES_256/CCM/NoPadding", PKCS11Constants.CKM_AES_CCM);
        put("AES/GCM/NoPadding", PKCS11Constants.CKM_AES_GCM);
        put("AES_128/GCM/NoPadding", PKCS11Constants.CKM_AES_GCM);
        put("AES_192/GCM/NoPadding", PKCS11Constants.CKM_AES_GCM);
        put("AES_256/GCM/NoPadding", PKCS11Constants.CKM_AES_GCM);


        //RC2


        //RSA mechanisms
        put("RSA/ECB/OAEPwithMD5andMGF1Padding", PKCS11Constants.CKM_RSA_PKCS_OAEP);
        put("RSA/ECB/OAEPwithSHA1andMGF1Padding", PKCS11Constants.CKM_RSA_PKCS_OAEP);
        put("RSA/ECB/OAEPwithSHA224andMGF1Padding", PKCS11Constants.CKM_RSA_PKCS_OAEP);
        put("RSA/ECB/OAEPwithSHA256andMGF1Padding", PKCS11Constants.CKM_RSA_PKCS_OAEP);
        put("RSA/ECB/OAEPwithSHA384andMGF1Padding", PKCS11Constants.CKM_RSA_PKCS_OAEP);
        put("RSA/ECB/OAEPwithSHA512andMGF1Padding", PKCS11Constants.CKM_RSA_PKCS_OAEP);
        put("RSA/ECB/PKCS1Padding", PKCS11Constants.CKM_RSA_PKCS);
        put("RSA/ECB/NoPadding", PKCS11Constants.CKM_RSA_X_509);
        put("RSA/ECB/ISO9796Padding", PKCS11Constants.CKM_RSA_9796);

        //Blowfish mechanisms
        put("Blowfish/CBC/NoPadding", PKCS11Constants.CKM_BLOWFISH_CBC);
        put("Blowfish/CBC/PKCS5Padding", PKCS11Constants.CKM_BLOWFISH_CBC);

        /**
         * Sign/Verify mechanisms
         */
        put("RawDSA", PKCS11Constants.CKM_DSA);
        put("DSA", PKCS11Constants.CKM_DSA_SHA1);

        //ECDSA sign/verify mechanisms
        put("NONEwithECDSA", PKCS11Constants.CKM_ECDSA);
        put("SHA1withECDSA", PKCS11Constants.CKM_ECDSA_SHA1);

        //RSA sign/verify mechanisms
        put("MD2withRSA", PKCS11Constants.CKM_MD2_RSA_PKCS);
        put("MD5withRSA", PKCS11Constants.CKM_MD5_RSA_PKCS);
        put("SHA1withRSA", PKCS11Constants.CKM_SHA1_RSA_PKCS);
        put("SHA256withRSA", PKCS11Constants.CKM_SHA256_RSA_PKCS);
        put("SHA384withRSA", PKCS11Constants.CKM_SHA384_RSA_PKCS);
        put("SHA512withRSA", PKCS11Constants.CKM_SHA512_RSA_PKCS);
        put("RipeMd128withRSA", PKCS11Constants.CKM_RIPEMD128_RSA_PKCS);
        put("RipeMd160withRSA", PKCS11Constants.CKM_RIPEMD160_RSA_PKCS);

        put("SHA1withRSAandMGF1", PKCS11Constants.CKM_SHA1_RSA_PKCS_PSS);
        put("SHA256withRSAandMGF1", PKCS11Constants.CKM_SHA256_RSA_PKCS_PSS);
        put("SHA384withRSAandMGF1", PKCS11Constants.CKM_SHA384_RSA_PKCS_PSS);
        put("SHA512withRSAandMGF1", PKCS11Constants.CKM_SHA512_RSA_PKCS_PSS);


        //DSA sign/verify mechanisms
        put("SHA1withDSA", PKCS11Constants.CKM_DSA_SHA1);

        /**
         * Digest mechanisms
         */
        put("SHA1", PKCS11Constants.CKM_SHA_1);
        put("SHA256", PKCS11Constants.CKM_SHA256);
        put("SHA384", PKCS11Constants.CKM_SHA384);
        put("SHA512", PKCS11Constants.CKM_SHA512);
        put("MD2", PKCS11Constants.CKM_MD2);
        put("MD5", PKCS11Constants.CKM_MD5);
        put("RipeMd128", PKCS11Constants.CKM_RIPEMD128);
        put("RipeMd160", PKCS11Constants.CKM_RIPEMD160);
    }};

    private static final HashMap<Long, String> parameterRequiredMechanisms = new HashMap<Long, String>() {{
        put(PKCS11Constants.CKM_AES_CBC, "IV16");
        put(PKCS11Constants.CKM_AES_CBC_PAD, "IV16");

        put(PKCS11Constants.CKM_RSA_PKCS_OAEP, "OAEP");

        put(PKCS11Constants.CKM_DES3_CBC, "IV8");
        put(PKCS11Constants.CKM_DES3_CBC_PAD, "IV8");

        put(PKCS11Constants.CKM_DES_CBC, "IV8");
        put(PKCS11Constants.CKM_DES_CBC_PAD, "IV8");
    }};

    private static final Random randomArrayGenerator = new Random();

    /**
     * Method to retrieve of mechanisms.
     *
     * @return HashMap of mechanisms.
     */
    public static HashMap<String, Long> getMechanisms() {
        return mechanisms;
    }

    public MechanismResolver() {
    }

    /**
     * Method to resolve the PKCS #11 mechanism when JCE mechanism specification is given.
     *
     * @param operatingMode          : Operation related to the mechanism.
     * @param mechanismSpecification : Standard JCE specified name of the mechanism.
     * @param data                   : Data used for cryptographic operation.
     * @return : Properly configured mechanism.
     */
    public Mechanism resolveMechanism(int operatingMode, String mechanismSpecification, byte[] data)
            throws CryptoException {

        Mechanism mechanism = null;
        if (mechanisms.containsKey(mechanismSpecification)) {
            mechanism = Mechanism.get(mechanisms.get(mechanismSpecification));
            if (parameterRequiredMechanisms.containsKey(mechanism.getMechanismCode())) {
                resolveParameters(mechanism, mechanismSpecification, operatingMode, data);
            }
        }
        return mechanism;
    }

    protected void resolveParameters(Mechanism mechanism, String mechanismSpecification, int operatingMode, byte[] data)
            throws CryptoException {

        String parameterSpec = parameterRequiredMechanisms.get(mechanism.getMechanismCode());
        if (parameterSpec.contains("IV")) {
            int ivSize = Integer.parseInt((String)
                    parameterSpec.subSequence(2, parameterSpec.length()));
            mechanism.setParameters(getInitializationVectorParameters(operatingMode, data, ivSize));
        } else if (parameterSpec.contains("OAEP")) {
            String[] specification = mechanismSpecification.split("/");
            mechanism.setParameters(getOAEPParameters(specification[specification.length - 1]));
        } else if (parameterSpec.contains("PSS")) {
            mechanism.setParameters(getRSAPSSParameters(mechanismSpecification));
        }
    }

    protected RSAPkcsOaepParameters getOAEPParameters(String parameter) throws CryptoException {

        String[] specParams = parameter.split("with");
        String[] oaepParams = specParams[1].split("and");
        if (mechanisms.containsKey(oaepParams[0])) {
            return new RSAPkcsOaepParameters(Mechanism.get(mechanisms.get(oaepParams[0])), 1L,
                    PKCS11Constants.CKZ_DATA_SPECIFIED, null);
        } else {
            String errorMessage = String.format("Invalid '%s' OAEP parameter specification", parameter);
            throw new CryptoException(errorMessage);
        }
    }

    protected InitializationVectorParameters getInitializationVectorParameters(int operatingMode,
                                                                             byte[] data, int ivSize) {
        byte[] iv = new byte[ivSize];
        if (operatingMode == 1) {
            randomArrayGenerator.nextBytes(iv);
        } else if (operatingMode == 2) {
            System.arraycopy(data, 0, iv, 0, ivSize);
        }
        return new InitializationVectorParameters(iv);
    }

    protected RSAPkcsPssParameters getRSAPSSParameters(String algorithmSpecification) throws CryptoException {

        if (algorithmSpecification.contains("SHA1")) {
            return new RSAPkcsPssParameters(Mechanism.get(mechanisms.get("SHA1")), 1L,
                    20L);
        } else if (algorithmSpecification.contains("SHA256")) {
            return new RSAPkcsPssParameters(Mechanism.get(mechanisms.get("SHA256")), 1L,
                    32L);
        } else if (algorithmSpecification.contains("SHA384")) {
            return new RSAPkcsPssParameters(Mechanism.get(mechanisms.get("SHA384")), 1L,
                    48L);
        } else if (algorithmSpecification.contains("SHA512")) {
            return new RSAPkcsPssParameters(Mechanism.get(mechanisms.get("SHA512")), 1L,
                    64L);
        } else {
            String errorMessage = String.format("Invalid '%s' algorithm specification", algorithmSpecification);
            throw new CryptoException(errorMessage);
        }
    }
}
