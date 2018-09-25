package org.wso2.carbon.crypto.hsmbasedcryptoprovider;

import org.wso2.carbon.base.api.ServerConfigurationService;
import org.wso2.carbon.crypto.api.CertificateInfo;
import org.wso2.carbon.crypto.api.CryptoContext;
import org.wso2.carbon.crypto.api.KeyResolver;
import org.wso2.carbon.crypto.api.PrivateKeyInfo;

/**
 *
 */
public class HSMBasedKeyResolver extends KeyResolver {

    public HSMBasedKeyResolver(ServerConfigurationService serverConfigurationService) {

    }

    @Override
    public boolean isApplicable(CryptoContext cryptoContext) {
        return true;
    }

    @Override
    public PrivateKeyInfo getPrivateKeyInfo(CryptoContext cryptoContext) {
        PrivateKeyInfo privateKeyInfo = new PrivateKeyInfo(cryptoContext.getTenantDomain(), null);
        return privateKeyInfo;
    }

    @Override
    public CertificateInfo getCertificateInfo(CryptoContext cryptoContext) {
        CertificateInfo certificateInfo = new CertificateInfo(cryptoContext.getTenantDomain(), null);
        return certificateInfo;
    }
}
