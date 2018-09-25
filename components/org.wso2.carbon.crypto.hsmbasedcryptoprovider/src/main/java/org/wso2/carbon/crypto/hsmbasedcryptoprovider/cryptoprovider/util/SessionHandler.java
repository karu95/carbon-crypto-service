package org.wso2.carbon.crypto.hsmbasedcryptoprovider.cryptoprovider.util;


import iaik.pkcs.pkcs11.*;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.wso2.carbon.base.api.ServerConfigurationService;
import org.wso2.carbon.crypto.api.CryptoException;

import java.io.IOException;
import java.util.HashMap;


/**
 * This class is responsible for handling sessions between application and the HSM.
 */
public class SessionHandler {

    private static final String PKCS11_MODULE_PROPERTY_PATH =
            "CryptoService.HSMBasedCryptoProviderConfig.HSMConfiguration.PKCS11Module";
    private static final String PKCS11_SLOT_CONFIGURATION_PROPERTY_PATH =
            "CryptoService.HSMBasedCryptoProviderConfig.HSMConfiguration.SlotConfiguration";
    private static SessionHandler sessionHandler;

    private Slot[] slotsWithTokens = null;
    private Module pkcs11Module;
    private ServerConfigurationService serverConfigurationService;
    private HashMap<Integer, String> configuredSlots = new HashMap<>();

    /**
     * Singleton design pattern is used.
     *
     * @param serverConfigurationService
     * @return Default instance of SessionHandler.
     * @throws CryptoException
     */
    public static SessionHandler getDefaultSessionHandler(ServerConfigurationService serverConfigurationService)
            throws CryptoException {
        if (sessionHandler == null) {
            sessionHandler = new SessionHandler(serverConfigurationService);
        }
        return sessionHandler;
    }

    private SessionHandler(ServerConfigurationService serverConfigurationService) throws CryptoException {
        try {
            pkcs11Module = Module.getInstance(serverConfigurationService.getFirstProperty(PKCS11_MODULE_PROPERTY_PATH));
        } catch (IOException e) {
            throw new CryptoException();
        }
        this.serverConfigurationService = serverConfigurationService;
        setupSlotConfiguration();
    }

    /**
     * Initiate a session for a given slot.
     *
     * @param slotNo : Slot number of the required session
     * @return Instance of a Session.
     * @throws CryptoException
     */
    public Session initiateSession(int slotNo) throws CryptoException {
        Session session = null;
        if (slotsWithTokens == null) {
            try {
                slotsWithTokens = pkcs11Module.getSlotList(Module.SlotRequirement.TOKEN_PRESENT);
            } catch (TokenException e) {
                throw new CryptoException("Session initiation error : " + e.getMessage());
            }
        }
        if (slotsWithTokens.length > slotNo) {
            Slot slot = slotsWithTokens[slotNo];
            try {
                Token token = slot.getToken();
                session = token.openSession(Token.SessionType.SERIAL_SESSION,
                        Token.SessionReadWriteBehavior.RW_SESSION, null, null);
                session.login(Session.UserType.USER, getUserPIN(slotNo));
            } catch (TokenException e) {
                throw new CryptoException("Session initiation error : " + e.getMessage());
            }
        } else {
            throw new CryptoException("Slot is not configured for cryptographic operations.");
        }
        return session;
    }

    /**
     * Close the given session.
     *
     * @param session : Session that need to be closed.
     * @throws CryptoException
     */
    public void closeSession(Session session) throws CryptoException {
        if (session != null) {
            try {
                session.closeSession();
            } catch (TokenException e) {
                throw new CryptoException("Error occurred during session closing : " + e.getMessage());
            }
        }
    }

    private char[] getUserPIN(int slotID) throws CryptoException {
        if (configuredSlots.containsKey(slotID)) {
            return configuredSlots.get(slotID).toCharArray();
        } else {
            throw new CryptoException("Slot configuration is not provided.");
        }
    }

    private void setupSlotConfiguration() throws CryptoException {
        NodeList configuredSlotsCandidateNodes = this.serverConfigurationService.getDocumentElement().
                getElementsByTagName("SlotConfiguration");
        if (configuredSlotsCandidateNodes != null) {
            Node hsmSlotConfiguration = configuredSlotsCandidateNodes.item(0);
            NodeList configuredSlots = hsmSlotConfiguration.getChildNodes();
            for (int i = 0; i < configuredSlots.getLength(); i++) {
                Node configuredSlot = configuredSlots.item(i);
                if (configuredSlot.getNodeType() == Node.ELEMENT_NODE && "Slot".equals(configuredSlot.getNodeName())) {
                    NamedNodeMap attributes = configuredSlot.getAttributes();
                    int id = Integer.valueOf(attributes.getNamedItem("id").getTextContent());
                    String pin = attributes.getNamedItem("pin").getTextContent();
                    if (!this.configuredSlots.containsKey(id)) {
                        this.configuredSlots.put(id, pin);
                    }
                }
            }
        } else {
            throw new CryptoException("Slot configuration is not provided.");
        }
    }
}
