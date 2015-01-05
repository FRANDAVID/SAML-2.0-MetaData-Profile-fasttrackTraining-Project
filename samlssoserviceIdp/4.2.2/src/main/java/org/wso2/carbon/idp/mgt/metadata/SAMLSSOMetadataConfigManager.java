package org.wso2.carbon.idp.mgt.metadata;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.ArtifactResolutionService;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.provider.FilesystemMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.parse.BasicParserPool;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.persistence.IdentityPersistenceManager;
import org.wso2.carbon.idp.mgt.dto.SAMLSSOIdentityProviderDTO;
import org.wso2.carbon.registry.core.Registry;
import org.wso2.carbon.registry.core.session.UserRegistry;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

/**
 * Created by rajee on 12/31/14.
 */
public class SAMLSSOMetadataConfigManager {
    private static final Log log = LogFactory.getLog(SAMLSSOMetadataConfigManager.class);
    private final UserRegistry registry;
    public static String check = "0";


    public SAMLSSOMetadataConfigManager(Registry userRegistry) {
        registry = (UserRegistry) userRegistry;
    }

    /**
     * read SAML object by uploading SAML metadata file
     *
     * @param fileContent content of a file
     * @return SAMLSSOServiceProviderDTO object
     */

    public SAMLSSOIdentityProviderDTO readServiceProvidersFromFile(String fileContent) throws IOException {

        String assertionConsumerServiceURL = null;
        SAMLSSOIdentityProviderDTO identityProviderDTO = new SAMLSSOIdentityProviderDTO();
        File metadataFile = new File("metadataFile");
        FileOutputStream fos = null;
        byte[] fileContentByteArray = fileContent.getBytes();


        try {
            fos = new FileOutputStream(metadataFile);
            fos.write(fileContentByteArray);
            FilesystemMetadataProvider filesystemMetadataProvider;
            DefaultBootstrap.bootstrap();
            filesystemMetadataProvider = new FilesystemMetadataProvider(metadataFile);
            filesystemMetadataProvider.setRequireValidMetadata(true);
            filesystemMetadataProvider.setParserPool(new BasicParserPool());
            filesystemMetadataProvider.initialize();

            EntityDescriptor entityDescriptor = (EntityDescriptor) filesystemMetadataProvider.getMetadata();

            String idpIssuerId = entityDescriptor.getEntityID();

            String spIssuerId = entityDescriptor.getIDPSSODescriptor(SAMLConstants.SAML20P_NS).getID();


            for (ArtifactResolutionService acs : entityDescriptor.getIDPSSODescriptor(SAMLConstants.SAML20P_NS)
                    .getArtifactResolutionServices()) {
                assertionConsumerServiceURL = acs.getLocation();

            }
            System.out.println("-------------------");
            System.out.println("identity entity Id  " + idpIssuerId);
            System.out.println("-------------------");
            System.out.println("-------------------");
            System.out.println("service provider entity Id  " + spIssuerId);
            System.out.println("-------------------");
            System.out.println("-------------------");
            System.out.println("SAML SSO service url  " + assertionConsumerServiceURL);
            System.out.println("-------------------");

            identityProviderDTO.setIdpEntityId(idpIssuerId);
            identityProviderDTO.setSpEntityId(spIssuerId);
            identityProviderDTO.setUrlSSO(assertionConsumerServiceURL);


        } catch (IOException e) {
            log.error("IO exception" + e);

        } catch (MetadataProviderException e) {
            log.error("metadata provider exception" + e);

        } catch (ConfigurationException e) {
            log.error("configuration exception" + e);

        } finally {

            assert fos != null;
            fos.flush();
            fos.close();
        }


        return identityProviderDTO;

    }


    /**
     * add SAML metadata file to registry
     *
     * @param fileContent content of a file
     * @param issuer      name of the issuer
     * @return boolean value
     * @throws IdentityException
     */
    public boolean addMetadataSAMLSSOFileResource(String fileContent, String issuer) throws IdentityException {
        IdentityPersistenceManager persistenceManager = null;
        try {
            System.out.println("persistant manager hit");
            persistenceManager = IdentityPersistenceManager.getPersistanceManager();
        } catch (IdentityException e) {
            log.error(e + "Adding error service provider metadata file  to registry");
        }
        return persistenceManager.addMetadataIdentityProvider(registry, fileContent, issuer);
    }


}
