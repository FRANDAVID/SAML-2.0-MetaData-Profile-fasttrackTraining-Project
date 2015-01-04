/*
 * Copyright 2005-2007 WSO2, Inc. (http://wso2.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.carbon.identity.sso.saml.metadata;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.provider.FilesystemMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.parse.BasicParserPool;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.core.persistence.IdentityPersistenceManager;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOServiceProviderDTO;
import org.wso2.carbon.registry.core.Registry;
import org.wso2.carbon.registry.core.session.UserRegistry;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;


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

    public SAMLSSOServiceProviderDTO readServiceProvidersFromFile(String fileContent) throws IOException {

        String assertionConsumerServiceURL = null;
        SAMLSSOServiceProviderDTO serviceProviderDTO = new SAMLSSOServiceProviderDTO();
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

            String issuer = entityDescriptor.getEntityID();


            for (AssertionConsumerService acs : entityDescriptor.getSPSSODescriptor(SAMLConstants.SAML20P_NS)
                    .getAssertionConsumerServices()) {
                assertionConsumerServiceURL = acs.getLocation();

            }
            System.out.println("-------------------");
            System.out.println("issuer name  " + issuer);
            System.out.println("-------------------");
            System.out.println("-------------------");
            System.out.println("assertion consumer service url  " + assertionConsumerServiceURL);
            System.out.println("-------------------");

            serviceProviderDTO.setIssuer(issuer);
            serviceProviderDTO.setAssertionConsumerUrl(assertionConsumerServiceURL);





        } catch (IOException e) {
            log.error("IO exception" + e);

        } catch (MetadataProviderException e) {
            log.error("metadata provider exception" + e);

        } catch (ConfigurationException e) {
            log.error("configuration exception"+e);

        }
        finally {

            assert fos != null;
            fos.flush();
            fos.close();
        }


        return serviceProviderDTO;

    }

    /**
     * add SAML object to registry
     *
     * @param samlssoServiceProviderDO SAML service provider object
     * @return boolean value
     * @throws IdentityException
     */
    public boolean addMetadataSAMLSSOObject(SAMLSSOServiceProviderDO samlssoServiceProviderDO) throws IdentityException {
        IdentityPersistenceManager persistenceManager = null;
        try {
            persistenceManager = IdentityPersistenceManager.getPersistanceManager();
        } catch (IdentityException e) {
            log.error(e + "Adding error service provider object to registry");
        }
        return persistenceManager != null && persistenceManager.addServiceProvider(registry, samlssoServiceProviderDO);
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
        return persistenceManager != null && persistenceManager.addMetadataServiceProvider(registry, fileContent, issuer);
    }


}