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

package org.wso2.carbon.identity.sso.saml;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.core.AbstractAdmin;
import org.wso2.carbon.core.util.KeyStoreUtil;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sso.saml.admin.SAMLSSOConfigAdmin;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOServiceProviderDTO;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOServiceProviderInfoDTO;
import org.wso2.carbon.identity.sso.saml.metadata.SAMLSSOMetadataConfigManager;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;
import org.wso2.carbon.security.SecurityConfigException;
import org.wso2.carbon.security.keystore.KeyStoreAdmin;
import org.wso2.carbon.security.keystore.service.KeyStoreData;
import org.wso2.carbon.user.api.Claim;
import org.wso2.carbon.user.api.ClaimMapping;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.io.IOException;

public class SAMLSSOConfigService extends AbstractAdmin {

    private static Log log = LogFactory.getLog(SAMLSSOConfigService.class);
    //public static boolean fileAddedReg = false;

    /**
     * @param spDto
     * @return
     * @throws IdentityException
     */
    public boolean addRPServiceProvider(SAMLSSOServiceProviderDTO spDto) throws IdentityException {
        SAMLSSOConfigAdmin configAdmin = new SAMLSSOConfigAdmin(getConfigSystemRegistry());
        return configAdmin.addRelyingPartyServiceProvider(spDto);
    }

    /**
     * @return
     * @throws IdentityException
     */
    public SAMLSSOServiceProviderInfoDTO getServiceProviders() throws IdentityException {
        SAMLSSOConfigAdmin configAdmin = new SAMLSSOConfigAdmin(getConfigSystemRegistry());
        return configAdmin.getServiceProviders();
    }

    /**
     * @return
     * @throws IdentityException
     */
    private KeyStoreData[] getKeyStores() throws IdentityException {
        try {
            KeyStoreAdmin admin = new KeyStoreAdmin(CarbonContext.getThreadLocalCarbonContext()
                    .getTenantId(), getGovernanceRegistry());
            boolean isSuperAdmin = MultitenantConstants.SUPER_TENANT_ID == CarbonContext
                    .getThreadLocalCarbonContext().getTenantId() ? true : false;
            return admin.getKeyStores(isSuperAdmin);
        } catch (SecurityConfigException e) {
            log.error("Error when loading the key stores from registry", e);
            throw new IdentityException("Error when loading the key stores from registry", e);
        }
    }

    /**
     * @return
     * @throws IdentityException
     */
    public String[] getCertAliasOfPrimaryKeyStore() throws IdentityException {
        KeyStoreData[] keyStores = getKeyStores();
        KeyStoreData primaryKeyStore = null;
        for (int i = 0; i < keyStores.length; i++) {
            boolean superTenant = MultitenantConstants.SUPER_TENANT_ID == CarbonContext
                    .getThreadLocalCarbonContext().getTenantId() ? true : false;
            if (superTenant && KeyStoreUtil.isPrimaryStore(keyStores[i].getKeyStoreName())) {
                primaryKeyStore = keyStores[i];
                break;
            } else if (!superTenant
                    && SAMLSSOUtil.generateKSNameFromDomainName(getTenantDomain()).equals(
                    keyStores[i].getKeyStoreName())) {
                primaryKeyStore = keyStores[i];
                break;
            }
        }
        if (primaryKeyStore != null) {
            return getStoreEntries(primaryKeyStore.getKeyStoreName());
        }
        throw new IdentityException("Primary Keystore cannot be found.");
    }

    /**
     * @param issuer
     * @return
     * @throws IdentityException
     */
    public boolean removeServiceProvider(String issuer) throws IdentityException {
        SAMLSSOConfigAdmin ssoConfigAdmin = new SAMLSSOConfigAdmin(getConfigSystemRegistry());
        return ssoConfigAdmin.removeServiceProvider(issuer);
    }

    /**
     * @return
     * @throws IdentityException
     */
    public String[] getClaimURIs() throws IdentityException {
        String tenatUser = MultitenantUtils.getTenantAwareUsername(CarbonContext
                .getThreadLocalCarbonContext().getUsername());
        String domainName = MultitenantUtils.getTenantDomain(tenatUser);
        String[] claimUris = null;
        try {
            UserRealm realm = IdentityTenantUtil.getRealm(domainName, tenatUser);
            String claimDialect = IdentityUtil
                    .getProperty(IdentityConstants.ServerConfig.SSO_ATTRIB_CLAIM_DIALECT);

            if (claimDialect == null || claimDialect.equals("")) {
                // set default
                claimDialect = "http://wso2.org/claims";
            }

            ClaimMapping[] claims = realm.getClaimManager().getAllClaimMappings(claimDialect);
            claimUris = new String[claims.length];

            for (int i = 0; i < claims.length; i++) {
                Claim claim = claims[i].getClaim();
                claimUris[i] = claim.getClaimUri();
            }

        } catch (IdentityException e) {
            log.error("Error while getting realm for " + tenatUser, e);
            throw new IdentityException("Error while getting realm for " + tenatUser + e);
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            log.error("Error while getting claims for " + tenatUser, e);
            throw new IdentityException("Error while getting claims for " + tenatUser + e);
        }
        return claimUris;
    }

    /**
     * @param keyStoreName
     * @return
     * @throws IdentityException
     */
    private String[] getStoreEntries(String keyStoreName) throws IdentityException {
        KeyStoreAdmin admin;
        try {
            admin = new KeyStoreAdmin(CarbonContext.getThreadLocalCarbonContext().getTenantId(),
                    getGovernanceRegistry());
            return admin.getStoreEntries(keyStoreName);
        } catch (SecurityConfigException e) {
            log.error("Error reading entries from the key store : " + keyStoreName);
            throw new IdentityException("Error reading entries from the keystore" + e);
        }
    }

    /**
     * add SAML SSO object by uploading file from local system
     *
     * @param fileContent content of a file
     * @return SAMLSSOServiceProviderDO
     * @throws IdentityException
     */
    public SAMLSSOServiceProviderDTO addMetadataServiceProvider(String fileContent) throws IdentityException, IOException {
        System.out.println("backend  read service provider from file hit" + fileContent.length());

        SAMLSSOMetadataConfigManager metadataConfigManager = new SAMLSSOMetadataConfigManager(getConfigUserRegistry());
        //fileAddedReg = metadataConfigManager.addMetadataSAMLSSOFileResource(fileContent,SAMLSSOMetadataConfigManager.issuer);
        return metadataConfigManager.readServiceProvidersFromFile(fileContent);
    }

    /**
     * add SAML SSO object by uploading file from local system
     *
     * @param metadataUrl url of a metadata file
     * @return SAMLSSOServiceProviderDO
     * @throws IdentityException
     */
    public SAMLSSOServiceProviderDTO addMetadataServiceProviderUrl(String metadataUrl) throws IdentityException, IOException {
        System.out.println("backend  read service provider from file hit" + metadataUrl.length());

        SAMLSSOMetadataConfigManager metadataConfigManager = new SAMLSSOMetadataConfigManager(getConfigUserRegistry());
        //fileAddedReg = metadataConfigManager.addMetadataSAMLSSOFileResource(fileContent,SAMLSSOMetadataConfigManager.issuer);
        return metadataConfigManager.readServiceProvidersFromUrl(metadataUrl);
    }

    /**
     * check metadata file is added to registry
     *
     * @param fileContent content of a file
     * @return boolean
     * @throws IdentityException
     */
    public String isMetadataFileAdded(String fileContent, String issuer) throws IdentityException {
        boolean fileAddedStatus = false;
        String fileAddedStatusS;
        System.out.println("add metadata service hit");
        SAMLSSOMetadataConfigManager metadataConfigManager = new SAMLSSOMetadataConfigManager(getConfigUserRegistry());
        fileAddedStatus = metadataConfigManager.addMetadataSAMLSSOFileResource(fileContent, issuer);
        if (fileAddedStatus == true) {
            fileAddedStatusS = "true";
        } else {
            fileAddedStatusS = "false";
        }
        return fileAddedStatusS;
    }

    /**
     * check metadata SAML object is added to registry
     *
     * @param samlssoServiceProviderDO SAMLSSO objcet
     * @return boolean
     * @throws IdentityException
     */
    public boolean isMetadataFileSAMLObjectAdded(SAMLSSOServiceProviderDO samlssoServiceProviderDO) throws IdentityException {
        SAMLSSOMetadataConfigManager metadataConfigManager = new SAMLSSOMetadataConfigManager(getConfigUserRegistry());
        return metadataConfigManager.addMetadataSAMLSSOObject(samlssoServiceProviderDO);
    }

}
