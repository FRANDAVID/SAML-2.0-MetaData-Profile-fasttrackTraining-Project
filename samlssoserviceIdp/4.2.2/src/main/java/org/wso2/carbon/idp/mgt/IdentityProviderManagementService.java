/*
 *Copyright (c) 2005-2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *WSO2 Inc. licenses this file to you under the Apache License,
 *Version 2.0 (the "License"); you may not use this file except
 *in compliance with the License.
 *You may obtain a copy of the License at
 *
 *http://www.apache.org/licenses/LICENSE-2.0
 *
 *Unless required by applicable law or agreed to in writing,
 *software distributed under the License is distributed on an
 *"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *KIND, either express or implied.  See the License for the
 *specific language governing permissions and limitations
 *under the License.
 */

package org.wso2.carbon.idp.mgt;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.core.AbstractAdmin;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.ProvisioningConnectorConfig;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.idp.mgt.dto.SAMLSSOIdentityProviderDTO;
import org.wso2.carbon.idp.mgt.internal.IdpMgtListenerServiceComponent;
import org.wso2.carbon.idp.mgt.listener.IdentityProviderMgtLister;
import org.wso2.carbon.idp.mgt.metadata.SAMLSSOMetadataConfigManager;
import org.wso2.carbon.user.api.ClaimMapping;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class IdentityProviderManagementService extends AbstractAdmin {

    private static Log log = LogFactory.getLog(IdentityProviderManager.class);
    private static String LOCAL_DEFAULT_CLAIM_DIALECT = "http://wso2.org/claims";

    /**
     * Retrieves resident Identity provider for the logged-in tenant
     *
     * @return <code>IdentityProvider</code>
     * @throws IdentityApplicationManagementException Error when getting Resident Identity Provider
     */
    public IdentityProvider getResidentIdP() throws IdentityApplicationManagementException {

        String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        IdentityProvider residentIdP = IdentityProviderManager.getInstance()
                .getResidentIdP(tenantDomain);
        return residentIdP;
    }

    /**
     * Updated resident Identity provider for the logged-in tenant
     *
     * @param identityProvider <code>IdentityProvider</code>
     * @throws IdentityApplicationManagementException Error when getting Resident Identity Provider
     */
    public void updateResidentIdP(IdentityProvider identityProvider)
            throws IdentityApplicationManagementException {

        // invoking the listeners
        List<IdentityProviderMgtLister> listerns = IdpMgtListenerServiceComponent.getListners();
        for (IdentityProviderMgtLister listner : listerns) {
            listner.updateResidentIdP(identityProvider);
        }

        String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        IdentityProviderManager.getInstance().updateResidentIdP(identityProvider, tenantDomain);
    }

    /**
     * Retrieves registered Identity providers for the logged-in tenant
     *
     * @return Array of <code>IdentityProvider</code>. IdP names, primary IdP and home
     * realm identifiers of each IdP
     * @throws IdentityApplicationManagementException Error when getting list of Identity Providers
     */
    public IdentityProvider[] getAllIdPs() throws IdentityApplicationManagementException {

        String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        List<IdentityProvider> identityProviders = IdentityProviderManager.getInstance().getIdPs(tenantDomain);
        return identityProviders.toArray(new IdentityProvider[identityProviders.size()]);
    }


    /**
     * Retrieves Enabled registered Identity providers for the logged-in tenant
     *
     * @return Array of <code>IdentityProvider</code>. IdP names, primary IdP and home
     * realm identifiers of each IdP
     * @throws IdentityApplicationManagementException Error when getting list of Identity Providers
     */
    public IdentityProvider[] getEnabledAllIdPs() throws IdentityApplicationManagementException {

        String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        List<IdentityProvider> identityProviders = IdentityProviderManager.getInstance().getEnabledIdPs(tenantDomain);
        return identityProviders.toArray(new IdentityProvider[identityProviders.size()]);
    }


    /**
     * Retrieves Identity provider information for the logged-in tenant by Identity Provider name
     *
     * @param idPName Unique name of the Identity provider of whose information is requested
     * @return <code>IdentityProvider</code> Identity Provider information
     * @throws IdentityApplicationManagementException
     */
    public IdentityProvider getIdPByName(String idPName)
            throws IdentityApplicationManagementException {

        String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        return IdentityProviderManager.getInstance().getIdPByName(idPName, tenantDomain, true);
    }

    /**
     * Adds an Identity Provider to the logged-in tenant
     *
     * @param identityProvider <code>IdentityProvider</code> new Identity Provider information
     * @throws IdentityApplicationManagementException Error when adding Identity Provider
     */
    public void addIdP(IdentityProvider identityProvider)
            throws IdentityApplicationManagementException {

        // invoking the listeners
        List<IdentityProviderMgtLister> listerns = IdpMgtListenerServiceComponent.getListners();
        for (IdentityProviderMgtLister listner : listerns) {
            listner.addIdP(identityProvider);
        }

        String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        IdentityProviderManager.getInstance().addIdP(identityProvider, tenantDomain);
    }

    /**
     * Deletes an Identity Provider from the logged-in tenant
     *
     * @param idPName Name of the IdP to be deleted
     * @throws IdentityApplicationManagementException Error when deleting Identity Provider
     */
    public void deleteIdP(String idPName) throws IdentityApplicationManagementException {
        String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        IdentityProviderManager.getInstance().deleteIdP(idPName, tenantDomain);

        // invoking the listeners
        List<IdentityProviderMgtLister> listerns = IdpMgtListenerServiceComponent.getListners();
        for (IdentityProviderMgtLister listner : listerns) {
            listner.deleteIdP(idPName);
        }
    }

    /**
     * @return
     * @throws IdentityApplicationManagementException
     */
    public String[] getAllLocalClaimUris() throws IdentityApplicationManagementException {

        try {
            String claimDialect = LOCAL_DEFAULT_CLAIM_DIALECT;
            ClaimMapping[] claimMappings = CarbonContext.getThreadLocalCarbonContext()
                    .getUserRealm().getClaimManager().getAllClaimMappings(claimDialect);
            List<String> claimUris = new ArrayList<String>();
            for (ClaimMapping claimMap : claimMappings) {
                claimUris.add(claimMap.getClaim().getClaimUri());
            }
            return claimUris.toArray(new String[claimUris.size()]);
        } catch (Exception e) {
            String message = "Error while reading system claims";
            throw new IdentityApplicationManagementException(message);
        }
    }

    /**
     * Updates a given Identity Provider's information in the logged-in tenant
     *
     * @param oldIdPName       existing Identity Provider name
     * @param identityProvider <code>IdentityProvider</code> new Identity Provider information
     * @throws IdentityApplicationManagementException Error when updating Identity Provider
     */
    public void updateIdP(String oldIdPName, IdentityProvider identityProvider)
            throws IdentityApplicationManagementException {


        // invoking the listeners
        List<IdentityProviderMgtLister> listerns = IdpMgtListenerServiceComponent.getListners();
        for (IdentityProviderMgtLister listner : listerns) {
            listner.updateIdP(oldIdPName, identityProvider);
        }
        String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        IdentityProviderManager.getInstance().updateIdP(oldIdPName, identityProvider, tenantDomain);
    }

    /**
     * Get the authenticators registered in the system.
     *
     * @return <code>FederatedAuthenticatorConfig</code> array.
     * @throws IdentityApplicationManagementException Error when getting authenticators registered in the system
     */
    public FederatedAuthenticatorConfig[] getAllFederatedAuthenticators() throws IdentityApplicationManagementException {
        return IdentityProviderManager.getInstance().getAllFederatedAuthenticators();
    }

    public ProvisioningConnectorConfig[] getAllProvisioningConnectors() throws IdentityApplicationManagementException {
        return IdentityProviderManager.getInstance().getAllProvisioningConnectors();
    }

    /**
     * add SAML SSO object by uploading file from local system
     *
     * @param fileContent content of a file
     * @return SAMLSSOIdentityProviderDTO
     * @throws org.wso2.carbon.identity.base.IdentityException
     */
    public SAMLSSOIdentityProviderDTO addMetadataServiceProvider(String fileContent) throws IdentityException, IOException {
        System.out.println("backend  read service provider from file hit" + fileContent.length());

        SAMLSSOMetadataConfigManager metadataConfigManager = new SAMLSSOMetadataConfigManager(getConfigUserRegistry());
        //fileAddedReg = metadataConfigManager.addMetadataSAMLSSOFileResource(fileContent,SAMLSSOMetadataConfigManager.issuer);
        return metadataConfigManager.readServiceProvidersFromFile(fileContent);
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
}
