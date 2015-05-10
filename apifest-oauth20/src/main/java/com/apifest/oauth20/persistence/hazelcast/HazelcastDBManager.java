/*
 * Copyright 2013-2014, ApiFest project
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

package com.apifest.oauth20.persistence.hazelcast;

import static com.apifest.oauth20.persistence.hazelcast.HazelcastConfigFactory.APIFEST_ACCESS_TOKEN_MAP;
import static com.apifest.oauth20.persistence.hazelcast.HazelcastConfigFactory.APIFEST_AUTH_CODE_MAP;
import static com.apifest.oauth20.persistence.hazelcast.HazelcastConfigFactory.APIFEST_CLIENT_MAP;
import static com.apifest.oauth20.persistence.hazelcast.HazelcastConfigFactory.APIFEST_SCOPE_MAP;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import com.apifest.oauth20.AccessToken;
import com.apifest.oauth20.AuthCode;
import com.apifest.oauth20.ClientCredentials;
import com.apifest.oauth20.Scope;
import com.apifest.oauth20.persistence.DBManager;
import com.hazelcast.client.HazelcastClient;
import com.hazelcast.client.config.ClientConfig;
import com.hazelcast.config.Config;
import com.hazelcast.core.Hazelcast;
import com.hazelcast.core.HazelcastInstance;
import com.hazelcast.core.IMap;
import com.hazelcast.query.EntryObject;
import com.hazelcast.query.Predicate;
import com.hazelcast.query.PredicateBuilder;

/**
 * This class implements a persistent storage layer using the Hazelcast Cache.
 *
 * @author Apostol Terziev
 */
public class HazelcastDBManager implements DBManager {

    private HazelcastInstance instance;

    public HazelcastDBManager(String name, String pwd, String host, String members, boolean embedded) {
		if (embedded) {
			Config config = HazelcastConfigFactory.buildConfig(name, pwd, host, members);
			instance = Hazelcast.newHazelcastInstance(config);
			
			HazelcastConfigFactory.addIndexes(instance);
		} else {			
			ClientConfig clientConfig = HazelcastConfigFactory.buildClientConfig(name, pwd, members);
			
			instance = HazelcastClient.newHazelcastClient(clientConfig);
		}
    }

    private IMap<String, PersistentScope> getScopesContainer() {
        return instance.getMap(APIFEST_SCOPE_MAP);
    }

    private IMap<String, PersistentClientCredentials> getClientCredentialsContainer() {
        return instance.getMap(APIFEST_CLIENT_MAP);
    }

    private IMap<String, PersistentAuthCode> getAuthCodeContainer() {
        return instance.getMap(APIFEST_AUTH_CODE_MAP);
    }

    private IMap<String, PersistentAccessToken> getAccessTokenContainer() {
        return instance.getMap(APIFEST_ACCESS_TOKEN_MAP);
    }

    /*
     * @see com.apifest.oauth20.persistence.DBManager#validClient(java.lang.String, java.lang.String)
     */
    @Override
    public boolean validClient(String clientId, String clientSecret) {
        ClientCredentials clientCredentials = findClientCredentials(clientId);
        return ((clientCredentials != null)
                && (clientCredentials.getSecret() != null && clientCredentials.getSecret().equals(clientSecret))
                && (clientCredentials.getStatus() == ClientCredentials.ACTIVE_STATUS));
    }

    /*
     * @see com.apifest.oauth20.persistence.DBManager#storeClientCredentials(com.apifest.oauth20.ClientCredentials)
     */
    @Override
    public void storeClientCredentials(ClientCredentials clientCreds) {
        getClientCredentialsContainer().put(clientCreds.getId(),
                PersistenceTransformations.toPersistentClientCredentials(clientCreds));
    }

    /*
     * @see com.apifest.oauth20.persistence.DBManager#storeAuthCode(com.apifest.oauth20.AuthCode)
     */
    // TODO: Set expiration time for auth code
    @Override
    public void storeAuthCode(AuthCode authCode) {
        getAuthCodeContainer().put(authCode.getCode(), PersistenceTransformations.toPersistentAuthCode(authCode));
    }

    /*
     * @see com.apifest.oauth20.persistence.DBManager#updateAuthCodeValidStatus(java.lang.String, boolean)
     */
    @Override
    public void updateAuthCodeValidStatus(String authCode, boolean valid) {
        PersistentAuthCode persistentAuthCode = getAuthCodeContainer().get(authCode);
        persistentAuthCode.setValid(valid);
        getAuthCodeContainer().put(authCode, persistentAuthCode);
    }

    /*
     * @see com.apifest.oauth20.persistence.DBManager#storeAccessToken(com.apifest.oauth20.AccessToken)
     */
    @Override
    public void storeAccessToken(AccessToken accessToken) {
        Long tokenExpiration = (accessToken.getRefreshExpiresIn() != null && !accessToken.getRefreshExpiresIn().isEmpty()) ? Long.valueOf(accessToken.getRefreshExpiresIn()) : Long.valueOf(accessToken.getExpiresIn());
        getAccessTokenContainer().put(accessToken.getToken(), PersistenceTransformations.toPersistentAccessToken(accessToken),
                tokenExpiration, TimeUnit.SECONDS);
    }

    /*
     * @see com.apifest.oauth20.persistence.DBManager#findAccessTokenByRefreshToken(java.lang.String, java.lang.String)
     */
    @Override
    @SuppressWarnings("unchecked")
    public AccessToken findAccessTokenByRefreshToken(String refreshToken, String clientId) {
        EntryObject eo = new PredicateBuilder().getEntryObject();
        Predicate<String, String> predicate = eo.get("refreshTokenByClient").equal(refreshToken + clientId);
        Collection<PersistentAccessToken> values = getAccessTokenContainer().values(predicate);
        if (values.isEmpty()) {
            return null;
        }
        return PersistenceTransformations.toAccessToken(values.iterator().next());
    }

    /*
     * @see com.apifest.oauth20.persistence.DBManager#updateAccessTokenValidStatus(java.lang.String, boolean)
     */
    @Override
    public void updateAccessTokenValidStatus(String accessToken, boolean valid) {
        PersistentAccessToken persistentAccessToken = getAccessTokenContainer().get(accessToken);
        persistentAccessToken.setValid(valid);
        getAccessTokenContainer().put(accessToken, persistentAccessToken, Long.valueOf(persistentAccessToken.getRefreshExpiresIn()), TimeUnit.SECONDS);
    }

    /*
     * @see com.apifest.oauth20.persistence.DBManager#findAccessToken(java.lang.String)
     */
    @Override
    public AccessToken findAccessToken(String accessToken) {
        PersistentAccessToken tokenStored = getAccessTokenContainer().get(accessToken);
        if (tokenStored != null) {
            return PersistenceTransformations.toAccessToken(tokenStored);
        } else {
            return null;
        }
    }

    /*
     * @see com.apifest.oauth20.persistence.DBManager#findAuthCode(java.lang.String, java.lang.String)
     */
    @Override
    @SuppressWarnings("unchecked")
    public AuthCode findAuthCode(String authCode, String redirectUri) {
        EntryObject eo = new PredicateBuilder().getEntryObject();
        Predicate<String, String> predicate = eo.get("codeURI").equal(authCode + redirectUri + true);
        Collection<PersistentAuthCode> values = getAuthCodeContainer().values(predicate);
        if (values.isEmpty()) {
            return null;
        }
        return PersistenceTransformations.toAuthCode(values.iterator().next());
    }

    /*
     * @see com.apifest.oauth20.persistence.DBManager#findClientCredentials(java.lang.String)
     */
    @Override
    public ClientCredentials findClientCredentials(String clientId) {
        return PersistenceTransformations.toClientCredentials(getClientCredentialsContainer().get(clientId));
    }

    /*
     * @see com.apifest.oauth20.persistence.DBManager#storeScope(com.apifest.oauth20.Scope)
     */
    @Override
    public boolean storeScope(Scope scope) {
        getScopesContainer().put(scope.getScope(), PersistenceTransformations.toPersistentScope(scope));
        return true;
    }

    /*
     * @see com.apifest.oauth20.persistence.DBManager#getAllScopes()
     */
    @Override
    public List<Scope> getAllScopes() {
        List<Scope> scopesList = new ArrayList<Scope>();
        IMap<String, PersistentScope> scopesContainer = getScopesContainer();
        for (String key : scopesContainer.keySet()) {
            scopesList.add(PersistenceTransformations.toScope(scopesContainer.get(key)));
        }
        return scopesList;
    }

    /*
     * @see com.apifest.oauth20.persistence.DBManager#findScope(java.lang.String)
     */
    @Override
    public Scope findScope(String scopeName) {
        return PersistenceTransformations.toScope(getScopesContainer().get(scopeName));
    }

    /*
     * @see com.apifest.oauth20.persistence.DBManager#updateClientApp(java.lang.String, java.lang.String, java.lang.Integer, java.util.Map)
     */
    @Override
    public boolean updateClientApp(String clientId, String scope, String description, Integer status, Map<String, String> applicationDetails) {
        PersistentClientCredentials clientCredentials = getClientCredentialsContainer().get(clientId);
        if (scope != null && scope.length() > 0) {
            clientCredentials.setScope(scope);
        }
        if (description != null && description.length() > 0) {
            clientCredentials.setDescr(description);
        }
        if (status != null) {
            clientCredentials.setStatus(status);
        }
        if (applicationDetails != null) {
            clientCredentials.setApplicationDetails(applicationDetails);
        }
        getClientCredentialsContainer().put(clientId, clientCredentials);
        return true;
    }

    /*
     * @see com.apifest.oauth20.persistence.DBManager#deleteClientApp(java.lang.String)
     */
    @Override
    public boolean deleteClientApp(String clientId) {
        PersistentClientCredentials cc = getClientCredentialsContainer().remove(clientId);
        return cc != null;
    }

    /*
     * @see com.apifest.oauth20.persistence.DBManager#getAllApplications()
     */
    @Override
    public List<ClientCredentials> getAllApplications() {
        List<ClientCredentials> appsList = new ArrayList<ClientCredentials>();
        IMap<String, PersistentClientCredentials> clientsContainer = getClientCredentialsContainer();
        for (String key : clientsContainer.keySet()) {
            ClientCredentials creds = PersistenceTransformations.toClientCredentials(clientsContainer.get(key));
            appsList.add(creds);
        }
        return appsList;
    }

    /*
     * @see com.apifest.oauth20.persistence.DBManager#deleteScope(java.lang.String)
     */
    @Override
    public boolean deleteScope(String scopeName) {
        PersistentScope scope = getScopesContainer().remove(scopeName);
        return scope != null;
    }

    /*
     * @see com.apifest.oauth20.persistence.DBManager#getAccessTokenByUserIdAndClientApp(java.lang.String, java.lang.String)
     */
    @Override
    @SuppressWarnings("unchecked")
    public List<AccessToken> getAccessTokenByUserIdAndClientApp(String userId, String clientId) {
        List<AccessToken> accessTokens = new ArrayList<AccessToken>();
        EntryObject eo = new PredicateBuilder().getEntryObject();
        Predicate<String, String> predicate = eo.get("accessTokenByUserIdAndClient").equal(userId + clientId + true);
        Collection<PersistentAccessToken> values = getAccessTokenContainer().values(predicate);
        if (!values.isEmpty()) {
            for (PersistentAccessToken token : values) {
                accessTokens.add(PersistenceTransformations.toAccessToken(token));
            }
        }
        return accessTokens;
    }

    /*
     * @see com.apifest.oauth20.persistence.DBManager#findClientCredentialsByName(java.lang.String)
     */
    @Override
    @SuppressWarnings("unchecked")
	public ClientCredentials findClientCredentialsByName(String clientName) {
    	EntryObject eo = new PredicateBuilder().getEntryObject();
        Predicate<String, String> predicate = eo.get("name").equal(clientName);
        Collection<PersistentClientCredentials> values = getClientCredentialsContainer().values(predicate);
        if (!values.isEmpty()) {
        	return PersistenceTransformations.toClientCredentials(values.iterator().next());
        }
        return null;
    }
    
    /*
     * @see com.apifest.oauth20.persistence.DBManager#removeAccessToken(java.lang.String)
     */	
    @Override
    public void removeAccessToken(String accessToken) {
        getAccessTokenContainer().remove(accessToken);
    }

}
