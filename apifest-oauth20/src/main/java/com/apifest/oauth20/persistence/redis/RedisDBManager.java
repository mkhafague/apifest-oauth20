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

/**
 * @author Apostol Terziev
 */
package com.apifest.oauth20.persistence.redis;

import java.util.*;

import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisSentinelPool;
import redis.clients.jedis.ScanParams;
import redis.clients.jedis.ScanResult;

import com.apifest.oauth20.AccessToken;
import com.apifest.oauth20.AuthCode;
import com.apifest.oauth20.ClientCredentials;
import com.apifest.oauth20.OAuthServer;
import com.apifest.oauth20.Scope;
import com.apifest.oauth20.persistence.DBManager;
import com.apifest.oauth20.utils.JSONUtils;

public class RedisDBManager implements DBManager {

    private static final String ACCESS_TOKEN_PREFIX_NAME = "at:";
    private static final String ACCESS_TOKEN_BY_USER_ID_PREFIX_NAME = "atuid:";
    private static final String ACCESS_TOKEN_BY_REFRESH_TOKEN_PREFIX_NAME = "atr:";
    
    private static final String CLIENT_CREDENTIALS_PREFIX_NAME = "cc:";
    private static final String CLIENT_CREDENTIALS_BY_NAME_PREFIX_NAME = "ncc:";
    
    private static final String AUTH_CODE_PREFIX_NAME = "acc:";
    private static final String AUTH_CODE_MAP_PREFIX_NAME = "acuri:";
    
    private static final String SCOPE_PREFIX_NAME = "sc:";

    private static JedisSentinelPool pool;
    //private static String storeAuthCodeScript = "";
    //private static String storeAuthCodeSHA;

    static {
        String[] sentinelsList = OAuthServer.getRedisSentinels().split(",");
        Set<String> sentinels = new HashSet<String>(Arrays.asList(sentinelsList));
        pool = new JedisSentinelPool(OAuthServer.getRedisMaster(), sentinels);
    }

    public void setupDBManager() {
        //Jedis jedis = pool.getResource();
        //storeAuthCodeSHA = jedis.scriptLoad(storeAuthCodeScript);
        //pool.returnResource(jedis);
    }

    /*
     * @see com.apifest.oauth20.persistence.DBManager#validClient(java.lang.String, java.lang.String)
     */
    @Override
    public boolean validClient(String clientId, String clientSecret) {
        Jedis jedis = pool.getResource();
		String key = CLIENT_CREDENTIALS_PREFIX_NAME + clientId;
        String secret = jedis.hget(key, "secret");
		String status = jedis.hget(key, "status");
        pool.returnResource(jedis);

        return (clientSecret.equals(secret) 
        			&& String.valueOf(ClientCredentials.ACTIVE_STATUS).equals(status));
    }

    /*
     * @see com.apifest.oauth20.persistence.DBManager#storeClientCredentials(com.apifest.oauth20.ClientCredentials)
     */
    @Override
    public void storeClientCredentials(ClientCredentials clientCreds) {
        Map<String, String> credentials = new HashMap<String, String>();
        credentials.put("_id", clientCreds.getId());
        credentials.put("secret", clientCreds.getSecret());
        credentials.put("name", clientCreds.getName());
        credentials.put("uri", clientCreds.getUri());
        credentials.put("descr", clientCreds.getDescr());
        credentials.put("type", String.valueOf(clientCreds.getType()));
        credentials.put("status", String.valueOf(clientCreds.getStatus()));
        credentials.put("created", String.valueOf(clientCreds.getCreated()));
        credentials.put("scope", String.valueOf(clientCreds.getScope()));
        credentials.put("details", JSONUtils.convertMapToJSON(clientCreds.getApplicationDetails()));
		Jedis jedis = pool.getResource();
        jedis.hmset(CLIENT_CREDENTIALS_PREFIX_NAME + clientCreds.getId(), credentials);
        jedis.hmset(CLIENT_CREDENTIALS_BY_NAME_PREFIX_NAME + clientCreds.getName(), credentials);
        pool.returnResource(jedis);
    }

    /*
     * @see com.apifest.oauth20.persistence.DBManager#storeAuthCode(com.apifest.oauth20.AuthCode)
     */
    @Override
    public void storeAuthCode(AuthCode authCode) {
        Map<String, String> authCodeMap = new HashMap<String, String>();
        // authCode.id -> generate random or do not use it
        authCodeMap.put("_id", (authCode.getId() != null) ? authCode.getId() : "");
        authCodeMap.put("code", authCode.getCode());
        authCodeMap.put("clientId", authCode.getClientId());
        authCodeMap.put("redirectUri", authCode.getRedirectUri());
        authCodeMap.put("state", authCode.getState());
        authCodeMap.put("scope", authCode.getScope());
        authCodeMap.put("type", authCode.getType());
        authCodeMap.put("valid", String.valueOf(authCode.isValid()));
        authCodeMap.put("userId", authCode.getUserId());
        authCodeMap.put("created", authCode.getCreated().toString());
        Jedis jedis = pool.getResource();        

        String key = AUTH_CODE_PREFIX_NAME + authCode.getCode();
        jedis.hmset(key, authCodeMap);        
		// REVISIT: expires on auth code
        jedis.expire(key, 1800); // TODO what is that constant ???!
		
		key = AUTH_CODE_MAP_PREFIX_NAME + authCode.getCode() + authCode.getRedirectUri();
        jedis.hset(key, "ac", authCode.getCode());
        jedis.expire(key, 1800); // TODO what is that constant ???!
        pool.returnResource(jedis);
    }

    /*
     * @see com.apifest.oauth20.persistence.DBManager#updateAuthCodeValidStatus(java.lang.String, boolean)
     */
    @Override
    public void updateAuthCodeValidStatus(String authCode, boolean valid) {
        Jedis jedis = pool.getResource();
        jedis.hset(AUTH_CODE_PREFIX_NAME + authCode, "valid", String.valueOf(valid));
        pool.returnResource(jedis);
    }

    /*
     * @see com.apifest.oauth20.persistence.DBManager#storeAccessToken(com.apifest.oauth20.AccessToken)
     */
    @Override
    public void storeAccessToken(AccessToken accessToken) {
        Map<String, String> accessTokenMap = new HashMap<String, String>();
        accessTokenMap.put("token", accessToken.getToken());
        accessTokenMap.put("refreshToken", accessToken.getRefreshToken());
        accessTokenMap.put("expiresIn", accessToken.getExpiresIn());
        accessTokenMap.put("type", accessToken.getType());
        accessTokenMap.put("scope", accessToken.getScope());
        accessTokenMap.put("valid", String.valueOf(accessToken.isValid()));
        accessTokenMap.put("clientId", accessToken.getClientId());
        accessTokenMap.put("codeId", accessToken.getCodeId());
        accessTokenMap.put("userId", accessToken.getUserId());
        accessTokenMap.put("created", String.valueOf(accessToken.getCreated()));
        accessTokenMap.put("details", JSONUtils.convertMapToJSON(accessToken.getDetails()));
        accessTokenMap.put("refreshExpiresIn", accessToken.getRefreshExpiresIn());
        Jedis jedis = pool.getResource();
        jedis.hmset(ACCESS_TOKEN_PREFIX_NAME + accessToken.getToken(), accessTokenMap);
        Integer tokenExpiration = Integer.valueOf((!accessToken.getRefreshExpiresIn().isEmpty()) ? accessToken.getRefreshExpiresIn() : accessToken.getExpiresIn());
        jedis.expire(ACCESS_TOKEN_PREFIX_NAME + accessToken.getToken(), tokenExpiration);
		String atrKey = ACCESS_TOKEN_BY_REFRESH_TOKEN_PREFIX_NAME + accessToken.getRefreshToken() + accessToken.getClientId();
        jedis.hset(atrKey, "access_token", accessToken.getToken());
        jedis.expire(atrKey, tokenExpiration);

        // store access tokens by user id and client app
        // REVISIT: Replace with Lua script
        Long uniqueId = System.currentTimeMillis();
        String key = ACCESS_TOKEN_BY_USER_ID_PREFIX_NAME 
        	+ accessToken.getUserId() + ":" + accessToken.getClientId() + ":" + uniqueId;
        jedis.hset(key, "access_token", accessToken.getToken());
        jedis.expire(key, Integer.valueOf(accessToken.getExpiresIn()));
        pool.returnResource(jedis);
    }

    /*
     * @see com.apifest.oauth20.persistence.DBManager#findAccessTokenByRefreshToken(java.lang.String, java.lang.String)
     */
    @Override
    public AccessToken findAccessTokenByRefreshToken(String refreshToken, String clientId) {
        Jedis jedis = pool.getResource();
        String accessToken = jedis.hget(ACCESS_TOKEN_BY_REFRESH_TOKEN_PREFIX_NAME + refreshToken + clientId, "access_token");
        Map<String, String> accessTokenMap = jedis.hgetAll(ACCESS_TOKEN_PREFIX_NAME + accessToken);
        pool.returnResource(jedis);
        if (accessTokenMap.isEmpty() || "false".equals(accessTokenMap.get("valid"))) {
            return null;
        }
        return AccessToken.loadFromStringMap(accessTokenMap);
    }

    /*
     * @see com.apifest.oauth20.persistence.DBManager#updateAccessTokenValidStatus(java.lang.String, boolean)
     */
    @Override
    public void updateAccessTokenValidStatus(String accessToken, boolean valid) {
        Jedis jedis = pool.getResource();
        jedis.hset(ACCESS_TOKEN_PREFIX_NAME + accessToken, "valid", String.valueOf(valid));
        pool.returnResource(jedis);
    }

    /*
     * @see com.apifest.oauth20.persistence.DBManager#findAccessToken(java.lang.String)
     */
    @Override
    public AccessToken findAccessToken(String accessToken) {
        Jedis jedis = pool.getResource();
        Map<String, String> accessTokenMap = jedis.hgetAll(ACCESS_TOKEN_PREFIX_NAME + accessToken);
        pool.returnResource(jedis);
        if (accessTokenMap.isEmpty() || "false".equals(accessTokenMap.get("valid"))) {
            return null;
        }
        return AccessToken.loadFromStringMap(accessTokenMap);
    }

    /*
     * @see com.apifest.oauth20.persistence.DBManager#findAuthCode(java.lang.String, java.lang.String)
     */
    @Override
    public AuthCode findAuthCode(String authCode, String redirectUri) {
        Jedis jedis = pool.getResource();
        // TODO: check by client_id too
        Map<String, String> authCodeIdMap = jedis.hgetAll(AUTH_CODE_MAP_PREFIX_NAME + authCode + redirectUri);
        String authCodeId = authCodeIdMap.get("ac");
        Map<String, String> authCodeMap = jedis.hgetAll(AUTH_CODE_PREFIX_NAME + authCodeId);
        pool.returnResource(jedis);
        if (authCodeMap.isEmpty() || "false".equals(authCodeMap.get("valid"))) {
            return null;
        }
        return AuthCode.loadFromStringMap(authCodeMap);
    }

    /*
     * @see com.apifest.oauth20.persistence.DBManager#findClientCredentials(java.lang.String)
     */
    @Override
    public ClientCredentials findClientCredentials(String clientId) {
        Jedis jedis = pool.getResource();
        Map<String, String> clientCredentialsMap = jedis.hgetAll(CLIENT_CREDENTIALS_PREFIX_NAME + clientId);
        pool.returnResource(jedis);
        if (clientCredentialsMap.isEmpty()) {
            return null;
        }
        return ClientCredentials.loadFromStringMap(clientCredentialsMap);
    }

    /*
     * @see com.apifest.oauth20.persistence.DBManager#findClientCredentialsByName(java.lang.String)
     */
    @Override
    public ClientCredentials findClientCredentialsByName(String clientName) {
    	Jedis jedis = pool.getResource();
        Map<String, String> clientCredentialsMap = 
        	jedis.hgetAll(CLIENT_CREDENTIALS_BY_NAME_PREFIX_NAME + clientName);
        pool.returnResource(jedis);
        if (clientCredentialsMap.isEmpty()) {
            return null;
        }
        return ClientCredentials.loadFromStringMap(clientCredentialsMap);
    }
    
    /*
     * @see com.apifest.oauth20.persistence.DBManager#storeScope(com.apifest.oauth20.Scope)
     */
    @Override
    public boolean storeScope(Scope scope) {
        Map<String, String> scopeMap = new HashMap<String, String>();
        scopeMap.put("id", scope.getScope());
        scopeMap.put(Scope.DESCRIPTION_FIELD, scope.getDescription());
        scopeMap.put(Scope.CC_EXPIRES_IN_FIELD, String.valueOf(scope.getCcExpiresIn()));
        scopeMap.put(Scope.PASS_EXPIRES_IN_FIELD, String.valueOf(scope.getPassExpiresIn()));
        scopeMap.put(Scope.REFRESH_EXPIRES_IN_FIELD, String.valueOf(scope.getRefreshExpiresIn()));
        Jedis jedis = pool.getResource();
        jedis.hmset(SCOPE_PREFIX_NAME + scope.getScope(), scopeMap);
		pool.returnResource(jedis);
        return true;
    }

    /*
     * @see com.apifest.oauth20.persistence.DBManager#getAllScopes()
     */
    @Override
    public List<Scope> getAllScopes() {
        List<Scope> list = new ArrayList<Scope>();
        ScanParams sp = (new ScanParams()).match(SCOPE_PREFIX_NAME+"*").count(1000);
        String cursor = ScanParams.SCAN_POINTER_START;
        
        Jedis jedis = pool.getResource();
        
        do {
	        ScanResult<String> result = jedis.scan(cursor, sp);
	        cursor = result.getStringCursor();
	        for (String entry : result.getResult()) {
				Map<String, String> scopeMap = jedis.hgetAll(entry);
				if (!scopeMap.isEmpty()) {
					list.add(Scope.loadFromStringMap(scopeMap));
				}
			}
        } while (!ScanParams.SCAN_POINTER_START.equals(cursor));        
        
        pool.returnResource(jedis);
        return list;
    }

    /*
     * @see com.apifest.oauth20.persistence.DBManager#findScope(java.lang.String)
     */
    @Override
    public Scope findScope(String scopeName) {
        Jedis jedis = pool.getResource();
        Map<String, String> scopeMap = jedis.hgetAll(SCOPE_PREFIX_NAME + scopeName);
        pool.returnResource(jedis);
        if (scopeMap.isEmpty()) {
            return null;
        }
        return Scope.loadFromStringMap(scopeMap);
    }

    /*
     * @see com.apifest.oauth20.persistence.DBManager#updateClientAppScope(java.lang.String)
     */
    @Override
    public boolean updateClientApp(String clientId, String scope, String description, Integer status, Map<String, String> applicationDetails) {
		String key = CLIENT_CREDENTIALS_PREFIX_NAME + clientId;
        Jedis jedis = pool.getResource();
        Map<String, String> clientApp = jedis.hgetAll(key);
        if (scope != null && scope.length() > 0) {
            clientApp.put("scope", scope);
        }
        if (description != null && description.length() > 0) {
            clientApp.put("descr", description);
        }
        if (status != null) {
            clientApp.put("status", String.valueOf(status));
        }
        if(applicationDetails != null) {
            clientApp.put("details", JSONUtils.convertMapToJSON(applicationDetails));
        }
        jedis.hmset(key, clientApp);
		pool.returnResource(jedis);
        return true;
    }

    /*
     * @see com.apifest.oauth20.persistence.DBManager#getAllApplications()
     */
    @Override
    public List<ClientCredentials> getAllApplications() {
        List<ClientCredentials> list = new ArrayList<ClientCredentials>();
        ScanParams sp = (new ScanParams()).match(CLIENT_CREDENTIALS_PREFIX_NAME+"*").count(1000);
        String cursor = ScanParams.SCAN_POINTER_START;

        Jedis jedis = pool.getResource();
        do {
	        ScanResult<String> result = jedis.scan(cursor, sp);
	        cursor = result.getStringCursor();
	        for (String entry : result.getResult()) {
				Map<String, String> appMap = jedis.hgetAll(entry);
				if (!appMap.isEmpty()) {
					ClientCredentials creds = ClientCredentials.loadFromStringMap(appMap);
					list.add(creds);
				}
			}
        } while (!ScanParams.SCAN_POINTER_START.equals(cursor));

        pool.returnResource(jedis);
        return list;
    }

    /*
     * @see com.apifest.oauth20.persistence.DBManager#deleteScope(java.lang.String)
     */
    @Override
    public boolean deleteScope(String scopeName) {
        Jedis jedis = pool.getResource();
        Long deleted = jedis.del(SCOPE_PREFIX_NAME + scopeName);
        pool.returnResource(jedis);
		
        // 1 if deleted, 0 - nothing deleted
        return (deleted.intValue() == 1);
    }

    /*
     * @see com.apifest.oauth20.persistence.DBManager#getAccessTokenByUserIdAndClientApp(java.lang.String, java.lang.String)
     */
    @Override
    public List<AccessToken> getAccessTokenByUserIdAndClientApp(String userId, String clientId) {
        List<AccessToken> accessTokens = new ArrayList<AccessToken>();
        
        String pattern = ACCESS_TOKEN_BY_USER_ID_PREFIX_NAME + userId + ":" + clientId + ":*";
        ScanParams sp = (new ScanParams()).match(pattern).count(1000);
        String cursor = ScanParams.SCAN_POINTER_START;
        
        Jedis jedis = pool.getResource();
        
        do {
	        ScanResult<String> result = jedis.scan(cursor, sp);
	        cursor = result.getStringCursor();
	        for (String entry : result.getResult()) {
				String token = jedis.hget(entry, "access_token");
				Map<String, String> accessTokenMap = jedis.hgetAll(ACCESS_TOKEN_PREFIX_NAME + token);
				if (!accessTokenMap.isEmpty() && "true".equals(accessTokenMap.get("valid"))) {
					accessTokens.add(AccessToken.loadFromStringMap(accessTokenMap));
				}
			}
        } while (!ScanParams.SCAN_POINTER_START.equals(cursor));        
        
        pool.returnResource(jedis);
        return accessTokens;
    }
    /*
     * @see com.apifest.oauth20.persistence.DBManager#removeAccessToken(java.lang.String)
     */
    @Override
    public void removeAccessToken(String accessToken) {
        Jedis jedis = pool.getResource();
        jedis.expire(ACCESS_TOKEN_PREFIX_NAME + accessToken, 0);
        // refresh token will be associated with the new access token issued
        pool.returnResource(jedis);
    }

}
