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

package com.apifest.oauth20;

import com.apifest.oauth20.api.AuthenticationException;
import com.apifest.oauth20.api.GrantType;
import com.apifest.oauth20.api.ICustomGrantTypeHandler;
import com.apifest.oauth20.api.IUserAuthentication;
import com.apifest.oauth20.api.UserDetails;
import com.apifest.oauth20.persistence.DBManager;
import com.apifest.oauth20.security.GuestUserAuthentication;

import org.apache.commons.codec.binary.Base64;
import org.codehaus.jackson.JsonParseException;
import org.codehaus.jackson.map.JsonMappingException;
import org.codehaus.jackson.map.ObjectMapper;
import org.jboss.netty.handler.codec.http.HttpHeaders;
import org.jboss.netty.handler.codec.http.HttpRequest;
import org.jboss.netty.handler.codec.http.HttpResponseStatus;
import org.jboss.netty.handler.codec.http.QueryStringEncoder;
import org.jboss.netty.util.CharsetUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Date;
import java.util.Map;

/**
 * Main class for authorization.
 *
 * @author Rossitsa Borissova
 */
public class AuthorizationServer {

    protected static final String BASIC = "Basic ";
    private static final String TOKEN_TYPE_BEARER = "Bearer";

    protected static Logger log = LoggerFactory.getLogger(AuthorizationServer.class);

    protected DBManager db = DBManagerFactory.getInstance();
    protected ScopeService scopeService = new ScopeService();

    protected Class<IUserAuthentication> userAuthenticationClass;
    protected Class<ICustomGrantTypeHandler> userCustomGrantTypeHandler;
    private String customGrantType;

    public AuthorizationServer(Class<IUserAuthentication> userAuthenticationClass,
            Class<ICustomGrantTypeHandler> userCustomGrantTypeHandler) {
        this.userAuthenticationClass = userAuthenticationClass;
        this.userCustomGrantTypeHandler = userCustomGrantTypeHandler;
        this.customGrantType = userCustomGrantTypeHandler.getAnnotation(GrantType.class).name();
    }

    /**
     * Issue {@link ClientCredentials} for an app
     *
     * @param req the request
     * @return created credentials
     * @throws OAuthException
     */
    public ClientCredentials issueClientCredentials(HttpRequest req) throws OAuthException {
        ClientCredentials creds;
        String content = req.getContent().toString(CharsetUtil.UTF_8);
        String contentType = req.headers().get(HttpHeaders.Names.CONTENT_TYPE);

        if (contentType != null && contentType.contains(Response.APPLICATION_JSON)) {
            ObjectMapper mapper = new ObjectMapper();
            ApplicationInfo appInfo;
            try {
                appInfo = mapper.readValue(content, ApplicationInfo.class);
                if (appInfo.valid()) {
                    checkScopeList(appInfo);
                    // check client_id, client_secret passed
                    if ((appInfo.getId() != null && appInfo.getId().length() > 0) &&
                            (appInfo.getSecret() != null && appInfo.getSecret().length() > 0)) {
                        // if a client app with this client_id already registered
                        if (db.findClientCredentials(appInfo.getId()) == null) {
                            creds = new ClientCredentials(appInfo.getName(), appInfo.getScope(), appInfo.getDescription(),
                                appInfo.getRedirectUri(), appInfo.getId(), appInfo.getSecret(), appInfo.getApplicationDetails());
                        } else {
                            throw new OAuthException(Response.ALREADY_REGISTERED_APP, HttpResponseStatus.BAD_REQUEST);
                        }
                    } else {
                        creds = new ClientCredentials(appInfo.getName(), appInfo.getScope(), appInfo.getDescription(),
                                appInfo.getRedirectUri(), appInfo.getApplicationDetails());
                    }
                    db.storeClientCredentials(creds);
                } else {
                    throw new OAuthException(Response.CANNOT_REGISTER_APP_NAME_OR_SCOPE_OR_URI_IS_NULL, HttpResponseStatus.BAD_REQUEST);
                }
            } catch (JsonParseException e) {
                throw new OAuthException(e, Response.CANNOT_REGISTER_APP, HttpResponseStatus.BAD_REQUEST);
            } catch (JsonMappingException e) {
                throw new OAuthException(e, Response.CANNOT_REGISTER_APP, HttpResponseStatus.BAD_REQUEST);
            } catch (IOException e) {
                throw new OAuthException(e, Response.CANNOT_REGISTER_APP, HttpResponseStatus.BAD_REQUEST);
            }
        } else {
            throw new OAuthException(Response.UNSUPPORTED_MEDIA_TYPE, HttpResponseStatus.BAD_REQUEST);
        }
        return creds;
    }

    // /authorize?response_type=code&client_id=s6BhdRkqt3&state=xyz&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb
    public String issueAuthorizationCode(HttpRequest req) throws OAuthException {
        AuthRequest authRequest = new AuthRequest(req);
        log.debug("received client_id:" + authRequest.getClientId());
        if (!isActiveClientId(authRequest.getClientId())) {
            throw new OAuthException(new TokenError(TokenErrorTypes.INACTIVE_CLIENT_CREDENTIALS, authRequest.getState())
                    , HttpResponseStatus.BAD_REQUEST);
        }
        authRequest.validate();

        String scope = scopeService.getValidScope(authRequest.getScope(), authRequest.getClientId());
        if (scope == null) {
            throw new OAuthException(new TokenError(TokenErrorTypes.INVALID_SCOPE, authRequest.getState()), HttpResponseStatus.BAD_REQUEST);
        }

        AuthCode authCode = new AuthCode(generateCode(), authRequest.getClientId(), authRequest.getRedirectUri(),
                authRequest.getState(), scope, authRequest.getResponseType(), authRequest.getUserId());
        log.debug("authCode: {}", authCode.getCode());
        db.storeAuthCode(authCode);

        // return redirect URI, append param code=[Authcode] & optional state if present in request [CSRF]
        QueryStringEncoder enc = new QueryStringEncoder(authRequest.getRedirectUri());
        enc.addParam("code", authCode.getCode());
        
		// CSRF protection
        if(authRequest.getState() != null)
        	enc.addParam("state", authRequest.getState());
		
		return enc.toString();
    }

	private AccessToken handleAuthorizationCodeGrantType(TokenRequest tokenRequest) throws OAuthException {	
		AuthCode authCode = findAuthCode(tokenRequest);
		// TODO: REVISIT: Move client_id check to db query
		if (authCode != null) {
			if (!tokenRequest.getClientId().equals(authCode.getClientId())) {
				throw new OAuthException(new TokenError(TokenErrorTypes.INACTIVE_CLIENT_CREDENTIALS, tokenRequest.getState()), HttpResponseStatus.BAD_REQUEST);
			}
			if (authCode.getRedirectUri() != null && !tokenRequest.getRedirectUri().equals(authCode.getRedirectUri())) {
				throw new OAuthException(new TokenError(TokenErrorTypes.INVALID_REDIRECT_URI, tokenRequest.getState()), HttpResponseStatus.BAD_REQUEST);
			} else {
				// invalidate the auth code
                AccessToken accessToken = new AccessToken(TOKEN_TYPE_BEARER, getExpiresIn(TokenRequest.PASSWORD,authCode.getScope()),
						authCode.getScope(), getExpiresIn(TokenRequest.REFRESH_TOKEN, authCode.getScope()));
				accessToken.setUserId(authCode.getUserId());
				accessToken.setClientId(authCode.getClientId());
				accessToken.setCodeId(authCode.getId());
				db.storeAccessToken(accessToken);
				return accessToken;
			}
		} else {
			throw new OAuthException(new TokenError(TokenErrorTypes.INVALID_AUTH_CODE, tokenRequest.getState()), HttpResponseStatus.BAD_REQUEST);
		}
	}
	private AccessToken handleRefreshTokenGrantType(TokenRequest tokenRequest) throws OAuthException {
        AccessToken accessToken = db.findAccessTokenByRefreshToken(tokenRequest.getRefreshToken(), tokenRequest.getClientId());
            if (accessToken != null) {
                if (!accessToken.refreshTokenExpired()) {
                    String validScope;
                    if (tokenRequest.getScope() != null) {
                        if (scopeService.scopeAllowed(tokenRequest.getScope(), accessToken.getScope())) {
                            validScope = tokenRequest.getScope();
                        } else {
                            throw new OAuthException(new TokenError(TokenErrorTypes.INVALID_SCOPE, tokenRequest.getState()), HttpResponseStatus.BAD_REQUEST);
                        }
                    } else {
                        validScope = accessToken.getScope();
                    }
                    db.updateAccessTokenValidStatus(accessToken.getToken(), false);
                    AccessToken newAccessToken = new AccessToken(TOKEN_TYPE_BEARER, getExpiresIn(TokenRequest.PASSWORD,
                            validScope), validScope, accessToken.getRefreshToken(), getExpiresIn(TokenRequest.REFRESH_TOKEN, validScope));
                    newAccessToken.setUserId(accessToken.getUserId());
                    newAccessToken.setDetails(accessToken.getDetails());
                    newAccessToken.setClientId(accessToken.getClientId());
                    db.storeAccessToken(newAccessToken);
                    db.removeAccessToken(accessToken.getToken());
                    return newAccessToken;
                } else {
                    db.removeAccessToken(accessToken.getToken());
                    throw new OAuthException(new TokenError(TokenErrorTypes.INVALID_REFRESH_TOKEN, tokenRequest.getState()), HttpResponseStatus.BAD_REQUEST);
                }
            } else {
                throw new OAuthException(new TokenError(TokenErrorTypes.INVALID_ACCESS_TOKEN, tokenRequest.getState()), HttpResponseStatus.BAD_REQUEST);
            }
	}
	
    private AccessToken handleClientCredentialsGrantType(TokenRequest tokenRequest) throws OAuthException {
		ClientCredentials clientCredentials = db.findClientCredentials(tokenRequest.getClientId());
		String scope = scopeService.getValidScopeByScope(tokenRequest.getScope(), clientCredentials.getScope());
		if (scope == null) {
			throw new OAuthException(new TokenError(TokenErrorTypes.INVALID_SCOPE, tokenRequest.getState()), HttpResponseStatus.BAD_REQUEST);
		}

        AccessToken accessToken = new AccessToken(TOKEN_TYPE_BEARER, getExpiresIn(TokenRequest.CLIENT_CREDENTIALS, scope),
				scope, false, getExpiresIn(TokenRequest.REFRESH_TOKEN, scope));
		accessToken.setClientId(tokenRequest.getClientId());
		Map<String, String> applicationDetails = clientCredentials.getApplicationDetails();
		if ((applicationDetails != null) && (applicationDetails.size() > 0)) {
			accessToken.setDetails(applicationDetails);
		}
		db.storeAccessToken(accessToken);
        return accessToken;
    }

    private AccessToken handlePasswordGrantType(TokenRequest tokenRequest, HttpRequest req) throws OAuthException {
		String scope = scopeService.getValidScope(tokenRequest.getScope(), tokenRequest.getClientId());
		if (scope == null) {
			throw new OAuthException(new TokenError(TokenErrorTypes.INVALID_SCOPE, tokenRequest.getState()), HttpResponseStatus.BAD_REQUEST);
		}

		try {
			UserDetails userDetails = authenticateUser(tokenRequest.getUsername(), tokenRequest.getPassword(), req);
			if (userDetails != null && userDetails.getUserId() != null) {
                AccessToken accessToken = new AccessToken(TOKEN_TYPE_BEARER, getExpiresIn(TokenRequest.PASSWORD, scope), scope,
						getExpiresIn(TokenRequest.REFRESH_TOKEN, scope));
				accessToken.setUserId(userDetails.getUserId());
				accessToken.setDetails(userDetails.getDetails());
				accessToken.setClientId(tokenRequest.getClientId());
				db.storeAccessToken(accessToken);
				return accessToken;
			} else {
				throw new OAuthException(new TokenError(TokenErrorTypes.INVALID_USERNAME_PASSWORD, tokenRequest.getState()), HttpResponseStatus.UNAUTHORIZED);
			}
		} catch (AuthenticationException e) {
			// in case some custom response should be returned other than HTTP 401
			// for instance, if the user authentication requires more user details as a subsequent step
			if (e.getResponse() != null) {
				String responseContent = e.getResponse().getContent().toString(CharsetUtil.UTF_8);
				throw new OAuthException(e, responseContent, e.getResponse().getStatus());
			} else {
				log.error("Cannot authenticate user", e);
				throw new OAuthException(e, new TokenError(TokenErrorTypes.UNAUTHORIZED_CLIENT, tokenRequest.getState()), HttpResponseStatus.UNAUTHORIZED);
			}
		}
	}

    private AccessToken handleCustomGrantType(TokenRequest tokenRequest, HttpRequest req) throws OAuthException {
        String scope = scopeService.getValidScope(tokenRequest.getScope(), tokenRequest.getClientId());
        if (scope == null) {
            throw new OAuthException(new TokenError(TokenErrorTypes.INVALID_SCOPE, tokenRequest.getState()), HttpResponseStatus.BAD_REQUEST);
        }
        try {
            AccessToken accessToken = new AccessToken(TOKEN_TYPE_BEARER, getExpiresIn(TokenRequest.PASSWORD, scope), scope,
                    getExpiresIn(TokenRequest.REFRESH_TOKEN, scope));
            accessToken.setClientId(tokenRequest.getClientId());
            UserDetails userDetails = callCustomGrantTypeHandler(req);
            if (userDetails != null && userDetails.getUserId() != null) {
                accessToken.setUserId(userDetails.getUserId());
                accessToken.setDetails(userDetails.getDetails());
            }
            db.storeAccessToken(accessToken);
            return accessToken;
        } catch (AuthenticationException e) {
            // in case some custom response should be returned other than HTTP 401
            // for instance, if the user authentication requires more user details as a subsequent step
            if (e.getResponse() != null) {
                String responseContent = e.getResponse().getContent().toString(CharsetUtil.UTF_8);
                throw new OAuthException(e, responseContent, e.getResponse().getStatus());
            } else {
                log.error("Cannot authenticate user", e);
                throw new OAuthException(e, new TokenError(TokenErrorTypes.UNAUTHORIZED_CLIENT, tokenRequest.getState()), HttpResponseStatus.UNAUTHORIZED);
            }
        }
    }

    public AccessToken issueAccessToken(HttpRequest req) throws OAuthException {
        return issueAccessToken(req, new TokenRequest(req));
    }
	
	public AccessToken issueAccessToken(HttpRequest req, TokenRequest tokenRequest) throws OAuthException {
        if (tokenRequest.getClientId() == null) {
            String clientId = getBasicAuthorizationClientId(req);
            // TODO: check Basic Auth is OK
            if (clientId == null || !isActiveClientId(clientId)) {
                throw new OAuthException(new TokenError(TokenErrorTypes.INACTIVE_CLIENT_CREDENTIALS, tokenRequest.getState()), HttpResponseStatus.BAD_REQUEST);
            }
            tokenRequest.setClientId(clientId);
            tokenRequest.validate(customGrantType);
        } else {
            tokenRequest.validate(customGrantType);
            // check valid client_id, client_secret and status of the client app should be active
            if (!isActiveClient(tokenRequest.getClientId(), tokenRequest.getClientSecret())) {
                throw new OAuthException(new TokenError(TokenErrorTypes.INVALID_CLIENT_CREDENTIALS, tokenRequest.getState()), HttpResponseStatus.BAD_REQUEST);
            }
        }

        AccessToken accessToken = null;
        if (TokenRequest.AUTHORIZATION_CODE.equals(tokenRequest.getGrantType())) {
            accessToken = handleAuthorizationCodeGrantType(tokenRequest);
        } else if (TokenRequest.REFRESH_TOKEN.equals(tokenRequest.getGrantType())) {
            accessToken = handleRefreshTokenGrantType(tokenRequest);
        } else if (TokenRequest.CLIENT_CREDENTIALS.equals(tokenRequest.getGrantType())) {
        	accessToken = handleClientCredentialsGrantType(tokenRequest);
        } else if (TokenRequest.PASSWORD.equals(tokenRequest.getGrantType())) {
        	accessToken = handlePasswordGrantType(tokenRequest, req);
        } else if (tokenRequest.getGrantType().equals(customGrantType)) {
            accessToken = handleCustomGrantType(tokenRequest, req);
        }
        
        return accessToken;
    }
	
    protected UserDetails authenticateUser(String username, String password, HttpRequest authRequest) throws AuthenticationException {
        UserDetails userDetails;
        if (userAuthenticationClass != null) {
            try {
                IUserAuthentication ua = userAuthenticationClass.newInstance();
                userDetails = ua.authenticate(username, password, authRequest);
            } catch (InstantiationException e) {
                log.error("cannot instantiate user authentication class", e);
                throw new AuthenticationException(e.getMessage());
            } catch (IllegalAccessException e) {
                log.error("cannot instantiate user authentication class", e);
                throw new AuthenticationException(e.getMessage());
            }
        } else {
            // if no specific UserAuthentication used, always returns guest customer
            userDetails = new GuestUserAuthentication().authenticate(username, password, authRequest);
        }
        return userDetails;
    }

    protected UserDetails callCustomGrantTypeHandler(HttpRequest authRequest) throws AuthenticationException {
        UserDetails userDetails = null;
        ICustomGrantTypeHandler customHandler;
        if (userCustomGrantTypeHandler != null) {
            try {
                customHandler = userCustomGrantTypeHandler.newInstance();
                userDetails = customHandler.execute(authRequest);
            } catch (InstantiationException e) {
                log.error("cannot instantiate custom grant_type class", e);
                throw new AuthenticationException(e.getMessage());
            } catch (IllegalAccessException e) {
                log.error("cannot instantiate custom grant_type class", e);
                throw new AuthenticationException(e.getMessage());
            }
        }
        return userDetails;
    }

    protected String getBasicAuthorizationClientId(HttpRequest req) {
        // extract Basic Authorization header
        String authHeader = req.headers().get(HttpHeaders.Names.AUTHORIZATION);
        String clientId = null;
        if (authHeader != null && authHeader.startsWith(BASIC)) {
            String value = authHeader.substring(BASIC.length());
            Base64 decoder = new Base64();
            byte[] decodedBytes = decoder.decode(value);
            String decoded = new String(decodedBytes, Charset.forName("UTF-8"));
            // client_id:client_secret - should be changed by client password
            String[] str = decoded.split(":");
            if (str.length == 2) {
                String authClientId = str[0];
                String authClientSecret = str[1];
                // check valid - DB call
                if (db.validClient(authClientId, authClientSecret)) {
                    clientId = authClientId;
                }
            }
        }
        return clientId;
    }

    protected AuthCode findAuthCode(TokenRequest tokenRequest) {
        return db.findAuthCode(tokenRequest.getCode(), tokenRequest.getRedirectUri());
    }

    public AccessToken isValidToken(String token) {
        AccessToken accessToken = db.findAccessToken(token);
        if (accessToken != null && accessToken.isValid()) {
            if (accessToken.tokenExpired()) {
                db.updateAccessTokenValidStatus(accessToken.getToken(), false);
                return null;
            }
            return accessToken;
        }
        return null;
    }

    public ApplicationInfo getApplicationInfo(String clientId) {
        ApplicationInfo appInfo = null;
        ClientCredentials creds = db.findClientCredentials(clientId);
        if (creds != null) {
            appInfo = new ApplicationInfo();
            appInfo.setName(creds.getName());
            appInfo.setDescription(creds.getDescr());
            appInfo.setScope(creds.getScope());
            appInfo.setRedirectUri(creds.getUri());
            appInfo.setRegistered(new Date(creds.getCreated()));
            appInfo.setStatus(creds.getStatus());
            appInfo.setApplicationDetails(creds.getApplicationDetails());
        }
        return appInfo;
    }

    protected String generateCode() {
        return AuthCode.generate();
    }

    protected boolean isActiveClientId(String clientId) {
        ClientCredentials creds = db.findClientCredentials(clientId);
        return (creds != null && creds.getStatus() == ClientCredentials.ACTIVE_STATUS);
    }

    // check only that clientId and clientSecret are valid, NOT that the status is active
    protected boolean isValidClientCredentials(String clientId, String clientSecret) {
        ClientCredentials creds = db.findClientCredentials(clientId);
        return (creds != null && creds.getSecret().equals(clientSecret));
    }

    protected boolean isActiveClient(String clientId, String clientSecret) {
        ClientCredentials creds = db.findClientCredentials(clientId);
        return (creds != null && creds.getSecret().equals(clientSecret) && creds.getStatus() == ClientCredentials.ACTIVE_STATUS);
    }

    protected boolean isExistingClient(String clientId) {
        ClientCredentials creds = db.findClientCredentials(clientId);
        return (creds != null);
    }

    protected String getExpiresIn(String tokenGrantType, String scope) {
        return String.valueOf(scopeService.getExpiresIn(tokenGrantType, scope));
    }

    public boolean revokeToken(HttpRequest req) throws OAuthException {
        RevokeTokenRequest revokeRequest = new RevokeTokenRequest(req);
        revokeRequest.checkMandatoryParams();
        String clientId = revokeRequest.getClientId();
        // check valid client_id, status does not matter as token of inactive client app could be revoked too
        if (!isExistingClient(clientId)) {
            throw new OAuthException(Response.INACTIVE_CLIENT_CREDENTIALS, HttpResponseStatus.BAD_REQUEST);
        }
        String token = revokeRequest.getAccessToken();
        AccessToken accessToken = db.findAccessToken(token);
        if (accessToken != null) {
            if (accessToken.tokenExpired()) {
                log.debug("access token {} is expired", token);
                return true;
            }
            if (clientId.equals(accessToken.getClientId())) {
                db.removeAccessToken(accessToken.getToken());
                log.debug("access token {} set status invalid", token);
                return true;
            } else {
                log.debug("access token {} is not obtained for that clientId {}", token, clientId);
                return false;
            }
        }
        log.debug("access token {} not found", token);
        return false;
    }

    private void checkScopeList(ApplicationInfo appInfo) throws OAuthException {
        if (appInfo.getScope() != null) {
            String[] scopeList = appInfo.getScope().split(" ");
            for (String s : scopeList) {
                // TODO: add cache for scope
                if (db.findScope(s) == null) {
                    throw new OAuthException(ScopeService.SCOPE_DOES_NOT_EXIST_ERROR, HttpResponseStatus.BAD_REQUEST);
                }
            }
        }
    }

    public boolean updateClientCredentials(HttpRequest req, String clientId) throws OAuthException {
        String content = req.getContent().toString(CharsetUtil.UTF_8);
        String contentType = req.headers().get(HttpHeaders.Names.CONTENT_TYPE);
        if (contentType != null && contentType.contains(Response.APPLICATION_JSON)) {
//            String clientId = getBasicAuthorizationClientId(req);
//            if (clientId == null) {
//                throw new OAuthException(Response.INACTIVE_CLIENT_CREDENTIALS, HttpResponseStatus.BAD_REQUEST);
//            }
            if (!isExistingClient(clientId)) {
                throw new OAuthException(Response.INACTIVE_CLIENT_CREDENTIALS, HttpResponseStatus.BAD_REQUEST);
            }
            ObjectMapper mapper = new ObjectMapper();
            ApplicationInfo appInfo;
            try {
                appInfo = mapper.readValue(content, ApplicationInfo.class);
                if (appInfo.validForUpdate()) {
                    checkScopeList(appInfo);
                    db.updateClientApp(clientId, appInfo.getScope(), appInfo.getDescription(), appInfo.getStatus(),
                                       appInfo.getApplicationDetails());
                } else {
                    throw new OAuthException(Response.UPDATE_APP_MANDATORY_PARAM_MISSING, HttpResponseStatus.BAD_REQUEST);
                }
            } catch (JsonParseException e) {
                throw new OAuthException(e, Response.CANNOT_UPDATE_APP, HttpResponseStatus.BAD_REQUEST);
            } catch (JsonMappingException e) {
                throw new OAuthException(e, Response.CANNOT_UPDATE_APP, HttpResponseStatus.BAD_REQUEST);
            } catch (IOException e) {
                throw new OAuthException(e, Response.CANNOT_UPDATE_APP, HttpResponseStatus.BAD_REQUEST);
            }
        } else {
            throw new OAuthException(Response.UNSUPPORTED_MEDIA_TYPE, HttpResponseStatus.BAD_REQUEST);
        }
        return true;
    }

}
