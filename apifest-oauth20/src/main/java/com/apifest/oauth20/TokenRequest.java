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

import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;
import org.jboss.netty.handler.codec.http.HttpRequest;
import org.jboss.netty.handler.codec.http.HttpResponseStatus;
import org.jboss.netty.util.CharsetUtil;

/**
 * Represents token request.
 *
 * @author Rossitsa Borissova
 */
public class TokenRequest {

    public static final String AUTHORIZATION_CODE = "authorization_code";
    public static final String REFRESH_TOKEN = "refresh_token";
    public static final String CLIENT_CREDENTIALS = "client_credentials";
    public static final String PASSWORD = "password";

    protected static final String GRANT_TYPE = "grant_type";
    protected static final String CODE = "code";
    protected static final String REDIRECT_URI = "redirect_uri";
    protected static final String CLIENT_ID = "client_id";
    protected static final String CLIENT_SECRET = "client_secret";
    protected static final String SCOPE = "scope";
    protected static final String USERNAME = "username";

    protected static final String STATE = "state";

    private String grantType;
    private String code;
    private String redirectUri;
    private String clientId;
    private String clientSecret;
    private String refreshToken;
    private String scope;
    private String username;
    private String password;
    private String userId;
    private String state;

    public TokenRequest(HttpRequest request) {
        this(request, null);
    }

    public TokenRequest(HttpRequest request, Map<String, String> additionalParams) {
        String content = request.getContent().toString(CharsetUtil.UTF_8);
        Map<String, String> params = parseContent(content);
        assignValues(request, params);

        if (additionalParams != null) {
            assignValues(request, additionalParams);
        }
    }

    private Map<String, String> parseContent(String content) {
        List<NameValuePair> values = URLEncodedUtils.parse(content, Charset.forName("UTF-8"));
        Map<String, String> params = new HashMap<String, String>();
        for (NameValuePair pair : values) {
            params.put(pair.getName(), pair.getValue());
        }

        return params;
    }

    private String assignIfEmpty(String var, Map<String, String> params, String key) {
        if (var != null) {
            return var;
        }
        return params.get(key);
    }

    private void assignValues(HttpRequest request, Map<String, String> params) {
        this.grantType = assignIfEmpty(this.grantType, params, GRANT_TYPE);
        this.code = assignIfEmpty(this.code, params, CODE);
        this.redirectUri = assignIfEmpty(this.redirectUri, params, REDIRECT_URI);
        this.clientId = assignIfEmpty(this.clientId, params,CLIENT_ID);
        this.clientSecret = assignIfEmpty(this.clientSecret, params, CLIENT_SECRET);
        if (this.clientId == null && this.clientSecret == null) {
            String[] clientCredentials = AuthorizationServer.getBasicAuthorizationClientCredentials(request);
            this.clientId = clientCredentials[0];
            this.clientSecret = clientCredentials[1];
        }
        this.refreshToken = assignIfEmpty(this.refreshToken, params, REFRESH_TOKEN);
        this.scope = assignIfEmpty(this.scope, params, SCOPE);
        this.username = assignIfEmpty(this.username, params, USERNAME);
        this.password = assignIfEmpty(this.password, params, PASSWORD);
        this.state = assignIfEmpty(this.state, params, STATE);
    }

    public void validate(String customGrantType) throws OAuthException {
        checkMandatoryParams();
        if (!grantType.equals(AUTHORIZATION_CODE) && !grantType.equals(REFRESH_TOKEN)
                && !grantType.equals(CLIENT_CREDENTIALS) && !grantType.equals(PASSWORD)
                && !grantType.equals(customGrantType)) {
            TokenError err = new TokenError(TokenErrorTypes.UNSUPPORTED_GRANT_TYPE, state);
            throw new OAuthException(err, HttpResponseStatus.BAD_REQUEST);
        }
        if (grantType.equals(AUTHORIZATION_CODE)) {
            if (code == null) {
                TokenError err = new TokenError(TokenErrorTypes.MANDATORY_PARAM_MISSING, state);
                err.setMessageParams(CODE);
                throw new OAuthException(err, HttpResponseStatus.BAD_REQUEST);
            }
            if (redirectUri == null) {
                TokenError err = new TokenError(TokenErrorTypes.MANDATORY_PARAM_MISSING, state);
                err.setMessageParams(REDIRECT_URI);
                throw new OAuthException(err, HttpResponseStatus.BAD_REQUEST);
            }
        }
        if (grantType.equals(REFRESH_TOKEN) && refreshToken == null) {
            TokenError err = new TokenError(TokenErrorTypes.MANDATORY_PARAM_MISSING, state);
            err.setMessageParams(REFRESH_TOKEN);
            throw new OAuthException(err, HttpResponseStatus.BAD_REQUEST);
        }
        if (grantType.equals(PASSWORD)) {
            if (username == null) {
                TokenError err = new TokenError(TokenErrorTypes.MANDATORY_PARAM_MISSING, state);
                err.setMessageParams(USERNAME);
                throw new OAuthException(err, HttpResponseStatus.BAD_REQUEST);
            }
            if (password == null) {
                TokenError err = new TokenError(TokenErrorTypes.MANDATORY_PARAM_MISSING, state);
                err.setMessageParams(PASSWORD);
                throw new OAuthException(err, HttpResponseStatus.BAD_REQUEST);
            }
        }
    }

    protected void checkMandatoryParams() throws OAuthException {
        if (clientId == null || clientId.isEmpty()) {
            TokenError err = new TokenError(TokenErrorTypes.MANDATORY_PARAM_MISSING, state);
            err.setMessageParams(CLIENT_ID);
            throw new OAuthException(err, HttpResponseStatus.BAD_REQUEST);
        }
        if (clientSecret == null || clientSecret.isEmpty()) {
            TokenError err = new TokenError(TokenErrorTypes.MANDATORY_PARAM_MISSING, state);
            err.setMessageParams(CLIENT_SECRET);
            throw new OAuthException(err, HttpResponseStatus.BAD_REQUEST);
        }
        if (grantType == null || grantType.isEmpty()) {
            TokenError err = new TokenError(TokenErrorTypes.MANDATORY_PARAM_MISSING, state);
            err.setMessageParams(GRANT_TYPE);
            throw new OAuthException(err, HttpResponseStatus.BAD_REQUEST);
        }
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getGrantType() {
        return grantType;
    }

    public String getCode() {
        return code;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public String getClientId() {
        return clientId;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getScope() {
        return scope;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    protected String getState() {
        return state;
    }
}
