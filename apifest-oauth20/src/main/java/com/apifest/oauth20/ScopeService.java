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

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.codehaus.jackson.JsonGenerationException;
import org.codehaus.jackson.JsonParseException;
import org.codehaus.jackson.map.JsonMappingException;
import org.codehaus.jackson.map.ObjectMapper;
import org.jboss.netty.handler.codec.http.HttpHeaders;
import org.jboss.netty.handler.codec.http.HttpRequest;
import org.jboss.netty.handler.codec.http.HttpResponseStatus;
import org.jboss.netty.handler.codec.http.QueryStringDecoder;
import org.jboss.netty.util.CharsetUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.apifest.oauth20.persistence.DBManager;
/**
 * Responsible for storing and loading OAuth20 scopes.
 *
 * @author Rossitsa Borissova
 */
public class ScopeService {

    static Logger log = LoggerFactory.getLogger(ScopeService.class);

    protected static final String MANDATORY_FIELDS_FOR_SCOPE_REGISTER_ERROR = "{\"error\":\"invalid mandatory fields for scope registration\"}";
    protected static final String MANDATORY_FIELDS_FOR_SCOPE_UPDATE_ERROR = "{\"error\":\"invalid mandatory fields for scope update\"}";
    protected static final String INVALID_SCOPE_NAME_ERROR = "{\"error\":\"invalid scope name - it may contain alpha-numeric, - and _ characters\"}";
    protected static final String INVALID_SCOPE_ERROR = "{\"error\":\"invalid scope\"}";
    protected static final String SCOPE_DOES_NOT_EXIST_ERROR = "{\"error\":\"scope does not exist\"}";
    protected static final String NO_SCOPES_ERROR = "{\"error\":\"scope does not exist\"}";

    protected static final String SCOPE_STORED_OK_MESSAGE = "{\"status\":\"scope successfully stored\"}";
    protected static final String SCOPE_STORED_NOK_MESSAGE = "{\"status\":\"scope not stored\"}";
    protected static final String SCOPE_UPDATED_OK_MESSAGE = "{\"status\":\"scope successfully updated\"}";
    protected static final String SCOPE_UPDATED_NOK_MESSAGE = "{\"status\":\"scope not updated\"}";
    protected static final String SCOPE_NOT_EXISTS_MESSAGE = "{\"status\":\"scope does not exist\"}";
    protected static final String SCOPE_ALREADY_EXISTS_MESSAGE = "{\"status\":\"scope already exists\"}";
    protected static final String SCOPE_DELETED_OK_MESSAGE = "{\"status\":\"scope successfully deleted\"}";
    protected static final String SCOPE_DELETED_NOK_MESSAGE = "{\"status\":\"scope not deleted\"}";
    protected static final String SCOPE_USED_BY_APP_MESSAGE = "{\"status\":\"scope cannot be deleted, there are client apps registered with it\"}";

    private static final String SPACE = " ";

    /**
     * Register an oauth scope. If the scope already exists, returns an error.
     *
     * @param req http request
     * @return String message that will be returned in the response
     */
    public String registerScope(HttpRequest req) throws OAuthException {
        String content = req.getContent().toString(CharsetUtil.UTF_8);
        String contentType = (req.headers() != null) ? req.headers().get(HttpHeaders.Names.CONTENT_TYPE) : null;

        // check Content-Type
        if (contentType != null && contentType.contains(Response.APPLICATION_JSON)) {
            ObjectMapper mapper = new ObjectMapper();
            try {
                Scope scope = mapper.readValue(content, Scope.class);
                if (scope.valid()) {
                    if (!Scope.validScopeName(scope.getScope())) {
                        log.error("scope name is not valid");
                        throw new OAuthException(INVALID_SCOPE_NAME_ERROR, HttpResponseStatus.BAD_REQUEST);
                    }
                    Scope foundScope = DBManagerFactory.getInstance().findScope(scope.getScope());
                    if (foundScope != null) {
                        log.error("scope already exists");
                        throw new OAuthException(SCOPE_ALREADY_EXISTS_MESSAGE, HttpResponseStatus.BAD_REQUEST);
                    } else {
                        // store in the DB, if already exists such a scope, overwrites it
                        boolean ok = DBManagerFactory.getInstance().storeScope(scope);
                        if (ok) {
                            return SCOPE_STORED_OK_MESSAGE;
                        } else {
                            return SCOPE_STORED_NOK_MESSAGE;
                        }
                    }
                } else {
                    log.error("scope is not valid");
                    throw new OAuthException(MANDATORY_FIELDS_FOR_SCOPE_REGISTER_ERROR, HttpResponseStatus.BAD_REQUEST);
                }
            } catch (JsonParseException e) {
                log.error("cannot parse scope request", e);
                throw new OAuthException(e, INVALID_SCOPE_ERROR, HttpResponseStatus.BAD_REQUEST);
            } catch (JsonMappingException e) {
                log.error("cannot map scope request", e);
                throw new OAuthException(e, INVALID_SCOPE_ERROR, HttpResponseStatus.BAD_REQUEST);
            } catch (IOException e) {
                log.error("cannot handle scope request", e);
                throw new OAuthException(e, INVALID_SCOPE_ERROR, HttpResponseStatus.BAD_REQUEST);
            }
        } else {
            throw new OAuthException(Response.UNSUPPORTED_MEDIA_TYPE, HttpResponseStatus.BAD_REQUEST);
        }
    }

    /**
     * Returns either all scopes or scopes for a specific client_id passed as query parameter.
     *
     * @param req request
     * @return string If query param client_id is passed, then the scopes for that client_id will be returned.
     * Otherwise, all available scopes will be returned in JSON format.
     */
    public String getScopes(HttpRequest req) throws OAuthException {
        QueryStringDecoder dec = new QueryStringDecoder(req.getUri());
        Map<String, List<String>> queryParams = dec.getParameters();
        if(queryParams.containsKey("client_id")) {
            return getScopes(queryParams.get("client_id").get(0));
        }
        List<Scope> scopes = DBManagerFactory.getInstance().getAllScopes();
        ObjectMapper mapper = new ObjectMapper();
        String jsonString;
        try {
            jsonString = mapper.writeValueAsString(scopes);
        } catch (JsonGenerationException e) {
            log.error("cannot load scopes", e);
            throw new OAuthException(e, NO_SCOPES_ERROR, HttpResponseStatus.BAD_REQUEST);
        } catch (JsonMappingException e) {
            log.error("cannot load scopes", e);
            throw new OAuthException(e, NO_SCOPES_ERROR, HttpResponseStatus.BAD_REQUEST);
        } catch (IOException e) {
            log.error("cannot load scopes", e);
            throw new OAuthException(e, NO_SCOPES_ERROR, HttpResponseStatus.BAD_REQUEST);
        }
        return jsonString;
    }

    /**
     * Checks whether a scope is valid for a given client id.
     *
     * @param scope oauth scope
     * @param clientId client id
     * @return the scope if it is valid, otherwise returns null
     */
    public String getValidScope(String scope, String clientId) {
        ClientCredentials creds = DBManagerFactory.getInstance().findClientCredentials(clientId);
        if(creds == null) {
            return null;
        }
        return getValidScopeByScope(scope, creds.getScope());
    }

    public String getValidScopeByScope(String scope, String storedScope) {
        String validScope = null;
        if(scope == null || scope.length() == 0) {
            // get client scope
            validScope = storedScope;
        } else {
            // check that scope exists and is allowed for that client app
            if(scopeAllowed(scope, storedScope)) {
                validScope = scope;
            }
        }
        return validScope;
    }

    /**
     * Checks whether a scope is contained in allowed scopes.
     *
     * @param scope scope to be checked
     * @param allowedScopes all allowed scopes
     * @return <code>true<code> if the scope is allowed, otherwise <code>false</code>>
     */
    public boolean scopeAllowed(String scope, String allowedScopes) {
        String [] allScopes = allowedScopes.split(SPACE);
        List<String> allowedList = Arrays.asList(allScopes);
        String [] scopes = scope.split(SPACE);
        int allowedCount = 0;
        for(String s : scopes) {
            if (allowedList.contains(s)) {
                allowedCount++;
            }
        }
        return (allowedCount == scopes.length);
    }

    /**
     * Returns value for expires_in by given scope and token type.
     *
     * @param tokenGrantType client_credentials or password type
     * @param scope scope/s for which expires in will be returned
     * @return minimum value of given scope/s expires_in
     */
    public int getExpiresIn(String tokenGrantType, String scope) {
        int expiresIn = Integer.MAX_VALUE;
        List<Scope> scopes = loadScopes(scope);
        boolean ccGrantType = TokenRequest.CLIENT_CREDENTIALS.equals(tokenGrantType);
        if (ccGrantType) {
            for (Scope s : scopes) {
                expiresIn = Math.min(s.getCcExpiresIn(), expiresIn);
            }
        } else if (TokenRequest.PASSWORD.equals(tokenGrantType)) {
            for (Scope s : scopes) {
                expiresIn = Math.min(s.getPassExpiresIn(), expiresIn);
            }
        } else {
            // refresh_token
            for (Scope s : scopes) {
                expiresIn = Math.min(s.getRefreshExpiresIn(), expiresIn);
            }
        }
        if (scopes.size() == 0 || expiresIn == Integer.MAX_VALUE) {
            expiresIn = (ccGrantType) ? OAuthServer.DEFAULT_CC_EXPIRES_IN : OAuthServer.DEFAULT_PASSWORD_EXPIRES_IN;
        }
        return expiresIn;
    }

    /**
     * Updates a scope. If the scope does not exists, returns an error.
     *
     * @param req http request
     * @param scopeName the scope to update
     * @return String message that will be returned in the response
     */
    public String updateScope(HttpRequest req, String scopeName) throws OAuthException {
        String content = req.getContent().toString(CharsetUtil.UTF_8);
        String contentType = (req.headers() != null) ? req.headers().get(HttpHeaders.Names.CONTENT_TYPE) : null;
        String responseMsg;
        // check Content-Type
        if (contentType != null && contentType.contains(Response.APPLICATION_JSON)) {
            ObjectMapper mapper = new ObjectMapper();
            try {
                Scope scope = mapper.readValue(content, Scope.class);
                if (scope.validForUpdate()) {
                    Scope foundScope = DBManagerFactory.getInstance().findScope(scopeName);
                    if (foundScope == null) {
                        log.error("scope does not exist");
                        throw new OAuthException(SCOPE_NOT_EXISTS_MESSAGE, HttpResponseStatus.BAD_REQUEST);
                    } else {
                        setScopeEmptyValues(scope, foundScope);
                        boolean ok = DBManagerFactory.getInstance().storeScope(scope);
                        if (ok) {
                            responseMsg = SCOPE_UPDATED_OK_MESSAGE;
                        } else {
                            responseMsg = SCOPE_UPDATED_NOK_MESSAGE;
                        }
                    }
                } else {
                    log.error("scope is not valid");
                    throw new OAuthException(MANDATORY_FIELDS_FOR_SCOPE_UPDATE_ERROR, HttpResponseStatus.BAD_REQUEST);
                }
            } catch (JsonParseException e) {
                log.error("cannot parse scope request", e);
                throw new OAuthException(e, SCOPE_UPDATED_NOK_MESSAGE, HttpResponseStatus.BAD_REQUEST);
            } catch (JsonMappingException e) {
                log.error("cannot map scope request", e);
                throw new OAuthException(e, SCOPE_UPDATED_NOK_MESSAGE, HttpResponseStatus.BAD_REQUEST);
            } catch (IOException e) {
                log.error("cannot handle scope request", e);
                throw new OAuthException(e, SCOPE_UPDATED_NOK_MESSAGE, HttpResponseStatus.BAD_REQUEST);
            }
        } else {
            throw new OAuthException(Response.UNSUPPORTED_MEDIA_TYPE, HttpResponseStatus.BAD_REQUEST);
        }
        return responseMsg;
    }

    /**
     * Deletes a scope. If the scope does not exists, returns an error.
     *
     * @param scopeName the scope to delete
     * @return String message that will be returned in the response
     */
    public String deleteScope(String scopeName) throws OAuthException {
        Scope foundScope = DBManagerFactory.getInstance().findScope(scopeName);
        if (foundScope == null) {
            log.error("scope does not exist");
            throw new OAuthException(SCOPE_NOT_EXISTS_MESSAGE, HttpResponseStatus.BAD_REQUEST);
        } else {
            // first, check whether there is a client app registered with that scope
            if (checkForClientAppByScope(scopeName)) {
                return SCOPE_USED_BY_APP_MESSAGE;
            } else {
                if (DBManagerFactory.getInstance().deleteScope(scopeName)) {
                    return SCOPE_DELETED_OK_MESSAGE;
                } else {
                    return SCOPE_DELETED_NOK_MESSAGE;
                }
            }
        }
    }

    public String getScopeByName(String scopeName) throws OAuthException {
        Scope scope = DBManagerFactory.getInstance().findScope(scopeName);
        if (scope != null) {
            ObjectMapper mapper = new ObjectMapper();
            try {
                return mapper.writeValueAsString(scope);
            } catch (JsonGenerationException e) {
                log.error("cannot load scope", e);
                throw new OAuthException(e, SCOPE_DOES_NOT_EXIST_ERROR, HttpResponseStatus.BAD_REQUEST);
            } catch (JsonMappingException e) {
                log.error("cannot load scope", e);
                throw new OAuthException(e, SCOPE_DOES_NOT_EXIST_ERROR, HttpResponseStatus.BAD_REQUEST);
            } catch (IOException e) {
                log.error("cannot load scope", e);
                throw new OAuthException(e, SCOPE_DOES_NOT_EXIST_ERROR, HttpResponseStatus.BAD_REQUEST);
            }
        } else {
            throw new OAuthException(SCOPE_NOT_EXISTS_MESSAGE, HttpResponseStatus.NOT_FOUND);
        }
    }

    protected boolean checkForClientAppByScope(String scopeName) {
        List<ClientCredentials> allApps = DBManagerFactory.getInstance().getAllApplications();
        for (ClientCredentials app : allApps) {
            if (app.getScope().contains(scopeName)) {
                return true;
            }
        }
        return false;
    }

    protected void setScopeEmptyValues(Scope scope, Scope foundScope) {
        // if some fields are null, keep the old values
        scope.setScope(foundScope.getScope());
        if (scope.getDescription() == null || scope.getDescription().length() == 0) {
            scope.setDescription(foundScope.getDescription());
        }
        if (scope.getCcExpiresIn() == null) {
            scope.setCcExpiresIn(foundScope.getCcExpiresIn());
        }
        if (scope.getPassExpiresIn() == null) {
            scope.setPassExpiresIn(foundScope.getPassExpiresIn());
        }
        if (scope.getRefreshExpiresIn() == null) {
            scope.setRefreshExpiresIn(foundScope.getRefreshExpiresIn());
        }
    }

    protected List<Scope> loadScopes(String scope) {
        String [] scopes = scope.split(SPACE);
        List<Scope> loadedScopes = new ArrayList<Scope>();
        DBManager db = DBManagerFactory.getInstance();
        for (String name : scopes) {
            loadedScopes.add(db.findScope(name));
        }
        return loadedScopes;
    }

    protected String getScopes(String clientId) throws OAuthException {
        ClientCredentials credentials = DBManagerFactory.getInstance().findClientCredentials(clientId);
        String jsonString;
        if(credentials != null) {
            //scopes are separated by comma
            String scopes = credentials.getScope();
            String [] s = scopes.split(SPACE);
            List<Scope> result = new ArrayList<Scope>();
            for(String name : s) {
                Scope scope = DBManagerFactory.getInstance().findScope(name);
                result.add(scope);
            }

            ObjectMapper mapper = new ObjectMapper();
            try {
                jsonString = mapper.writeValueAsString(result);
            } catch (JsonGenerationException e) {
                log.error("cannot load scopes per clientId", e);
                throw new OAuthException(e, ClientCredentialsService.INVALID_CLIENT_CREDENTIALS, HttpResponseStatus.BAD_REQUEST);
            } catch (JsonMappingException e) {
                log.error("cannot load scopes per clientId", e);
                throw new OAuthException(e, ClientCredentialsService.INVALID_CLIENT_CREDENTIALS, HttpResponseStatus.BAD_REQUEST);
            } catch (IOException e) {
                log.error("cannot load scopes per clientId", e);
                throw new OAuthException(e, ClientCredentialsService.INVALID_CLIENT_CREDENTIALS, HttpResponseStatus.BAD_REQUEST);
            }
        } else {
            throw new OAuthException(ClientCredentialsService.CLIENT_APP_DOES_NOT_EXIST, HttpResponseStatus.NOT_FOUND);
        }
        return jsonString;
    }
}
