package com.apifest.oauth20;

import com.apifest.oauth20.persistence.DBManager;
import org.codehaus.jackson.JsonParseException;
import org.codehaus.jackson.map.JsonMappingException;
import org.codehaus.jackson.map.ObjectMapper;
import org.jboss.netty.handler.codec.http.HttpHeaders;
import org.jboss.netty.handler.codec.http.HttpRequest;
import org.jboss.netty.handler.codec.http.HttpResponseStatus;
import org.jboss.netty.util.CharsetUtil;

import java.io.IOException;

/**
 * Responsible for storing and loading OAuth20 client credentials.
 *
 * @author Edouard De Oliveira
 */
public class ClientCredentialsService {

    protected DBManager db = DBManagerFactory.getInstance();

    /**
     * Issue {@link ClientCredentials} for an app
     *
     * @param req the request
     * @return created credentials
     * @throws OAuthException
     */
    protected ClientCredentials issueClientCredentials(HttpRequest req) throws OAuthException {
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

    protected boolean updateClientCredentials(HttpRequest req, String clientId) throws OAuthException {
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
        return (db.findClientCredentials(clientId) != null);
    }
}
