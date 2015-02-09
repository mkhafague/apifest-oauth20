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
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.apifest.oauth20.api.ICustomGrantTypeHandler;
import com.apifest.oauth20.api.IUserAuthentication;
import org.codehaus.jackson.JsonGenerationException;
import org.codehaus.jackson.map.JsonMappingException;
import org.codehaus.jackson.map.ObjectMapper;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.channel.ChannelFutureListener;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.ExceptionEvent;
import org.jboss.netty.channel.MessageEvent;
import org.jboss.netty.channel.SimpleChannelUpstreamHandler;
import org.jboss.netty.handler.codec.http.HttpHeaders;
import org.jboss.netty.handler.codec.http.HttpMethod;
import org.jboss.netty.handler.codec.http.HttpRequest;
import org.jboss.netty.handler.codec.http.HttpResponse;
import org.jboss.netty.handler.codec.http.HttpResponseStatus;
import org.jboss.netty.handler.codec.http.QueryStringDecoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.apifest.oauth20.api.ExceptionEventHandler;
import com.apifest.oauth20.api.LifecycleHandler;
import com.apifest.oauth20.security.RestrictedAccessException;
import com.apifest.oauth20.security.SubnetRange;
import com.google.gson.Gson;
import com.google.gson.JsonObject;

/**
 * Handler for requests received on the server.
 *
 * @author Rossitsa Borissova
 */
public class HttpRequestHandler extends SimpleChannelUpstreamHandler {

	protected static final String ADMIN_LOGIN_URI = "/oauth20/admin-login";

    protected static final String AUTH_CODE_URI = "/oauth20/auth-codes";
    protected static final String ACCESS_TOKEN_URI = "/oauth20/tokens";
    protected static final String ACCESS_TOKEN_VALIDATE_URI = "/oauth20/tokens/validate";
    protected static final String APPLICATION_URI = "/oauth20/applications";
    protected static final String ACCESS_TOKEN_REVOKE_URI = "/oauth20/tokens/revoke";
    protected static final String OAUTH_CLIENT_SCOPE_URI = "/oauth20/scopes";

    protected static final Pattern OAUTH_CLIENT_SCOPE_PATTERN = Pattern.compile("/oauth20/scopes/((\\p{Alnum}+-?_?)+$)");
    protected static final Pattern APPLICATION_PATTERN = Pattern.compile("/oauth20/applications/([a-f[0-9]]+)$");

    protected Logger log = LoggerFactory.getLogger(HttpRequestHandler.class);

    protected static Logger accessTokensLog = LoggerFactory.getLogger("accessTokens");

    protected AuthorizationServer auth;

    protected SubnetRange allowedIPs;
    private boolean productionMode = false;
	private Map<String, String> serverCredentials;

	public HttpRequestHandler(Class<IUserAuthentication> userAuthenticationClass,
                              Class<ICustomGrantTypeHandler> userCustomGrantTypeHandler) {
        auth = new AuthorizationServer(userAuthenticationClass, userCustomGrantTypeHandler);
    }
	
	protected void setContext(Map<String, String> serverCredentials, SubnetRange allowedIPs, boolean productionMode) {
		this.serverCredentials = serverCredentials;
		this.allowedIPs = allowedIPs;
		this.productionMode = productionMode;
	}

	private void checkSecurityRestrictions(ChannelHandlerContext ctx, String rawUri, HttpRequest req) throws RestrictedAccessException {
		checkSecurityRestrictions(true, ctx, rawUri, req);
	}
	
	private void checkSecurityRestrictions(boolean checkAuth, ChannelHandlerContext ctx, String rawUri, HttpRequest req) throws RestrictedAccessException {
		if (productionMode) {
			String addr = ((InetSocketAddress) ctx.getChannel().getRemoteAddress()).getAddress().getHostAddress();
			
			if (!allowedIPs.inRange(addr)) {
				log.info("Unauthorized access to "+rawUri+" from "+addr+" ...");
				HttpResponse unauthorizedResponse = Response.createResponse(HttpResponseStatus.FORBIDDEN, "Unauthorized access");
				throw new RestrictedAccessException(unauthorizedResponse);
			}
			
			if (checkAuth) {
				String authHeader = req.headers().get(HttpHeaders.Names.AUTHORIZATION);
				if (authHeader == null || !authHeader.startsWith("Bearer ")) {
					log.info("Unauthorized access (invalid auth) to "+rawUri+" from "+addr+" ...");
					throw new RestrictedAccessException(Response.createUnauthorizedResponse());
				}
				else {
					String tokenParam = authHeader.substring(7);
					AccessToken token = auth.isValidToken(tokenParam);
					if (token == null || !token.isValid()) {
						log.info("Unauthorized access (invalid token) to "+rawUri+" from "+addr+" ...");
						throw new RestrictedAccessException(Response.createUnauthorizedResponse());				
					}
				}
			}
		}
	}
	
    @Override
    public void messageReceived(ChannelHandlerContext ctx, MessageEvent e) {
        final Channel channel = ctx.getChannel();
        Object message = e.getMessage();
        if (message instanceof HttpRequest) {
            HttpRequest req = (HttpRequest) message;
            invokeRequestEventHandlers(req, null);

            HttpMethod method = req.getMethod();
            String rawUri = req.getUri();
            try {
                URI u = new URI(rawUri);
                rawUri = u.getRawPath();
            } catch (URISyntaxException e2) {
                log.error("URI syntax exception {}", rawUri);
                invokeExceptionHandler(e2, req);
            }

            HttpResponse response;
            try {
            	if (ADMIN_LOGIN_URI.equals(rawUri) && method.equals(HttpMethod.POST)) {
            		checkSecurityRestrictions(false, ctx, rawUri, req);
            		response = handleLogin(req);
            	} 
            	// APPLICATION URI's 
            	else if (APPLICATION_URI.equals(rawUri)) {
            		if (method.equals(HttpMethod.GET)) {
		            	checkSecurityRestrictions(ctx, rawUri, req);
		                response = handleGetAllClientApplications(req);
            		} else if (method.equals(HttpMethod.POST)) {
		    			checkSecurityRestrictions(ctx, rawUri, req); 
		                response = handleRegister(req);
		            } else {
		            	response = Response.createNotFoundResponse();
		            }
	            } else if (rawUri.startsWith(APPLICATION_URI)) {
	            	if (method.equals(HttpMethod.GET)) {
		            	checkSecurityRestrictions(ctx, rawUri, req);
		                response = handleGetClientApplication(req);
	            	} else if (method.equals(HttpMethod.PUT)) {
		            	checkSecurityRestrictions(ctx, rawUri, req);
		                response = handleUpdateClientApplication(req);
		            } else {
		            	response = Response.createNotFoundResponse();
		            }
	            } else if (AUTH_CODE_URI.equals(rawUri) && method.equals(HttpMethod.GET)) {
	                response = handleAuthorize(req);
	            } 
	            // ACCESS TOKEN URI's
	            else if (ACCESS_TOKEN_URI.equals(rawUri)) {
	            	if (method.equals(HttpMethod.GET)) {
		            	checkSecurityRestrictions(ctx, rawUri, req);
		                response = handleGetAccessTokens(req);
	            	} else if (method.equals(HttpMethod.POST))
	            		response = handleToken(req);
		            else {
		            	response = Response.createNotFoundResponse();
		            }
	            } else if (ACCESS_TOKEN_VALIDATE_URI.equals(rawUri) && method.equals(HttpMethod.GET)) {
	            	// restrict IP access only, this is a server to server call ?!
	            	checkSecurityRestrictions(false, ctx, rawUri, req);
	                response = handleTokenValidate(req);
	            } else if (ACCESS_TOKEN_REVOKE_URI.equals(rawUri) && method.equals(HttpMethod.POST)) {
	            	checkSecurityRestrictions(ctx, rawUri, req);
	                response = handleTokenRevoke(req);
	            } 
	            // SCOPE URI's
	            else if (OAUTH_CLIENT_SCOPE_URI.equals(rawUri)) {
	            	if (method.equals(HttpMethod.GET)) {
	            		checkSecurityRestrictions(ctx, rawUri, req);
	            		response = handleGetAllScopes(req);
	            	} else if (method.equals(HttpMethod.POST)) {
		            	checkSecurityRestrictions(ctx, rawUri, req);
		                response = handleRegisterScope(req);
		            } else {
		            	response = Response.createNotFoundResponse();
		            }
	            } else if (rawUri.startsWith(OAUTH_CLIENT_SCOPE_URI)) {
	            	if (method.equals(HttpMethod.GET)) {
		            	checkSecurityRestrictions(ctx, rawUri, req);
		                response = handleGetScope(req);
		            } else if (method.equals(HttpMethod.PUT)) {
		            	checkSecurityRestrictions(ctx, rawUri, req);
		                response = handleUpdateScope(req);
		            } else if (method.equals(HttpMethod.DELETE)) {
		            	checkSecurityRestrictions(ctx, rawUri, req);
		                response = handleDeleteScope(req);
		            } else {
		            	response = Response.createNotFoundResponse();
		            }
	            } else {
	            	response = Response.createNotFoundResponse();
	            }
            } catch (RestrictedAccessException raex) {
            	response = raex.getResponse();
            }
            invokeResponseEventHandlers(req, response);
            ChannelFuture future = channel.write(response);

            if(!HttpHeaders.isKeepAlive(req)) {
                future.addListener(ChannelFutureListener.CLOSE);
            }
        } else {
            log.info("write response here from the BE");
        }
    }

    protected HttpResponse handleGetClientApplication(HttpRequest req) {
        HttpResponse response = null;
        Matcher m = APPLICATION_PATTERN.matcher(req.getUri());
        if (m.find()) {
            String clientId = m.group(1);
            ApplicationInfo appInfo = auth.getApplicationInfo(clientId);
            if (appInfo != null) {
                ObjectMapper mapper = new ObjectMapper();
                try {
                    String json = mapper.writeValueAsString(appInfo);
                    log.debug(json);
                    response = Response.createOkResponse(json);
                } catch (JsonGenerationException e) {
                    log.error("error getting application info", e);
                    invokeExceptionHandler(e, req);
                } catch (JsonMappingException e) {
                    log.error("error getting application info", e);
                    invokeExceptionHandler(e, req);
                } catch (IOException e) {
                    log.error("error getting application info", e);
                    invokeExceptionHandler(e, req);
                }
            } else {
                response = Response.createResponse(HttpResponseStatus.NOT_FOUND, Response.CLIENT_APP_DOES_NOT_EXIST);
            }
        } else {
            response = Response.createNotFoundResponse();
        }
        return response;
    }

    protected HttpResponse handleTokenValidate(HttpRequest req) {
        HttpResponse response;
        QueryStringDecoder dec = new QueryStringDecoder(req.getUri());
        Map<String, List<String>> params = dec.getParameters();
        String tokenParam = QueryParameter.getFirstElement(params, QueryParameter.TOKEN);
        if (tokenParam == null || tokenParam.isEmpty()) {
            response = Response.createBadRequestResponse();
        } else {
            AccessToken token = auth.isValidToken(tokenParam);
            if (token != null) {
                Gson gson = new Gson();
                String json = gson.toJson(token);
                log.debug(json);
                response = Response.createOkResponse(json);
            } else {
                response = Response.createUnauthorizedResponse();
            }
        }
        return response;
    }

    protected HttpResponse handleLogin(HttpRequest request) {
        HttpResponse response = null;
        String contentType = request.headers().get(HttpHeaders.Names.CONTENT_TYPE);
        if (contentType != null && contentType.contains(HttpHeaders.Values.APPLICATION_X_WWW_FORM_URLENCODED)) {
            TokenRequest tokenRequest = null;
            try {
            	tokenRequest = new TokenRequest(request, serverCredentials);
                AccessToken accessToken = auth.issueAccessToken(request, tokenRequest);
                CSRFAccessToken csrfToken = 
                	new CSRFAccessToken(accessToken, tokenRequest.getState());
                
                if (accessToken != null) {
                    ObjectMapper mapper = new ObjectMapper();
                    String jsonString = mapper.writeValueAsString(csrfToken);
                    log.debug("access token:" + jsonString);
                    response = Response.createOkResponse(jsonString);
                    accessTokensLog.debug("token {}", jsonString);
                }
            } catch (OAuthException ex) {
                response = Response.createOAuthExceptionResponse(ex);
                invokeExceptionHandler(ex, request);
            } catch (JsonGenerationException e1) {
                log.error("error handling login", e1);
                invokeExceptionHandler(e1, request);
            } catch (JsonMappingException e1) {
                log.error("error handling login", e1);
                invokeExceptionHandler(e1, request);
            } catch (IOException e1) {
                log.error("error handling login", e1);
                invokeExceptionHandler(e1, request);
            }

            if (response == null) {
                response = Response.createTokenErrorResponse(
                        new TokenError(TokenErrorTypes.CANNOT_ISSUE_TOKEN, tokenRequest.getState()));
            }
        } else {
            response = Response.createResponse(HttpResponseStatus.BAD_REQUEST, Response.UNSUPPORTED_MEDIA_TYPE);
        }
        return response;
    }
	
    protected HttpResponse handleToken(HttpRequest request) {
        HttpResponse response = null;
        String contentType = request.headers().get(HttpHeaders.Names.CONTENT_TYPE);
        if (contentType != null && contentType.contains(HttpHeaders.Values.APPLICATION_X_WWW_FORM_URLENCODED)) {
            TokenRequest tokenRequest = null;
            try {
				tokenRequest = new TokenRequest(request);
                AccessToken accessToken = auth.issueAccessToken(request, tokenRequest);
                CSRFAccessToken csrfToken = 
                	new CSRFAccessToken(accessToken, tokenRequest.getState());
					
                if (accessToken != null) {
                    ObjectMapper mapper = new ObjectMapper();
                    String jsonString = mapper.writeValueAsString(csrfToken);
                    log.debug("access token:" + jsonString);
                    response = Response.createOkResponse(jsonString);
                    accessTokensLog.debug("token {}", jsonString);
                }
            } catch (OAuthException ex) {
                response = Response.createOAuthExceptionResponse(ex);
                invokeExceptionHandler(ex, request);
            } catch (JsonGenerationException e1) {
                log.error("error handling token", e1);
                invokeExceptionHandler(e1, request);
            } catch (JsonMappingException e1) {
                log.error("error handling token", e1);
                invokeExceptionHandler(e1, request);
            } catch (IOException e1) {
                log.error("error handling token", e1);
                invokeExceptionHandler(e1, request);
            }

            if (response == null) {
                response = Response.createTokenErrorResponse(
                        new TokenError(TokenErrorTypes.CANNOT_ISSUE_TOKEN, tokenRequest.getState()));
            }
        } else {
            response = Response.createResponse(HttpResponseStatus.BAD_REQUEST, Response.UNSUPPORTED_MEDIA_TYPE);
        }

        return response ;
    }

    protected void invokeRequestEventHandlers(HttpRequest request, HttpResponse response) {
        invokeHandlers(request, response, LifecycleEventHandlers.getRequestEventHandlers());
    }

    protected void invokeResponseEventHandlers(HttpRequest request, HttpResponse response) {
        invokeHandlers(request, response, LifecycleEventHandlers.getResponseEventHandlers());
    }

    private void invokeHandlers(HttpRequest request, HttpResponse response, List<Class<LifecycleHandler>> handlers) {
        List<Class<LifecycleHandler>> list = new ArrayList<Class<LifecycleHandler>>(handlers);
        for (Class<LifecycleHandler> clazz : list) {
            try {
                LifecycleHandler handler = clazz.newInstance();
                handler.handle(request, response);
            } catch (InstantiationException e) {
                log.error("cannot instantiate handler", e);
                invokeExceptionHandler(e, request);
            } catch (IllegalAccessException e) {
                log.error("cannot invoke handler", e);
                invokeExceptionHandler(e, request);
            }
        }
    }

    protected void invokeExceptionHandler(Exception ex, HttpRequest request) {
        List<Class<ExceptionEventHandler>> handlers = new ArrayList<Class<ExceptionEventHandler>>(LifecycleEventHandlers.getExceptionHandlers());
        for (Class<ExceptionEventHandler> clazz : handlers) {
            try {
                ExceptionEventHandler handler = clazz.newInstance();
                handler.handleException(ex, request);
            } catch (InstantiationException e) {
                log.error("cannot instantiate exception handler", e);
                invokeExceptionHandler(e, request);
            } catch (IllegalAccessException e) {
                log.error("cannot invoke exception handler", e);
                invokeExceptionHandler(ex, request);
            }
        }
    }

    protected HttpResponse handleAuthorize(HttpRequest req) {
        HttpResponse response;
        try {
            String redirectURI = auth.issueAuthorizationCode(req);
            log.debug("redirectURI: {}", redirectURI);

            // return auth_code
            JsonObject obj = new JsonObject();
            obj.addProperty("redirect_uri", redirectURI);
            response = Response.createOkResponse(obj.toString());
            accessTokensLog.info("authCode {}", obj.toString());
        } catch (OAuthException ex) {
            response = Response.createOAuthExceptionResponse(ex);
            invokeExceptionHandler(ex, req);
        }
        return response;
    }

    protected HttpResponse handleRegister(HttpRequest req) {
        HttpResponse response = null;
        try {
            ClientCredentials creds = getClientCredentialsService().issueClientCredentials(req);
            ObjectMapper mapper = new ObjectMapper();
            String jsonString = mapper.writeValueAsString(creds);
            log.debug("credentials:" + jsonString);
            response = Response.createOkResponse(jsonString);
        } catch (OAuthException ex) {
            response = Response.createOAuthExceptionResponse(ex);
            invokeExceptionHandler(ex, req);
        } catch (JsonGenerationException e1) {
            log.error("error handling register", e1);
            invokeExceptionHandler(e1, req);
        } catch (JsonMappingException e1) {
            log.error("error handling register", e1);
            invokeExceptionHandler(e1, req);
        } catch (IOException e1) {
            log.error("error handling register", e1);
            invokeExceptionHandler(e1, req);
        }
        if (response == null) {
            response = Response.createBadRequestResponse(Response.CANNOT_REGISTER_APP);
        }
        return response;
    }

    protected HttpResponse handleTokenRevoke(HttpRequest req) {
        boolean revoked;
        try {
            revoked = auth.revokeToken(req);
        } catch (OAuthException e) {
            log.error("cannot revoke token", e);
            invokeExceptionHandler(e, req);
            return Response.createOAuthExceptionResponse(e);
        }
        String json = "{\"revoked\":\"" + revoked + "\"}";

        return Response.createOkResponse(json);
    }

    protected HttpResponse handleRegisterScope(HttpRequest req) {
        ScopeService scopeService = getScopeService();

        try {
            String responseMsg = scopeService.registerScope(req);
            return Response.createOkResponse(responseMsg);
        } catch (OAuthException e) {
            invokeExceptionHandler(e, req);
            return Response.createResponse(e.getHttpStatus(), e.getMessage());
        }
    }

    protected HttpResponse handleUpdateScope(HttpRequest req) {
        HttpResponse response;
        Matcher m = OAUTH_CLIENT_SCOPE_PATTERN.matcher(req.getUri());
        if (m.find()) {
            String scopeName = m.group(1);
            ScopeService scopeService = getScopeService();
            try {
                String responseMsg = scopeService.updateScope(req, scopeName);
                response = Response.createOkResponse(responseMsg);
            } catch (OAuthException e) {
                invokeExceptionHandler(e, req);
                response = Response.createResponse(e.getHttpStatus(), e.getMessage());
            }
        } else {
            response = Response.createNotFoundResponse();
        }
        return response;
    }

    protected HttpResponse handleGetAllScopes(HttpRequest req) {
        ScopeService scopeService = getScopeService();

        try {
            String jsonString = scopeService.getScopes(req);
            return Response.createOkResponse(jsonString);
        } catch (OAuthException e) {
            invokeExceptionHandler(e, req);
            return Response.createResponse(e.getHttpStatus(), e.getMessage());
        }
    }

    protected HttpResponse handleGetScope(HttpRequest req) {
        HttpResponse response;
        Matcher m = OAUTH_CLIENT_SCOPE_PATTERN.matcher(req.getUri());
        if (m.find()) {
            String scopeName = m.group(1);
            ScopeService scopeService = getScopeService();
            try {
                String responseMsg = scopeService.getScopeByName(scopeName);
                response = Response.createOkResponse(responseMsg);
            } catch (OAuthException e) {
                invokeExceptionHandler(e, req);
                response = Response.createResponse(e.getHttpStatus(), e.getMessage());
            }
        } else {
            response = Response.createNotFoundResponse();
        }
        return response;
    }

    protected HttpResponse handleDeleteScope(HttpRequest req) {
        HttpResponse response;
        Matcher m = OAUTH_CLIENT_SCOPE_PATTERN.matcher(req.getUri());
        if (m.find()) {
            String scopeName = m.group(1);
            ScopeService scopeService = getScopeService();
            try {
                String responseMsg = scopeService.deleteScope(scopeName);
                response = Response.createOkResponse(responseMsg);
            } catch (OAuthException e) {
                invokeExceptionHandler(e, req);
                response = Response.createResponse(e.getHttpStatus(), e.getMessage());
            }
        } else {
            response = Response.createNotFoundResponse();
        }
        return response;
    }

    protected ScopeService getScopeService() {
        return new ScopeService();
    }

    protected ClientCredentialsService getClientCredentialsService() {
        return new ClientCredentialsService();
    }

    protected HttpResponse handleUpdateClientApplication(HttpRequest req) {
        HttpResponse response = null;
        Matcher m = APPLICATION_PATTERN.matcher(req.getUri());
        if (m.find()) {
            String clientId = m.group(1);
            try {
                if (getClientCredentialsService().updateClientCredentials(req, clientId)) {
                    response = Response.createOkResponse(Response.CLIENT_APP_UPDATED);
                }
            } catch (OAuthException ex) {
                response = Response.createOAuthExceptionResponse(ex);
                invokeExceptionHandler(ex, req);
            }
        } else {
            response = Response.createNotFoundResponse();
        }
        return response;
    }

    protected HttpResponse handleGetAllClientApplications(HttpRequest req) {
        List<ClientCredentials> apps = filterClientApps(req, DBManagerFactory.getInstance().getAllApplications());
        Gson gson = new Gson();
        String jsonString = gson.toJson(apps);
        return Response.createOkResponse(jsonString);
    }

    protected List<ClientCredentials> filterClientApps(HttpRequest req, List<ClientCredentials> apps) {
        List<ClientCredentials> filteredApps = new ArrayList<ClientCredentials>();
        QueryStringDecoder dec = new QueryStringDecoder(req.getUri());
        Map<String, List<String>> params = dec.getParameters();
        if (params != null) {
            String status = QueryParameter.getFirstElement(params, "status");
            if (status != null && !status.isEmpty()) {
                try {
                    Integer statusInt = Integer.valueOf(status);
                    for (ClientCredentials app : apps) {
                        if (app.getStatus() == statusInt) {
                            filteredApps.add(app);
                        }
                    }
                } catch (NumberFormatException e) {
                    // status is invalid, ignore it
                    filteredApps = Collections.unmodifiableList(apps);
                }
            } else {
                filteredApps = Collections.unmodifiableList(apps);
            }
        }
        return filteredApps;
    }

    protected HttpResponse handleGetAccessTokens(HttpRequest req) {
        HttpResponse response;
        QueryStringDecoder dec = new QueryStringDecoder(req.getUri());
        Map<String, List<String>> params = dec.getParameters();
        String clientId = QueryParameter.getFirstElement(params, QueryParameter.CLIENT_ID);
        String userId = QueryParameter.getFirstElement(params, QueryParameter.USER_ID);
        if (clientId == null || clientId.isEmpty()) {
            response = Response.createBadRequestResponse(String.format(Response.MANDATORY_PARAM_MISSING, QueryParameter.CLIENT_ID));
        } else if (userId == null || userId.isEmpty()) {
            response = Response.createBadRequestResponse(String.format(Response.MANDATORY_PARAM_MISSING, QueryParameter.USER_ID));
        } else {
            // check that clientId exists, no matter whether it is active or not
            if (!getClientCredentialsService().isExistingClient(clientId)) {
                response = Response.createBadRequestResponse(Response.INACTIVE_CLIENT_CREDENTIALS);
            } else {
                List<AccessToken> accessTokens = DBManagerFactory.getInstance().getAccessTokenByUserIdAndClientApp(userId, clientId);
                Gson gson = new Gson();
                String jsonString = gson.toJson(accessTokens);
                response = Response.createOkResponse(jsonString);
            }
        }
        return response;
    }

    @Override
	public void exceptionCaught(ChannelHandlerContext ctx, ExceptionEvent e) throws Exception {
		log.error("Error report", e.getCause());
		e.getChannel().close();
	}    
}