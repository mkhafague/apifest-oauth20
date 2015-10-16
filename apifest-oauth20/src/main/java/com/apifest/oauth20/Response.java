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

import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.handler.codec.http.DefaultHttpResponse;
import org.jboss.netty.handler.codec.http.HttpHeaders;
import org.jboss.netty.handler.codec.http.HttpResponse;
import org.jboss.netty.handler.codec.http.HttpResponseStatus;
import org.jboss.netty.handler.codec.http.HttpVersion;
import org.jboss.netty.util.CharsetUtil;

/**
 * Contains all supported responses and response messages.
 *
 * @author Rossitsa Borissova
 */
public final class Response {

    public static final String APPLICATION_JSON = "application/json";

    public static final String NOT_FOUND = "{\"error\":\"not found\"}";
    public static final String UNSUPPORTED_MEDIA_TYPE = "{\"error\": \"unsupported media type\"}";
    public static final String MANDATORY_PARAM_MISSING = "{\"error\": \"mandatory parameter %s is missing\"}";

    public static HttpResponse createBadRequestResponse() {
        return createBadRequestResponse(null);
    }

    public static HttpResponse createBadRequestResponse(String message) {
        return createResponse(HttpResponseStatus.BAD_REQUEST, message);
    }

    public static HttpResponse createNotFoundResponse() {
        return createResponse(HttpResponseStatus.NOT_FOUND, Response.NOT_FOUND);
    }

    public static HttpResponse createOkResponse(String jsonString) {
        return createResponse(HttpResponseStatus.OK, jsonString);
    }

    public static HttpResponse createTokenErrorResponse(TokenError err) {
        return createResponse(HttpResponseStatus.BAD_REQUEST, err.toString());
    }

    public static HttpResponse createOAuthExceptionResponse(OAuthException ex) {
        return createResponse(ex.getHttpStatus(), ex.getMessage());
    }

    public static HttpResponse createUnauthorizedResponse() {
        return createResponse(HttpResponseStatus.UNAUTHORIZED, new TokenError(TokenErrorTypes.UNAUTHORIZED_CLIENT).toString());
    }

    public static HttpResponse createResponse(HttpResponseStatus status, String message) {
        HttpResponse response = new DefaultHttpResponse(HttpVersion.HTTP_1_1, status);
        if (message != null) {
            ChannelBuffer buf = ChannelBuffers.copiedBuffer(message.getBytes(CharsetUtil.UTF_8));
            response.setContent(buf);
            response.headers().set(HttpHeaders.Names.CONTENT_LENGTH, buf.array().length);
        } else {
            response.headers().set(HttpHeaders.Names.CONTENT_LENGTH, 0);
        }
        response.headers().set(HttpHeaders.Names.CONTENT_TYPE, APPLICATION_JSON);
        response.headers().set(HttpHeaders.Names.CACHE_CONTROL, HttpHeaders.Values.NO_STORE);
        response.headers().set(HttpHeaders.Names.PRAGMA, HttpHeaders.Values.NO_CACHE);
        return response;
    }
}

