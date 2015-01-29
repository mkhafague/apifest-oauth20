package com.apifest.oauth20.security;

import org.jboss.netty.handler.codec.http.HttpResponse;

/**
 *
 *
 * @author Edouard De Oliveira
 */
public class RestrictedAccessException extends Exception {
	private static final long serialVersionUID = 5422887688125058499L;
	
	private HttpResponse response;
	
	public RestrictedAccessException(HttpResponse response) {
		super(response.getStatus().getReasonPhrase());
		this.response = response;
	}

	public HttpResponse getResponse() {
		return response;
	}
	
}
