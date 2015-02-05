package com.apifest.oauth20.security;

import java.util.HashMap;
import java.util.Map;

import org.jboss.netty.handler.codec.http.HttpRequest;

import com.apifest.oauth20.api.AuthenticationException;
import com.apifest.oauth20.api.IUserAuthentication;
import com.apifest.oauth20.api.UserDetails;

/**
 * Default implementation of {@link IUserAuthentication} which always successfully authenticates
 * an user.
 *
 * @author Edouard De Oliveira
 */
public class GuestUserAuthentication implements IUserAuthentication {
	private static Map<String, String> details = new HashMap<String, String>();

	static {
		details.put("roles", "GUEST");
	}
	
	@Override
	public UserDetails authenticate(String username, String password, HttpRequest authRequest) throws AuthenticationException {
		return new UserDetails(username, details);
	}
}
