package com.apifest.oauth20.security;

import java.util.HashMap;
import java.util.Map;

import org.jboss.netty.handler.codec.http.HttpRequest;

import com.apifest.oauth20.api.AuthenticationException;
import com.apifest.oauth20.api.IUserAuthentication;
import com.apifest.oauth20.api.UserDetails;

public class GuestUserAuthentication implements IUserAuthentication {
	private static Map<String, String> details = new HashMap<String, String>();
	public static UserDetails guest = new UserDetails("guest", details);

	static {
		details.put("firstname", "Edouard");
		details.put("lastname", "DE OLIVEIRA");
		details.put("roles", "USER, READER");
	}
	
	@Override
	public UserDetails authenticate(String username, String password, HttpRequest authRequest) throws AuthenticationException {
		return guest;
	}
}
