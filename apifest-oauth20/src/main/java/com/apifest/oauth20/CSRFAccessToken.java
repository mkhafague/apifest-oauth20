package com.apifest.oauth20;

import org.codehaus.jackson.annotate.JsonProperty;
import org.codehaus.jackson.annotate.JsonUnwrapped;
import org.codehaus.jackson.map.annotate.JsonSerialize;
import org.codehaus.jackson.map.annotate.JsonSerialize.Inclusion;

/**
 * Access token decorated with the CSRF state attribute.
 *
 * @author Edouard De Oliveira
 */
@JsonSerialize(include=Inclusion.NON_EMPTY)
public class CSRFAccessToken
{
	@JsonUnwrapped
    @JsonProperty("token")
	private AccessToken token;
	
    @JsonProperty("state")
    private String state;
    
    public CSRFAccessToken(AccessToken token, String state) {
    	this.token = token;
    	this.state = state; 
    }

	protected AccessToken getToken() {
		return token;
	}

	protected String getState() {
		return state;
	}
}
