package com.apifest.oauth20;

/**
 * Error reponses when requesting a token.
 *
 * @author Edouard De Oliveira
 */
public enum TokenErrorTypes {
	INVALID_REDIRECT_URI(ErrorTypes.INVALID_REQUEST, "invalid redirect_uri"),
	CANNOT_ISSUE_TOKEN(ErrorTypes.INVALID_REQUEST, "cannot issue token"),
    MANDATORY_PARAM_MISSING(ErrorTypes.INVALID_REQUEST, "mandatory parameter %s is missing"),
    UNSUPPORTED_RESPONSE_TYPE(ErrorTypes.INVALID_REQUEST, "unsupported response type"),

    UNSUPPORTED_GRANT_TYPE(ErrorTypes.UNSUPPORTED_GRANT_TYPE, "unsupported grant type"),

    INVALID_ACCESS_TOKEN(ErrorTypes.INVALID_GRANT, "invalid access token"),
    INVALID_REFRESH_TOKEN(ErrorTypes.INVALID_GRANT, "invalid refresh token"),
    INVALID_AUTH_CODE(ErrorTypes.INVALID_GRANT, "invalid auth code"),
    INVALID_USERNAME_PASSWORD(ErrorTypes.INVALID_GRANT, "invalid username/password"),

    INACTIVE_CLIENT_CREDENTIALS(ErrorTypes.INVALID_CLIENT, "client is inactive"),
    INVALID_CLIENT_CREDENTIALS(ErrorTypes.INVALID_CLIENT, "invalid client_id/client_secret"),

    INVALID_SCOPE(ErrorTypes.INVALID_SCOPE, "invalid scope"),

    UNAUTHORIZED_CLIENT(ErrorTypes.UNAUTHORIZED_CLIENT, "unauthorized client");

    public enum ErrorTypes {
		INVALID_REQUEST, INVALID_CLIENT, INVALID_GRANT, 
		UNAUTHORIZED_CLIENT, UNSUPPORTED_GRANT_TYPE, INVALID_SCOPE
	}

	private ErrorTypes type;
	private String description;

	private TokenErrorTypes(ErrorTypes type, String description) {
		this.type = type;
		this.description = description;
	}

	public ErrorTypes getType() {
		return type;
	}

	public String getDescription() {
		return description;
	}

	public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("\"error\": \"").append(type.toString().toLowerCase()).append('\"');
        if (description != null) {
            sb.append(", \"error_description\": \"").append(description).append('\"');
        }

        return sb.toString();
	}
}
