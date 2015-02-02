package com.apifest.oauth20;

/**
 * @author Edouard De Oliveira
 */
public class TokenError {
    private TokenErrorTypes type;
    private String errorUri;
    private String state;
    private String[] messageParams;

    public TokenError(TokenErrorTypes type) {
        this(type, null, null);
    }

    public TokenError(TokenErrorTypes type, String state) {
        this(type, state, null);
    }

    public TokenError(TokenErrorTypes type, String state, String errorUri) {
        this.type = type;
        this.errorUri = errorUri;
        this.state = state;
    }

    public TokenErrorTypes getType() {
        return type;
    }

    public String getErrorUri() {
        return errorUri;
    }

    public void setMessageParams(String... messageParams) {
        this.messageParams = messageParams;
    }

    public String getState() {
        return state;
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append('{');
        if (messageParams == null || messageParams.length == 0) {
            sb.append(type.toString());
        } else {
            sb.append("\"error\": \"").append(type.getType().toString().toLowerCase()).append('\"');
            if (type.getDescription() != null) {
                String desc = String.format(type.getDescription(), messageParams);
                sb.append(", \"error_description\": \"").append(desc).append('\"');
            }
        }
        if (errorUri != null) {
            sb.append(", \"error_uri\": \"").append(errorUri).append('\"');
        }
        if (state != null) {
            sb.append(", \"state\": \"").append(state).append('\"');
        }
        sb.append('}');

        return sb.toString();
    }
}
