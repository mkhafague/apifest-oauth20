package com.apifest.oauth20;

import com.apifest.oauth20.api.AuthenticationException;
import com.apifest.oauth20.api.GrantType;
import com.apifest.oauth20.api.ICustomGrantTypeHandler;
import com.apifest.oauth20.api.UserDetails;
import org.jboss.netty.handler.codec.http.HttpRequest;

/**
 * Implements the "foo" custom grant type.
 *
 * @author Edouard De Oliveira
 */
@GrantType(name="foo")
public class FooGrantType implements ICustomGrantTypeHandler {

    @Override
    public UserDetails execute(HttpRequest request) throws AuthenticationException {
        return new UserDetails("dummy", null);
    }
}
