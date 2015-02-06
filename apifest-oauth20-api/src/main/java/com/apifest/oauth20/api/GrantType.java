package com.apifest.oauth20.api;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
* Annotation that provides the name of the grant type at runtime
*
* @author Edouard De Oliveira
*/
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
public @interface GrantType { 
	String name();
}
