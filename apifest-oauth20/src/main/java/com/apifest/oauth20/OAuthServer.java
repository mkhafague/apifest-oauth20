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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.security.KeyStore;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.Executors;
import java.util.concurrent.locks.ReentrantLock;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;

import org.jboss.netty.bootstrap.ServerBootstrap;
import org.jboss.netty.channel.ChannelFactory;
import org.jboss.netty.channel.ChannelPipeline;
import org.jboss.netty.channel.ChannelPipelineFactory;
import org.jboss.netty.channel.Channels;
import org.jboss.netty.channel.socket.nio.NioServerSocketChannelFactory;
import org.jboss.netty.handler.codec.http.HttpChunkAggregator;
import org.jboss.netty.handler.codec.http.HttpRequestDecoder;
import org.jboss.netty.handler.codec.http.HttpResponseEncoder;
import org.jboss.netty.handler.ssl.SslContext;
import org.jboss.netty.handler.ssl.SslHandler;
import org.jboss.netty.handler.ssl.util.SelfSignedCertificate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.apifest.oauth20.api.GrantType;
import com.apifest.oauth20.api.ICustomGrantTypeHandler;
import com.apifest.oauth20.api.IUserAuthentication;
import com.apifest.oauth20.persistence.DBManager;
import com.apifest.oauth20.persistence.hazelcast.HazelcastConfigFactory;
import com.apifest.oauth20.security.GuestUserAuthentication;
import com.apifest.oauth20.security.SslRequiredHandler;
import com.apifest.oauth20.security.SubnetRange;
import com.hazelcast.config.GroupConfig;

/**
 * Class responsible for ApiFest OAuth 2.0 Server.
 *
 * @author Rossitsa Borissova
 */
public final class OAuthServer {

    protected static Logger log = LoggerFactory.getLogger(OAuthServer.class);

    // expires_in in seconds for grant type password
    public static final int DEFAULT_PASSWORD_EXPIRES_IN = 900;

    // expires_in in seconds for grant type client_credentials
    public static final int DEFAULT_CC_EXPIRES_IN = 1800;

    public static final String OAUTH2_SERVER_CLIENT_NAME = "Oauth2Server";

    private static final ReentrantLock lock = new ReentrantLock();

    // Context
    private static String customJar;
    private static String userAuthClass;
    private static Class<IUserAuthentication> userAuthenticationClass;
    private static String customGrantType;
    private static String customGrantTypeClass;
    private static Class<ICustomGrantTypeHandler> customGrantTypeHandler;
    private static URLClassLoader jarClassLoader;

    private static String host;
    private static int portInt;

    private static String databaseType;
    private static String mongoDBUri;
    private static String redisSentinels;
    private static String redisMaster;
    private static String hazelcastClusterName;
    private static String hazelcastClusterMembers;
    private static String hazelcastPassword;

    private static boolean https;
    private static SslContext sslCtx;
    private static SSLContext jdkSslContext;
    private static SelfSignedCertificate ssc;

    private static boolean productionMode;
    private static SubnetRange allowedIPs;
    private static Map<String, String> serverCredentials;

    public static void main(String[] args) throws Exception {
        if (!loadConfig()) {
            System.exit(1);
        }
        startServer();
    }

    private static void startServer() {
        log.info("ApiFest OAuth 2.0 Server starting ...");
        log.info("Initializing "+ getDatabaseType()+" database ...");
        DBManagerFactory.init();

		serverCredentials = setAuthServerContext(host, portInt);
        ChannelFactory factory = new NioServerSocketChannelFactory(Executors.newCachedThreadPool(),
                Executors.newCachedThreadPool());

        if (https) {
        	log.info("Setting up secured https only mode ...");
        } else {
        	log.info("Setting up default unsecured http mode ...");
        }

        ServerBootstrap bootstrap = new ServerBootstrap(factory);
        bootstrap.setPipelineFactory(new ChannelPipelineFactory() {

            @Override
            public ChannelPipeline getPipeline() {
                ChannelPipeline pipeline = Channels.pipeline();
                
                if (https) {
                    // Add SSL handler first to encrypt and decrypt everything.
                    if (sslCtx != null) {
                        pipeline.addLast("sslRequiredHandler", new SslRequiredHandler(sslCtx.newHandler()));
                    } else {
                        SSLEngine engine = jdkSslContext.createSSLEngine();
                        engine.setUseClientMode(false);
                        pipeline.addLast("sslRequiredHandler", new SslRequiredHandler(new SslHandler(engine)));
                    }
                }
                pipeline.addLast("decoder", new HttpRequestDecoder());
                pipeline.addLast("aggregator", new HttpChunkAggregator(4096));
                pipeline.addLast("encoder", new HttpResponseEncoder());
                
                HttpRequestHandler handler = new HttpRequestHandler();
                handler.setInitialContext(serverCredentials, allowedIPs, productionMode);
                pipeline.addLast("handler", handler);
                return pipeline;
            }
        });

        bootstrap.setOption("child.tcpNoDelay", true);
        bootstrap.setOption("child.keepAlive", true);
        bootstrap.setOption("child.soLinger", -1);

        bootstrap.bind(new InetSocketAddress(host, portInt));
        log.info("ApiFest OAuth 2.0 Server started at " + host + ":" + portInt);
    }

    protected static boolean loadConfig() {
        String propertiesFilePath = System.getProperty("properties.file");
        InputStream in = null;
        try {
            if (propertiesFilePath == null) {
                in = Thread.currentThread().getContextClassLoader().getResourceAsStream("apifest-oauth.properties");
                if (in != null) {
                    setupProperties(in);
                } else {
                    log.error("Cannot load properties file");
                    return false;
                }
            } else {
                File file = new File(propertiesFilePath);
                try {
                    in = new FileInputStream(file);
                    setupProperties(in);
                } catch (FileNotFoundException e) {
                    log.error("Cannot find properties file {}", propertiesFilePath);
                    return false;
                }
            }
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException e) {
                    log.error("cannot close input stream", e);
                }
            }
        }
        
        loadCustomClasses();
        return true;
    }

    protected static void loadCustomClasses() {
        if (customJar == null || customJar.isEmpty()) {
            log.warn("Set value for custom.classes.jar in properties file to load custom classes from this jar\n" +
                        "Otherwise user authentication will always pass successfully if using default implementations");
        }
        if (userAuthClass != null && userAuthClass.length() > 0) {
            try {
                userAuthenticationClass = loadCustomUserAuthentication(userAuthClass);
            } catch (ClassNotFoundException e) {
                log.error("cannot load user.authenticate.class, check property value", e);
            }
        }
        if (customGrantTypeClass != null && !customGrantTypeClass.isEmpty()) {
            try {
                customGrantTypeHandler = loadCustomGrantType(customGrantTypeClass);
            } catch (ClassNotFoundException e) {
                log.error("cannot load custom.grant_type.class, check property value", e);
            }
        }

        try {
            LifecycleEventHandlers.loadLifecycleHandlers(getJarClassLoader(), customJar);
        } catch (MalformedURLException e) {
            log.warn("cannot load custom jar");
        }
    }

    @SuppressWarnings("unchecked")
    public static Class<IUserAuthentication> loadCustomUserAuthentication(String className) throws ClassNotFoundException {
        Class<?> clazz = loadClass(className);
        if (IUserAuthentication.class.isAssignableFrom(clazz)) {
            return (Class<IUserAuthentication>) clazz;
        } else {
            log.error("user.authentication.class {} does not implement IUserAuthentication interface, default authentication will be used", clazz);
        }
        
        return null;
    }

    @SuppressWarnings("unchecked")
    public static Class<ICustomGrantTypeHandler> loadCustomGrantType(String className) throws ClassNotFoundException {
		Class<?> clazz = loadClass(className);
		if (clazz == null) {
			log.error("Unable to load class {} ", className);
		} else {
			GrantType gtAnnotation = clazz.getAnnotation(GrantType.class);
			
			if (gtAnnotation == null || gtAnnotation.name() == null || gtAnnotation.name().isEmpty()) {
				log.error("Custom {} does not have the GrantType annotation declared", clazz.getCanonicalName());
			} else if (!ICustomGrantTypeHandler.class.isAssignableFrom(clazz)) {
				log.error("Custom {} does not implement ICustomGrantTypeHandler interface", clazz);
			} else {
				customGrantType = gtAnnotation.name();
				return (Class<ICustomGrantTypeHandler>) clazz;
	        }
		}

        return null;
    }

	private static Class<?> loadClass(String className) throws ClassNotFoundException {
		try {
			URLClassLoader classLoader = getJarClassLoader();
			if (classLoader != null) {
				return classLoader.loadClass(className);
			} else {
                return OAuthServer.class.getClassLoader().loadClass(className);
			}
		} catch (MalformedURLException e) {
			log.error("cannot load custom jar");
		}		
		
		return null;
	}
	
    private static URLClassLoader getJarClassLoader() throws MalformedURLException {
        if (jarClassLoader == null) {
            if (customJar != null) {
                File file = new File(customJar);
                if (file.exists()) {
                    URL jarfile = file.toURI().toURL();
                    jarClassLoader = URLClassLoader.newInstance(new URL[] { jarfile },
                            OAuthServer.class.getClassLoader());
                } else {
                    throw new MalformedURLException(
                            "check property custom.classes.jar, jar does not exist");
                }
            }
        }
        return jarClassLoader;
    }

    @SuppressWarnings("unchecked")
    protected static void setupProperties(InputStream in) {
        Properties props = new Properties();
        try {
            props.load(in);
            setHostAndPort((String) props.get("oauth20.host"), (String) props.get("oauth20.port"));

            customJar = props.getProperty("custom.classes.jar");
            userAuthClass = props.getProperty("user.authenticate.class");
            if (userAuthClass == null || userAuthClass.length() == 0) {
                userAuthClass = GuestUserAuthentication.class.getCanonicalName();
            }
            customGrantTypeClass = props.getProperty("custom.grant_type.class");

            databaseType = props.getProperty("oauth20.database");
            redisSentinels = props.getProperty("redis.sentinels");
            redisMaster = props.getProperty("redis.master");
            mongoDBUri = props.getProperty("mongodb.uri");
            if (mongoDBUri == null || mongoDBUri.length() == 0) {
                mongoDBUri = "localhost";
            }

            hazelcastClusterName = props.getProperty("hazelcast.cluster.name", HazelcastConfigFactory.HAZELCAST_GROUP_NAME);

            // dev-pass is the default password used in Hazelcast
            hazelcastPassword = props.getProperty("hazelcast.password", GroupConfig.DEFAULT_GROUP_PASSWORD);
            hazelcastClusterMembers = props.getProperty("hazelcast.cluster.members");
            
            https = Boolean.parseBoolean((String) props.get("oauth20.https"));
            if (https) {
                configureSSL((String) props.get("oauth20.keystore.path"),
                        (String) props.get("oauth20.keystore.password"),
                        (String) props.get("oauth20.keystore.algorithm"));
            }

            String mode = (String) props.get("oauth20.production.mode");
            productionMode = Boolean.parseBoolean(mode);
            String subnetsString = (String) props.get("oauth20.subnets.whitelist");
            if (subnetsString != null) {
                allowedIPs = SubnetRange.parse(subnetsString);
            }
        } catch (Exception e) {            
			log.error("Cannot load properties file", e);
        }
    }

    protected static Map<String, String> setAuthServerContext(String host, int portInt) {
    	if (productionMode) {
	    	DBManager db = DBManagerFactory.getInstance();
	    	
	    	// check/create admin scope
	        Scope adminScope = new Scope();
	        adminScope.setScope("admin");
	        adminScope.setDescription("Administration scope");
	        adminScope.setPassExpiresIn(OAuthServer.DEFAULT_PASSWORD_EXPIRES_IN);
	        adminScope.setCcExpiresIn(OAuthServer.DEFAULT_CC_EXPIRES_IN);
	        
	        Scope foundScope = db.findScope("admin");
	        
	        if (foundScope == null) {
	        	db.storeScope(adminScope);
	        }
	        
	        // check/create oauth20 application issueClientCredentials
	        ApplicationInfo appInfo = new ApplicationInfo();
	        appInfo.setName(OAUTH2_SERVER_CLIENT_NAME);
	        appInfo.setScope(adminScope.getScope());
	        appInfo.setDescription("Oauth2 server admin");

            StringBuilder uri = new StringBuilder("http");
            if (https) {
                uri.append('s');
            }
            uri.append("://").append(host).append(':').append(portInt);
            uri.append("/oauth20");
            appInfo.setRedirectUri(uri.toString());
	        appInfo.valid();
	        
	        ClientCredentials cc = db.findClientCredentials(appInfo.getId());
	        
	        if (cc == null) {
	            cc = new ClientCredentials(appInfo.getName(), appInfo.getScope(), appInfo.getDescription(),
	                    appInfo.getRedirectUri(), appInfo.getApplicationDetails());
	
	        	ClientCredentials foundCc = db.findClientCredentialsByName(OAUTH2_SERVER_CLIENT_NAME);
	        	if (foundCc == null) {
	        		db.storeClientCredentials(cc);
	        	}
	        }
	        
	        Map<String, String> map = new HashMap<String, String>();
	        map.put(TokenRequest.GRANT_TYPE, TokenRequest.PASSWORD);
	        map.put(TokenRequest.SCOPE, cc.getScope());
	        map.put(TokenRequest.CLIENT_ID, cc.getId());
	        map.put(TokenRequest.CLIENT_SECRET, cc.getSecret());
	        
	        return map;
    	}
    	
    	// Should return some default info ?
    	return null;
    }

    private static void buildSelfSignedCertificate() {
        lock.lock();
        try {
            if (ssc == null) {
                try {
                    String fqdn = InetAddress.getLocalHost().getCanonicalHostName();
                    log.info("Building self signed certificate for host [" + fqdn + "] ...");
                    ssc = new SelfSignedCertificate(fqdn);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        } finally {
            lock.unlock();
        }
    }

    protected static void configureSSL(String keystorePath, String password, String algorithm) throws IOException {
    	if (keystorePath != null) {
    		try {
	    		String alg = algorithm == null ? "JKS" : algorithm;
	    		char[] pwd = password == null ? null : password.toCharArray();
	    		final KeyStore ks = KeyStore.getInstance(alg);
	    		
	    		ks.load(new FileInputStream(keystorePath), pwd); 
	    		final KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());    		 
	    		kmf.init(ks, pwd);
	    		
	    		jdkSslContext = SSLContext.getInstance("TLS");
	    		jdkSslContext.init(kmf.getKeyManagers(), null, null);
    		} catch (Exception e) {
				throw new IOException("Unable to load certificate", e);
			}
    	} else {
            try {
                buildSelfSignedCertificate();
                sslCtx = SslContext.newServerContext(ssc.certificate(), ssc.privateKey());
            } catch (Exception e) {
            	throw new IOException("Unable to create self signed certificate", e);
			}
    	}
    }
    
    protected static void setHostAndPort(String configHost, String configPort) {
        host = configHost;
        // if not set in properties file, loaded from env var
        if (host == null || host.length() == 0) {
            host = System.getProperty("oauth20.host");
            if (host == null || host.length() == 0) {
                log.error("oauth20.host property not set");
                System.exit(1);
            }
        }
        String portStr = configPort;
        // if not set in properties file, loaded from env var
        if (portStr == null || portStr.length() == 0) {
            portStr = System.getProperty("oauth20.port");
            if (portStr == null || portStr.length() == 0) {
                log.error("oauth20.port property not set");
                System.exit(1);
            }
        }
        try {
            portInt = Integer.parseInt(portStr);
        } catch (NumberFormatException e) {
            log.error("oauth20.port must be an integer");
            System.exit(1);
        }
    }

    public static String getHost() {
        return host;
    }

    public static String getMongoDBUri() {
        return mongoDBUri;
    }

    public static String getDatabaseType() {
        return databaseType;
    }

    public static String getRedisSentinels() {
        return redisSentinels;
    }

    public static String getRedisMaster() {
        return redisMaster;
    }

    public static boolean useEmbeddedHazelcast() {
        String name = getHazelcastClusterName();
        return name != null && !(name.isEmpty());
    }

    public static String getHazelcastClusterName() {
        return hazelcastClusterName;
    }

    public static String getHazelcastClusterMembers() {
        return hazelcastClusterMembers;
    }

    public static Class<IUserAuthentication> getUserAuthenticationClass() {
        return userAuthenticationClass;
    }

    public static String getCustomGrantType() {
        return customGrantType;
    }

    public static Class<ICustomGrantTypeHandler> getCustomGrantTypeHandler() {
        return customGrantTypeHandler;
    }

    public static String getHazelcastPassword() {
        return hazelcastPassword;
    }
}
