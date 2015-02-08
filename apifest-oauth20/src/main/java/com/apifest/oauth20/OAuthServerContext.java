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

import com.apifest.oauth20.api.ICustomGrantTypeHandler;
import com.apifest.oauth20.api.IUserAuthentication;
import com.apifest.oauth20.security.SubnetRange;

import java.util.Map;

/**
 * Holds the {@link com.apifest.oauth20.OAuthServer} context data
 *
 * @author Edouard De Oliveira
 */
public final class OAuthServerContext {

    private Class<IUserAuthentication> userAuthenticationClass;
    private String customGrantType;
    private Class<ICustomGrantTypeHandler> customGrantTypeHandler;

    private String host;
    private int portInt;

    private String databaseType;
    private String mongoDBUri;
    private String redisSentinels;
    private String redisMaster;
    private String hazelcastClusterName;
    private String hazelcastClusterMembers;
    private String hazelcastPassword;

    private boolean https;
    private boolean productionMode;
    private SubnetRange allowedIPs;
    private Map<String, String> serverCredentials;

    private OAuthServerContext(String host, int portInt, String databaseType, String mongoDBUri, String redisSentinels, String redisMaster,
                              String hazelcastClusterName, String hazelcastClusterMembers, String hazelcastPassword,
                              boolean https, boolean productionMode, SubnetRange allowedIPs, Map<String, String> serverCredentials,
                              String customGrantType, Class<ICustomGrantTypeHandler> customGrantTypeHandler, Class<IUserAuthentication> userAuthenticationClass) {
        this.customGrantType = customGrantType;
        this.customGrantTypeHandler = customGrantTypeHandler;
        this.host = host;
        this.portInt = portInt;
        this.databaseType = databaseType;
        this.mongoDBUri = mongoDBUri;
        this.redisSentinels = redisSentinels;
        this.redisMaster = redisMaster;
        this.hazelcastClusterName = hazelcastClusterName;
        this.hazelcastClusterMembers = hazelcastClusterMembers;
        this.hazelcastPassword = hazelcastPassword;
        this.https = https;
        this.productionMode = productionMode;
        this.allowedIPs = allowedIPs;
        this.serverCredentials = serverCredentials;
        this.userAuthenticationClass = userAuthenticationClass;
    }

    public Class<IUserAuthentication> getUserAuthenticationClass() {
        return userAuthenticationClass;
    }

    public Class<ICustomGrantTypeHandler> getCustomGrantTypeHandler() {
        return customGrantTypeHandler;
    }

    public String getCustomGrantType() {
        return customGrantType;
    }

    public String getHost() {
        return host;
    }

    public int getPortInt() {
        return portInt;
    }

    public String getDatabaseType() {
        return databaseType;
    }

    public String getMongoDBUri() {
        return mongoDBUri;
    }

    public String getRedisSentinels() {
        return redisSentinels;
    }

    public String getRedisMaster() {
        return redisMaster;
    }

    public String getHazelcastClusterName() {
        return hazelcastClusterName;
    }

    public String getHazelcastClusterMembers() {
        return hazelcastClusterMembers;
    }

    public String getHazelcastPassword() {
        return hazelcastPassword;
    }

    public boolean isHttps() {
        return https;
    }

    public boolean isProductionMode() {
        return productionMode;
    }

    public SubnetRange getAllowedIPs() {
        return allowedIPs;
    }

    public Map<String, String> getServerCredentials() {
        return serverCredentials;
    }

    public boolean useEmbeddedHazelcast() {
        return hazelcastClusterName != null && !(hazelcastClusterName.isEmpty());
    }

    public static final class OAuthServerContextBuilder {
        private Class<IUserAuthentication> userAuthenticationClass;
        private String customGrantType;
        private Class<ICustomGrantTypeHandler> customGrantTypeHandler;

        private String host;
        private int portInt;

        private String databaseType;
        private String mongoDBUri;
        private String redisSentinels;
        private String redisMaster;
        private String hazelcastClusterName;
        private String hazelcastClusterMembers;
        private String hazelcastPassword;

        private boolean https;
        private boolean productionMode;
        private SubnetRange allowedIPs;
        private Map<String, String> serverCredentials;

        public OAuthServerContextBuilder() {
        }

        public OAuthServerContextBuilder setUserAuthenticationClass(Class<IUserAuthentication> userAuthenticationClass) {
            this.userAuthenticationClass = userAuthenticationClass;
            return this;
        }

        public OAuthServerContextBuilder setCustomGrantType(String customGrantType) {
            this.customGrantType = customGrantType;
            return this;
        }

        public OAuthServerContextBuilder setCustomGrantTypeHandler(Class<ICustomGrantTypeHandler> customGrantTypeHandler) {
            this.customGrantTypeHandler = customGrantTypeHandler;
            return this;
        }

        public OAuthServerContextBuilder setHost(String host) {
            this.host = host;
            return this;
        }

        public OAuthServerContextBuilder setPortInt(int portInt) {
            this.portInt = portInt;
            return this;
        }

        public OAuthServerContextBuilder setDatabaseType(String databaseType) {
            this.databaseType = databaseType;
            return this;
        }

        public OAuthServerContextBuilder setMongoDBUri(String mongoDBUri) {
            this.mongoDBUri = mongoDBUri;
            return this;
        }

        public OAuthServerContextBuilder setRedisSentinels(String redisSentinels) {
            this.redisSentinels = redisSentinels;
            return this;
        }

        public OAuthServerContextBuilder setRedisMaster(String redisMaster) {
            this.redisMaster = redisMaster;
            return this;
        }

        public OAuthServerContextBuilder setHazelcastClusterName(String hazelcastClusterName) {
            this.hazelcastClusterName = hazelcastClusterName;
            return this;
        }

        public OAuthServerContextBuilder setHazelcastClusterMembers(String hazelcastClusterMembers) {
            this.hazelcastClusterMembers = hazelcastClusterMembers;
            return this;
        }

        public OAuthServerContextBuilder setHazelcastPassword(String hazelcastPassword) {
            this.hazelcastPassword = hazelcastPassword;
            return this;
        }

        public OAuthServerContextBuilder setHttps(boolean https) {
            this.https = https;
            return this;
        }

        public OAuthServerContextBuilder setProductionMode(boolean productionMode) {
            this.productionMode = productionMode;
            return this;
        }

        public OAuthServerContextBuilder setAllowedIPs(SubnetRange allowedIPs) {
            this.allowedIPs = allowedIPs;
            return this;
        }

        public OAuthServerContextBuilder setServerCredentials(Map<String, String> serverCredentials) {
            this.serverCredentials = serverCredentials;
            return this;
        }

        public String getHost() {
            return host;
        }

        public int getPortInt() {
            return portInt;
        }

        public boolean isProductionMode() {
            return productionMode;
        }

        public boolean isHttps() {
            return https;
        }

        public OAuthServerContext build() {
            return new OAuthServerContext(host, portInt, databaseType, mongoDBUri, redisSentinels, redisMaster,
                                            hazelcastClusterName, hazelcastClusterMembers, hazelcastPassword,
                                            https, productionMode, allowedIPs, serverCredentials,
                                            customGrantType, customGrantTypeHandler, userAuthenticationClass);
        }
    }
}
