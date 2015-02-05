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

package com.apifest.oauth20.persistence.hazelcast;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.hazelcast.client.config.ClientConfig;
import com.hazelcast.client.config.ClientNetworkConfig;
import com.hazelcast.config.Config;
import com.hazelcast.config.ExecutorConfig;
import com.hazelcast.config.GroupConfig;
import com.hazelcast.config.InMemoryFormat;
import com.hazelcast.config.InterfacesConfig;
import com.hazelcast.config.JoinConfig;
import com.hazelcast.config.MapConfig;
import com.hazelcast.config.MaxSizeConfig;
import com.hazelcast.config.NetworkConfig;
import com.hazelcast.config.TcpIpConfig;
import com.hazelcast.config.MapConfig.EvictionPolicy;
import com.hazelcast.config.MaxSizeConfig.MaxSizePolicy;
import com.hazelcast.core.HazelcastInstance;

/**
 * Creates all the configuration to start a {@link com.hazelcast.core.HazelcastInstance}.
 *
 * @author Edouard De Oliveira
 */
public class HazelcastConfigFactory {

	public static final String HAZELCAST_GROUP_NAME = "apifest-oauth20";
	
    private static Logger log = LoggerFactory.getLogger(HazelcastConfigFactory.class);
    private static final int MAX_POOL_SIZE = 64;
    
    protected static final String APIFEST_SCOPE_MAP = "APIFEST_SCOPE";
    protected static final String APIFEST_CLIENT_MAP = "APIFEST_CLIENT";
    protected static final String APIFEST_AUTH_CODE_MAP = "APIFEST_AUTH_CODE";
    protected static final String APIFEST_ACCESS_TOKEN_MAP = "APIFEST_ACCESS_TOKEN";

    private HazelcastConfigFactory() {
    }

    public static Config buildConfig(String groupPassword) {
    	return buildConfig(HAZELCAST_GROUP_NAME, groupPassword, null, null);
    }
    
    public static Config buildConfig(String groupName, String groupPassword, String hostname, String clusterMembers) {    	
    	Config config = createConfiguration(hostname, clusterMembers);
        
        GroupConfig groupConfig = new GroupConfig(groupName, groupPassword);
        config.setGroupConfig(groupConfig);
        config.setMapConfigs(createMapConfigs());
    	
        return config;
    }
    
    public static ClientConfig buildClientConfig(String groupName, String groupPassword, String clusterMembers) {
    	ClientConfig config = createClientConfiguration(clusterMembers);
        
        GroupConfig groupConfig = new GroupConfig(groupName, groupPassword);
        config.setGroupConfig(groupConfig);
        return config;
    }

	public static void addIndexes(HazelcastInstance instance) {
    	instance.getMap(APIFEST_CLIENT_MAP).addIndex("name", false);
    	instance.getMap(APIFEST_AUTH_CODE_MAP).addIndex("codeURI", false);
    	instance.getMap(APIFEST_ACCESS_TOKEN_MAP).addIndex("refreshTokenByClient", false);
    	instance.getMap(APIFEST_ACCESS_TOKEN_MAP).addIndex("accessTokenByUserIdAndClient", false);
    }

    private static ClientConfig createClientConfiguration(String clusterMembers) {
        ClientConfig config = new ClientConfig();
        config.setNetworkConfig(createClientNetworkConfig(clusterMembers));
        config.setExecutorPoolSize(MAX_POOL_SIZE);

        return config;
    }
    
    private static Config createConfiguration(String hostname, String clusterMembers) {
        Config config = new Config();
        NetworkConfig networkCfg = createNetworkConfig(hostname, clusterMembers);
        config.setNetworkConfig(networkCfg);

        ExecutorConfig executorConfig = new ExecutorConfig();
        executorConfig.setPoolSize(MAX_POOL_SIZE);
        executorConfig.setStatisticsEnabled(false);
        config.addExecutorConfig(executorConfig);

        return config;
    }
    
    private static Map<String, MapConfig> createMapConfigs() {
        Map<String, MapConfig> configs = new HashMap<String, MapConfig>();
        MapConfig accTokenConfig = createMapConfig(APIFEST_ACCESS_TOKEN_MAP);
        MapConfig scopeConfig = createMapConfig(APIFEST_SCOPE_MAP);
        MapConfig clientConfig = createMapConfig(APIFEST_CLIENT_MAP);
        MapConfig authCodeConfig = createMapConfig(APIFEST_AUTH_CODE_MAP);
        configs.put(accTokenConfig.getName(), accTokenConfig);
        configs.put(scopeConfig.getName(), scopeConfig);
        configs.put(clientConfig.getName(), clientConfig);
        configs.put(authCodeConfig.getName(), authCodeConfig);
        return configs;
    }

    private static MapConfig createMapConfig(String mapName) {
        MapConfig mapConfig = new MapConfig(mapName);
        mapConfig.setInMemoryFormat(InMemoryFormat.OBJECT);
        mapConfig.setBackupCount(1);
        mapConfig.setEvictionPolicy(EvictionPolicy.NONE);
        mapConfig.setMaxSizeConfig(new MaxSizeConfig(0, MaxSizePolicy.PER_NODE));
        mapConfig.setEvictionPercentage(0);
        mapConfig.setMergePolicy("com.hazelcast.map.merge.PutIfAbsentMapMergePolicy");
        return mapConfig;
    }

    private static NetworkConfig createNetworkConfig(String hostname, String clusterMembers) {
        NetworkConfig networkConfig = new NetworkConfig();
        InterfacesConfig interfaceConfig = new InterfacesConfig();
        
        // add host
        try {
        	if (hostname == null) {
        		hostname = InetAddress.getLocalHost().getCanonicalHostName();
        	}

            interfaceConfig.addInterface(InetAddress.getByName(hostname).getHostAddress());
        } catch (UnknownHostException e) {
            log.error("cannot create hazelcast config", e);
        }
        interfaceConfig.setEnabled(true);

        networkConfig.setInterfaces(interfaceConfig);
        JoinConfig joinConfig = new JoinConfig();

        List<String> members = createMembersList(clusterMembers);
        if (members != null) {
        	TcpIpConfig tcpIps = new TcpIpConfig();
            tcpIps.setMembers(members);
            tcpIps.setEnabled(true);
            joinConfig.setTcpIpConfig(tcpIps);
            joinConfig.getMulticastConfig().setEnabled(false);
        } else {
        	joinConfig.getMulticastConfig().setEnabled(true);
        }
        
        networkConfig.setJoin(joinConfig);

        return networkConfig;
    }

    private static ClientNetworkConfig createClientNetworkConfig(String clusterMembers) {
        ClientNetworkConfig networkConfig = new ClientNetworkConfig();
        List<String> members = createMembersList(clusterMembers);
        if (members != null) {
            networkConfig.setAddresses(members);
        }

        return networkConfig;
    }
    
    private static List<String> createMembersList(String list) {
        if (list != null && list.length() > 0) {
            String [] n = list.split(",");
            return Arrays.asList(n);
        }
        return null;
    }
}
