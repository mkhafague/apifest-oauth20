package com.apifest.oauth20.persistence.hazelcast;

import static org.testng.Assert.assertEquals;

import com.hazelcast.config.GroupConfig;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.hazelcast.client.HazelcastClient;
import com.hazelcast.client.config.ClientConfig;
import com.hazelcast.config.Config;
import com.hazelcast.core.Hazelcast;
import com.hazelcast.core.HazelcastInstance;
import com.hazelcast.core.IMap;

import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * Creates a client to the apifest hazelcast cluster.
 *
 * @author Edouard De Oliveira
 */
public class HazelcastClusterClient {

    private static final String NAME = "test-group";
    private static final String PWD = "test-pwd";

    HazelcastInstance instance1, instance2;

    @BeforeMethod
    public void setup() throws UnknownHostException {
        String hostname = InetAddress.getLocalHost().getCanonicalHostName();
        Config config = HazelcastConfigFactory.buildConfig(NAME, PWD, hostname, hostname);

        // speed up tests
        config.getSecurityConfig().setEnabled(false);
        instance1 = Hazelcast.newHazelcastInstance(config);

        config.getNetworkConfig().setPort(config.getNetworkConfig().getPort()+1);
        instance2 = Hazelcast.newHazelcastInstance(config);
    }

    @AfterMethod
    public void teardown() {
        instance1.shutdown();
        instance2.shutdown();
    }

    @Test
    public void when_connect_get_empty_map() {
        // GIVEN
        ClientConfig clientConfig = HazelcastConfigFactory.buildClientConfig(NAME, PWD, null);
        HazelcastInstance client = HazelcastClient.newHazelcastClient(clientConfig);

        // WHEN
        IMap<Object, Object> map = client.getMap(HazelcastConfigFactory.APIFEST_CLIENT_MAP);

        // THEN
        assertEquals(map.size(), 0);
        client.shutdown();
    }

    public static void main(String[] args) {
        ClientConfig clientConfig = HazelcastConfigFactory.buildClientConfig(
                HazelcastConfigFactory.HAZELCAST_GROUP_NAME, GroupConfig.DEFAULT_GROUP_PASSWORD, null);
        HazelcastInstance client = HazelcastClient.newHazelcastClient(clientConfig);
        IMap<Object, Object> map = client.getMap(HazelcastConfigFactory.APIFEST_CLIENT_MAP);

        System.out.println("Map Size:" + map.size());
        client.shutdown();
        System.exit(0);
    }
}
