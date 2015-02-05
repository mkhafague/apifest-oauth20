package com.apifest.oauth20.persistence.hazelcast;

import com.hazelcast.config.Config;
import com.hazelcast.config.GroupConfig;
import com.hazelcast.core.Hazelcast;
import com.hazelcast.core.HazelcastInstance;

/**
 * Creates a member of the apifest hazelcast cluster.
 *
 * @author Edouard De Oliveira
 */
public class HazelcastClusterMember
{
	public static void main( String[] args ) {
        Config config = HazelcastConfigFactory.buildConfig(GroupConfig.DEFAULT_GROUP_PASSWORD);
        HazelcastInstance instance = Hazelcast.newHazelcastInstance(config);
        HazelcastConfigFactory.addIndexes(instance);
	}	
}
