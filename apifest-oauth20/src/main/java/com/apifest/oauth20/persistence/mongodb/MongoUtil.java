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

package com.apifest.oauth20.persistence.mongodb;

import java.net.UnknownHostException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.mongodb.DB;
import com.mongodb.MongoClient;
import com.mongodb.MongoClientURI;
import com.mongodb.MongoClientOptions;

/**
 * Utility class for Mongo DB.
 *
 * @author Rossitsa Borissova
 */
public class MongoUtil {

	private static String DEFAULT_DATABASE_NAME = "apifest";
	
    private static MongoClient mongoClient;
	private static String database = DEFAULT_DATABASE_NAME;
    private static Logger log = LoggerFactory.getLogger(MongoUtil.class);

    public static MongoClient getMongoClient(String uri) {
        if (mongoClient == null) {
            try {
                MongoClientOptions.Builder options = new MongoClientOptions.Builder()
                        .connectionsPerHost(100).connectTimeout(2000)
                        .threadsAllowedToBlockForConnectionMultiplier(1);
                final MongoClientURI mongoClientURI  = new MongoClientURI(uri, options);
                mongoClient = new MongoClient(mongoClientURI);

                if (mongoClientURI.getDatabase() != null) {
                    database = mongoClientURI.getDatabase();
                }
            } catch (UnknownHostException e) {
                log.error("Cannot connect to DB", e);
            }
        }
        return mongoClient;
    }

    public static DB getDB(String uri) {
        return getMongoClient(uri).getDB(database);
    }

}
