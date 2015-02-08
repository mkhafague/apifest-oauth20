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

import static org.mockito.Mockito.mock;
import static org.testng.Assert.assertTrue;

import com.apifest.oauth20.persistence.DBManager;
import com.apifest.oauth20.persistence.mongodb.MongoDBManager;
import org.slf4j.Logger;
import org.testng.annotations.Test;

import java.io.File;
import java.net.URISyntaxException;

/**
 * @author Rossitsa Borissova
 */
public class DBManagerFactoryTest {

    @Test
    public void when_mongo_oauth20_database_set_return_mongodb_manager() throws Exception {
        // GIVEN
        OAuthServer.log = mock(Logger.class);
        try {
            String path = (new File(getClass().getClassLoader().getResource("apifest-oauth-test.properties").toURI())).toString();
            System.setProperty("properties.file", path);
        } catch (URISyntaxException uex) {
            System.err.println(uex.getMessage());
        }
        OAuthServerContext.OAuthServerContextBuilder builder = new OAuthServerContext.OAuthServerContextBuilder();
        OAuthServer.loadConfig(builder);
        OAuthServer.context = builder.build();

        // WHEN
        DBManager dbManager = DBManagerFactory.getInstance();

        // THEN
        assertTrue(dbManager instanceof MongoDBManager);
        System.setProperty("properties.file", "");
    }
}
