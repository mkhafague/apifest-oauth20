#ApiFest OAuth 2.0 Server and Mapping
ApiFest consists of two main parts - the ApiFest OAuth 2.0 an OAuth 2.0 server and the ApiFest Mapping Server.

##ApiFest Mapping Server
The ApiFest Mapping Server is for people who have APIs and want to expose them to the world in a safe and convenient way.
The ApiFest Mapping Server is used to translate between the outside world and your internal systems. It helps you keep a consistent API facade.

###Features
- mappings are described in xml
- can validate and authorize requests using the ApiFest OAuth20 Server
- out-of-the-box flexible mapping options - several versions support, different hosts to which API requests could be directed to
- easy to extend and customize
- customizable error messages and responses
- "online" change of all configurations
- unlimited horizontal scalability


##ApiFest OAuth 2.0 Server
The ApiFest OAuth 2.0 Server implements OAuth 2.0 server side as per http://tools.ietf.org/html/rfc6749.
It enables the usage of access tokens in ApiFest Mapping Server.

###Features
- register new client app
- generate access token using auth code
- generate access token using username and password - grant_type=password
- generate access token using client credentials - grant_type=client_credentials
- generate access token using refresh token - grant_type=refresh_token
- revoke access token
- validate access token
- pluggable storage (currently supports MongoDB and Redis)
- unlimited horizontal scalability


##ApiFest OAuth 2.0 Server Quick start:
**1. apifest-oauth.properties file**

Here is a template of the apifest-oauth.properties file:
```
oauth20.host=  
oauth20.port=  
oauth20.https=  
oauth20.production.mode=  
oauth20.subnets.whitelist=  
oauth20.keystore.path=  
oauth20.keystore.password=  
oauth20.database=  
mongodb.uri=
redis.master=
redis.sentinels=
redis.password=
hazelcast.cluster.name=  
hazelcast.password=  
hazelcast.cluster.members=  
custom.classes.jar=  
custom.authenticate.class=
custom.grant_type.class=
```

The path to the apifest.properties file should be set using a system variable ***-Dproperties.file***  

* **Setup the ApiFest OAuth 2.0 Server host and port**

The ApiFest OAuth 2.0 Server can run on different hosts and ports.
You can define the host and the port in the apifest-oauth.properties file using ***oauth20.host*** and ***oauth20.port***

* **Setup security properties**

You can set the server to run in SSL only mode if setting ***oauth20.https*** to true  
***oauth20.keystore.path*** and ***oauth20.keystore.password*** allow you to set the ssl certificate for the server

You can set the server to run in production mode, which will restrict the access to authenticated uers (see /oauth20/login endpoint) to the endpoints used for sensitive administration (see endpoint descriptions at the end)

***oauth20.production.mode***

You can further filter access to restricted endpoints by setting a whitelist of authorized subnets (CIDR notation separated by commas) with the following property :

***oauth20.subnets.whitelist***

e.g.

```oauth20.subnets.whitelist = 10.0.0.1/24,...,192.168.0.1/16```

* **Setup the type of the DB (Hazelcast, MongoDB or Redis)**

You can define the type of the DB to be used (by default MongoDB is used) - valid values are "hazelcast", "mongodb" and "redis" (without quotes) 

***oauth20.database***

* **Setup MongoDB**

If MongoDB is used, define the mongo URI string in the following property in the apifest-oauth.properties file:

***mongodb.uri***

e.g. ```mongodb://[username:password@]host1[:port1][,host2[:port2],...[,hostN[:portN]]][/[database][?options]]```

Username and password can optionally be set in the connection URI, find more documentation at 

Unless overridden, the following default values are set for the connection: ```connectTimeoutMS=2000```  

* **Setup Redis**

If Redis is used, define Redis sentinels list(as comma-separated list) in the following property in the apifest-oauth.properties file:
N.B: Redis code uses the SCAN command which requires 2.8.0+ versions

***redis.sentinels***

You can define the name of Redis master in the following property in the apifest-oauth.properties file:

***redis.master***

You can define the password of Redis in the following property in the apifest-oauth.properties file:

***redis.password***

* **Setup Hazelcast**
If Hazelcast is used, you can use an embedded instance or connect to an external cluster

if defined the following property will connect to an external cluster with the given group name:

***hazelcast.cluster.name***

you can set a password using the following property (otherwise the default Hazelcast password - dev-pass will be used):

***hazelcast.password***

you can setup the distributed storage nodes of the cluster using the following property (as comma-separated list of IPs):

***hazelcast.cluster.members***

* **Setup user authentication**

As the ApiFest OAuth 2.0 Server should be able to authenticate the user, you can implement your own user authentication implementing ```com.apifest.oauth20.IUserAuthentication``` interface (```com.apifest.oauth20.security.GuestUserAuthentication``` is the default implementation which always returns a default user).

In addition, ApiFest supports a custom grant_type and you can implement your own handler for it (implement ```com.apifest.oauth20.ICustomGrantTypeHandler``` interface and add the ```com.apifest.oauth20.GrantType``` annotation to provide the grant type name).

You can add your classes to the classpath or provide a jar that contains the implementation of these custom classes and set the following property:

***custom.classes.jar***

The custom user authentication class will be loaded when it's name is provided by the following property:

***custom.authenticate.class***

* **Setup custom grant_type**

If for some reason, you need to support additional custom grant_type, you can set it's classname using the following property:

***custom.grant_type.class***

**2. Start ApiFest OAuth 2.0 Server**

You can start the ApiFest OAuth 2.0 Server with the following command:

```java -Dproperties.file=[apifest_properties_file_path] -Dlog4j.configuration=file:///[log4j_xml_file_path] -jar apifest-oauth20-0.1.2-SNAPSHOT-jar-with-dependencies.jar```

When the server is started, you will see:
```ApiFest OAuth 2.0 Server started at [host]:[port]```

##ApiFest OAuth 2.0 Endpoints:
| Name | Description | Admin restricted access |
:------------- | :------------- | :-------------:
| */oauth20/login* | logs an user using provided access_token and checking credentials against configured authenticator class to access restricted endpoints when running in production mode | :white_check_mark: |
| */oauth20/applications* | registers client applications (POST method), returns all client applications info (GET method) | :white_check_mark: |
| */oauth20/applications/[client_id]* | returns client application info (GET method), updates a client application (PUT method), deletes a client application (DELETE method) | :white_check_mark: |
| */oauth20/auth-codes* | issues auth codes |
| */oauth20/tokens* | issues access tokens |
| */oauth20/tokens/validate* | validates access tokens |
| */oauth20/tokens/revoke* | revokes access tokens | :white_check_mark: |
| */oauth20/scopes* | creates a new scope (POST method) | :white_check_mark: |
| */oauth20/scopes/[scope_name]* | returns info about a scope name, description and expires_in (GET method), updates a scope (PUT method), deletes a scope (DELETE method) | :white_check_mark: |
| */oauth20/scopes?client_id=[client_id]* | returns scopes by client_id | :white_check_mark: |
| */oauth20/tokens?client_id=[client_id]&user_id=[user_id]* | returns all active tokens for a given user and client application | :white_check_mark: |
