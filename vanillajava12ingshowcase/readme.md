# Example with only Java 12 using the jdk http-client 

The http client was introduced in Java 11. Unfortunately, there was a blocking issue in 
Java 11, because some http header fields could not be overwritten, but yet this
is necessary for the flow to work.
In Java 12 this got solved.

## Intro

Simple demonstration of consuming the ING Showcase API, see https://developer.ing.com/api-marketplace/marketplace.
It shows how to:
* setup mutual TLS connection
* get oauth access token (client_credentials flow)
* call the 'greetings' service
* sign request with private key
* verify response signature

## Building and running

To run your application from command line:
```
mvn clean compile exec:java
```

You can also create a jar file with dependencies:
```
mvn package
java -jar target/vanillajava12-ingshowcase-1.0-SNAPSHOT.jar 
```

