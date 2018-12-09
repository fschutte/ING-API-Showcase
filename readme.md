# Consuming the ING Bank API

In here I provide two simple solutions for consuming the ING Bank Showcase API, see https://developer.ing.com.
The Showcase API is a production API for which authentication is required (two-legged oauth).

The following prerequisites apply:

1. register at ING Developer Portal
2. create an app in the developer portal and apply the Showcase API to it
3. note the client-id in the developer portal
4. create keypairs and certificates and upload the latter to the portal: there should be one for mutual TLS connection and a different one for signing on message level
5. Either in the Spring or Vertx application, change the configuration to reflect your client-id and the paths to your certificates and keys    

Once all is set, you can run the application in here.
Both the Spring Boot as well as the Vert.x application are as autonomous as possible.
Both contain a `main` function so that they can be run from the command line or directly from any IDE.


#### Note about the keys and certificates needed

You can use the following openssl command:

`openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem`

But I have also provided a simple Kotlin script that does the same:

`kotlinc -script gen-keys-and-certificates.kts`

It will create files for both the TLS connection as well as the Signing part.

