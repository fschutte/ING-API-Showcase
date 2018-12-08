In here I provide two simple solutions for consuming the ING Showcase API, see https://developer.ing.com.
The Showcase API is a production API for which authentication is required (two-legged oauth).

The following prerequisites apply:
1. register at ING Developer Portal
2. create an app in the developer portal and apply the Showcase API to it
3. create keypairs and certificates and upload the latter to the portal : 
    there should be one for mutual TLS connection and a different one for signing on message level

Once all is set, you can run the application in here.
Both the Spring Boot as well as the Vert.x application are as autonomous as possible.
Both contain a `main` function so that they can be run from the command line or directly from any IDE.

