# Clever-cloud Identity Provider

*By please-open.it*

## Create an oauth consumer

### Using Web Console

Go to "+ Create..." then choose "an oAuth consumer"

![](2022-09-17-15-47-04.png)

Then, add your informations about your Keycloak server : 

![](2022-09-17-15-49-03.png)

You can give only "Access my personal information"

![](2022-09-17-15-50-22.png)

Afterthat, you have a key and a secret, you are done.

## Install in Keycloak

Just do 

```
mvn clean install
```

Copy the generated JAR from "deployment" to "providers" directory in Keycloak. Restart Keycloak. You are done.

