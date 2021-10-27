# Document Security

Securing documents with a digital signature should not be a costly solution, this lightweight executable jar signs a PDF with a local PKCS12 keystore in order to validate the integrity of the document.

**Disclaimer this repository is heavily borrowed from the Apache PDFBox example code base**

## How to build

In order to use this library execute `mvn clean install` which will then produce the build artifact called `document-security.jar` under the `target/` folder.

## How to use

In order to execute this JAR file you will need to provide it with a few inputs:

1. A valid PKCS12 Keystore (it can be self signed)
2. The Alias within the PKCS12 file
3. The PKCS12 Keystore password
4. The Document to Sign

To generate a self signed PKCS12 keystore execute the following command:

keytool -genkeypair -storepass <your_pwd> -storetype pkcs12 -alias <your_alias> -validity 365 -v -keyalg RSA -keystore keystore.p12

**Note:** Make sure to change the <your_pwd> and the <your_alias> before executing this command

Then you can execute the jar by running the following command: `java -jar document-security.jar keystore.p12 <your_alias> <path_to_pdf>`

## Benefits

If you need to manage the integrity of a document, having a signature placed on it will help validate that no changes have been made after the signature has been applied.

# Contributors

- [Patrique Legault](https://github.com/pat-lego)
