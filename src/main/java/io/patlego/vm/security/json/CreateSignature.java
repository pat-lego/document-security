package io.patlego.vm.security.json;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.util.Base64;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import org.apache.commons.io.IOUtils;

import io.patlego.vm.security.SignDocumentException;

public class CreateSignature {

    private KeyStore keyStore;
    private char[] pin;
    private String alias;

    private static final String ENCODED_ELEMENT = "encoded";

    public CreateSignature(KeyStore keystore, String alias, char[] pin) {
        this.keyStore = keystore;
        this.pin = pin;
        this.alias = alias;
    }

    public void signDocument(File in) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException,
            SignDocumentException, InvalidKeyException, SignatureException, IOException {
        signDocument(in, in);
    }

    public void signDocument(File in, File out) throws UnrecoverableKeyException, KeyStoreException,
            NoSuchAlgorithmException, SignDocumentException, InvalidKeyException, SignatureException, IOException {
        PrivateKey key = this.getPrivateKey(this.pin, this.alias, this.keyStore);
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(key);
        privateSignature.update(this.getFileAsString(in).getBytes());

        byte[] signature = privateSignature.sign();

        String encoded = Base64.getEncoder().encodeToString(signature);

        JsonElement element = this.getFileAsJsonElement(in);
        JsonObject object = new JsonObject();
        if (element.isJsonObject()) {
            object = element.getAsJsonObject();
            object.addProperty(ENCODED_ELEMENT, encoded);
        } else if (element.isJsonArray() || element.isJsonPrimitive()) {
            object.add("data", element);
            object.addProperty(ENCODED_ELEMENT, encoded);
        } else {
            throw new SignDocumentException("Json cannot be of type JsonNull, please supply a valid Json object");
        }

        try (FileOutputStream fileOutputStream = new FileOutputStream(out)) {
            fileOutputStream.write(object.toString().getBytes());
        }
    }

    public String getFileAsString(File file) throws IOException {
        FileInputStream fileInputStream = new FileInputStream(file);
        return IOUtils.toString(fileInputStream, StandardCharsets.UTF_8);
    }

    public JsonElement getFileAsJsonElement(File file) throws IOException {
        String jsonString = this.getFileAsString(file);
        return JsonParser.parseString(jsonString);
    }

    public PrivateKey getPrivateKey(char[] password, String alias, KeyStore keyStore)
            throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, SignDocumentException {
        Key key = this.keyStore.getKey(this.alias, this.pin);
        if (key instanceof PrivateKey) {
            return (PrivateKey) key;
        }

        throw new SignDocumentException("Could not locate a private key within the provided keystore");
    }

}
