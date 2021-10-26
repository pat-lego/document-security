package io.patlego.vm.security.pdf;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;

import io.patlego.vm.security.SignDocument;
import io.patlego.vm.security.SignDocumentException;
import io.patlego.vm.security.SignDocumentType;

public class SignDocumentPDF implements SignDocument {

    @Override
    public void sign(String[] args) throws SignDocumentException {
        try {
            // load the keystore
            KeyStore keystore = KeyStore.getInstance("PKCS12");
            char[] password = System.console().readPassword("Password: ");
            keystore.load(new FileInputStream(args[0]), password);

            // sign PDF
            CreateSignature signing = new CreateSignature(keystore, args[1], password);

            File inFile = new File(args[2]);
            String name = inFile.getName();
            String substring = name.substring(0, name.lastIndexOf('.'));

            File outFile = new File(inFile.getParent(), substring + "_signed.pdf");
            signing.signDetached(inFile, outFile);
        } catch (IOException | GeneralSecurityException e) {
            throw new SignDocumentException(e.getMessage(), e);
        }

    }

    @Override
    public SignDocumentType getType() {
        return SignDocumentType.PDF;
    }

}
