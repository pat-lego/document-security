package io.patlego.vm.security;

import java.util.ServiceLoader;

public class Main {

    public static void main(String[] args) throws SignDocumentException {
        if (args.length < 3) {
            usage();
            System.exit(1);
        }

        SignDocumentType extension = getDocExtension(args[2]);

        ServiceLoader<SignDocument> loader = ServiceLoader.load(SignDocument.class);
        SignDocument signDocument = loader.stream().filter(service -> service.get().getType().equals(extension)).findFirst().get().get();

        signDocument.sign(args);
    }

    public static SignDocumentType getDocExtension(String doc) {
        if (null == doc || doc.isEmpty()) {
            throw new IllegalArgumentException("Invalid document name has been provided as part of the signing ceremony");
        }

        int lastDot = doc.lastIndexOf(".");
        String extension = doc.substring(lastDot + 1);
        return SignDocumentType.valueOf(extension.toUpperCase());
    }

    private static void usage() {
        System.err
                .println("Usage: java " + Main.class.getName() + " " + "<pkcs12_keystore> <alias> <document_to_sign>");
    }

}
