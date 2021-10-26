package io.patlego.vm.security;

public class SignDocumentException extends Exception {

    public SignDocumentException(String msg, Throwable t) {
        super(msg, t);
    }

    public SignDocumentException(String msg) {
        super(msg);
    }
    
}
