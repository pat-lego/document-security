package io.patlego.vm.security;

public interface SignDocument {
    
    public void sign(String[] args) throws SignDocumentException;

    public SignDocumentType getType();
}
