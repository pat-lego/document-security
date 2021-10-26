package io.patlego.vm.security;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

public class TestMain {
    
    @Test
    public void testMainExtensionParser() {
        SignDocumentType extension = Main.getDocExtension("this.path.has/some/dots/myFile.pdf");
        assertEquals(SignDocumentType.PDF, extension);
    }
}
