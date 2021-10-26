package io.patlego.vm.security.pdf;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Enumeration;

import org.apache.pdfbox.io.IOUtils;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;

/**
 * An example for signing a PDF with bouncy castle. A keystore can be created
 * with the java keytool, for example:
 *
 * {@code keytool -genkeypair -storepass 123456 -storetype pkcs12 -alias test -validity 365
 *        -v -keyalg RSA -keystore keystore.p12 }
 *
 * @author Thomas Chojecki
 * @author Vakhtang Koroghlishvili
 * @author John Hewson
 */
public class CreateSignature extends CreateSignatureBase {
    private KeyStore keyStore;
    private String alias;

    /**
     * Initialize the signature creator with a keystore and certificate password.
     *
     * @param keystore the pkcs12 keystore containing the signing certificate
     * @param pin      the password for recovering the key
     * @throws KeyStoreException         if the keystore has not been initialized
     *                                   (loaded)
     * @throws NoSuchAlgorithmException  if the algorithm for recovering the key
     *                                   cannot be found
     * @throws UnrecoverableKeyException if the given password is wrong
     * @throws CertificateException      if the certificate is not valid as signing
     *                                   time
     * @throws IOException               if no certificate could be found
     */
    public CreateSignature(KeyStore keystore, String alias, char[] pin) throws KeyStoreException,
            UnrecoverableKeyException, NoSuchAlgorithmException, CertificateException, IOException {
        super(keystore, pin);
        this.keyStore = keystore;
        this.alias = alias;
    }

    /**
     * Signs the given PDF file. Alters the original file on disk.
     * 
     * @param file the PDF file to sign
     * @throws IOException       if the file could not be read or written
     * @throws KeyStoreException
     */
    public void signDetached(File file) throws IOException, KeyStoreException {
        signDetached(file, file);
    }

    /**
     * Signs the given PDF file.
     * 
     * @param inFile  input PDF file
     * @param outFile output PDF file
     * @param tsaUrl  optional TSA url
     * @throws IOException       if the input file could not be read
     * @throws KeyStoreException
     */
    public void signDetached(File inFile, File outFile) throws IOException, KeyStoreException {
        if (inFile == null || !inFile.exists()) {
            throw new FileNotFoundException("Document for signing does not exist");
        }

        FileOutputStream fos = new FileOutputStream(outFile);

        // sign
        PDDocument doc = null;
        try {
            doc = PDDocument.load(inFile);
            signDetached(doc, fos);
        } finally {
            IOUtils.closeQuietly(doc);
            IOUtils.closeQuietly(fos);
        }
    }

    public void signDetached(PDDocument document, OutputStream output) throws IOException, KeyStoreException {
        int accessPermissions = SigUtils.getMDPPermission(document);
        if (accessPermissions == 1) {
            throw new IllegalStateException(
                    "No changes to the document are permitted due to DocMDP transform parameters dictionary");
        }

        // create signature dictionary
        PDSignature signature = new PDSignature();
        signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
        signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
        signature.setName(this.alias);
        signature.setLocation(((X509Certificate) this.getCert(this.keyStore, this.alias)).getSubjectDN().toString());
        signature.setReason("Digital Document Signing");
        signature.setSignDate(Calendar.getInstance());

        // Optional: certify
        if (accessPermissions == 0) {
            SigUtils.setMDPPermission(document, signature, 2);
        }

        SignatureOptions signatureOptions = new SignatureOptions();
        // Size can vary, but should be enough for purpose.
        signatureOptions.setPreferredSignatureSize(SignatureOptions.DEFAULT_SIGNATURE_SIZE * 2);
        // register signature dictionary and sign interface
        document.addSignature(signature, this, signatureOptions);

        // write incremental (only for signing purpose)
        document.saveIncremental(output);

    }

    public Certificate getCert(KeyStore keystore, String alias) throws KeyStoreException {
        Enumeration<String> aliases = keystore.aliases();
        while (aliases.hasMoreElements()) {
            String entry = aliases.nextElement();
            if (entry.equals(alias)) {
                return keystore.getCertificate(entry);
            }
        }

        throw new KeyStoreException("Could not locate the alias from the provided certificate");
    }

}