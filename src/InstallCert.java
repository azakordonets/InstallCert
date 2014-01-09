/**
 * Created by a.zakordonets on 9-1-14.
 */

import javax.net.ssl.*;
import java.io.*;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

public class InstallCert {
    public static void main(final String[] args) throws Exception {
        String host;
        String proxyHost =null;
        int port;
        String proxyPort = null;
        char[] passphrase;

        Map<String, String> paramsMap = new HashMap<String, String>();
        // parsing all passed parameters and storing them in the map
        for (String arg : args){
            paramsMap.put(arg.split("=")[0].replaceAll(" ", ""), arg.split("=")[1].replaceAll(" ", ""));
        }
        // Writing out all parameters that were passed to java
        Iterator it = paramsMap.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry pairs = (Map.Entry)it.next();
            System.out.println(pairs.getKey() + " = " + pairs.getValue());
        }
        //check if proxy parameters were passed in. If yes, then enable Proxy
        if (paramsMap.containsKey("proxyHost")) proxyHost = paramsMap.get("proxyHost");
        if (paramsMap.containsKey("proxyPort")) proxyPort = paramsMap.get("proxyPort");
        if (proxyHost != null && proxyPort != null){
            ProxyController proxy = new ProxyController();
            proxy.enableProxy(proxyHost,proxyPort);
        }else {
            System.out.println("Connecting to address without enabled proxy settings. ");
        };
        // now checking if host,port and passphrase parameters were passed succesfully
        if (paramsMap.containsKey("host")) {
            host = paramsMap.get("host");
            try {
                port = paramsMap.containsKey("port") ? Integer.parseInt(paramsMap.get("port")) : 443;
            } catch (NumberFormatException e) {
                System.out.println("Port was specified incorrectly. Setting to 443");
                port = 443;
                e.printStackTrace();
            }
            final String p = paramsMap.containsKey("passphraase") ? paramsMap.get("passphrase") : "changeit";
            passphrase = p.toCharArray();
        } else {
            System.out.println(
                    "Usage: java InstallCert host=[hostName] port=[portName] passphrase=[passphrase] " +
                            "proxyHost=[proxyHost] proxyPort=[proxyPort]\n" +
                            "passphrase, proxy details are not mandatory. Can be used default in case when they are " +
                            "not specified");
            return;
        }

        File file = new File("jssecacerts");
        if (file.isFile() == false) {
            final char SEP = File.separatorChar;
            final File dir = new File(System.getProperty("java.home")
                    + SEP + "lib" + SEP + "security");
            file = new File(dir, "jssecacerts");
            if (file.isFile() == false) {
                file = new File(dir, "cacerts");
            }
        }

        System.out.println("Loading KeyStore " + file + "...");
        final InputStream in = new FileInputStream(file);
        final KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(in, passphrase);
        in.close();

        final SSLContext context = SSLContext.getInstance("TLS");
        final TrustManagerFactory tmf =
                TrustManagerFactory.getInstance(TrustManagerFactory
                        .getDefaultAlgorithm());
        tmf.init(ks);
        final X509TrustManager defaultTrustManager =
                (X509TrustManager) tmf.getTrustManagers()[0];
        final SavingTrustManager tm = new SavingTrustManager(
                defaultTrustManager);
        context.init(null, new TrustManager[] { tm }, null);
        final SSLSocketFactory factory = context.getSocketFactory();

        System.out.println("Opening connection to "
                + host + ":" + port + "...");
        final SSLSocket socket = (SSLSocket) factory.createSocket(host, port);
        socket.setSoTimeout(10000);
        try {
            System.out.println("Starting SSL handshake...");
            socket.startHandshake();
            socket.close();
            System.out.println();
            System.out.println("No errors, certificate is already trusted");
        } catch (final SSLException e) {
            System.out.println();
            e.printStackTrace(System.out);
        }

        final X509Certificate[] chain = tm.chain;
        if (chain == null) {
            System.out.println("Could not obtain server certificate chain");
            return;
        }

        final BufferedReader reader =
                new BufferedReader(new InputStreamReader(System.in));

        System.out.println();
        System.out.println("Server sent " + chain.length + " certificate(s):");
        System.out.println();
        final MessageDigest sha1 = MessageDigest.getInstance("SHA1");
        final MessageDigest md5 = MessageDigest.getInstance("MD5");
        for (int i = 0; i < chain.length; i++) {
            final X509Certificate cert = chain[i];
            System.out.println(" " + (i + 1) + " Subject "
                    + cert.getSubjectDN());
            System.out.println("   Issuer  " + cert.getIssuerDN());
            sha1.update(cert.getEncoded());
            System.out.println("   sha1    " + toHexString(sha1.digest()));
            md5.update(cert.getEncoded());
            System.out.println("   md5     " + toHexString(md5.digest()));
            System.out.println();
        }

        System.out.println("Enter certificate to add to trusted keystore"
                + " or 'q' to quit: [1]");
        final String line = reader.readLine().trim();
        int k;
        try {
            k = (line.length() == 0) ? 0 : Integer.parseInt(line) - 1;
        } catch (final NumberFormatException e) {
            System.out.println("KeyStore not changed");
            return;
        }

        final X509Certificate cert = chain[k];
        final String alias = host + "-" + (k + 1);
        ks.setCertificateEntry(alias, cert);

        final OutputStream out = new FileOutputStream(file);
        ks.store(out, passphrase);
        out.close();

        System.out.println();
        System.out.println(cert);
        System.out.println();
        System.out.println(
                "Added certificate to keystore 'cacerts' using alias '"
                        + alias + "'");
    }

    private static final char[] HEXDIGITS = "0123456789abcdef".toCharArray();

    private static String toHexString(final byte[] bytes) {
        final StringBuilder sb = new StringBuilder(bytes.length * 3);
        for (int b : bytes) {
            b &= 0xff;
            sb.append(HEXDIGITS[b >> 4]);
            sb.append(HEXDIGITS[b & 15]);
            sb.append(' ');
        }
        return sb.toString();
    }

    private static class SavingTrustManager implements X509TrustManager {

        private final X509TrustManager tm;
        private X509Certificate[] chain;

        SavingTrustManager(final X509TrustManager tm) {
            this.tm = tm;
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
            // throw new UnsupportedOperationException();
        }

        @Override
        public void checkClientTrusted(final X509Certificate[] chain,
                                       final String authType)
                throws CertificateException {
            throw new UnsupportedOperationException();
        }

        @Override
        public void checkServerTrusted(final X509Certificate[] chain,
                                       final String authType)
                throws CertificateException {
            this.chain = chain;
            this.tm.checkServerTrusted(chain, authType);
        }
    }


}
