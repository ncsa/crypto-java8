package edu.uiuc.ncsa.security.util.crypto;

import org.apache.commons.codec.binary.Base64;

import java.io.*;

/**
 * This does the grunt work of formatting keys and cert requests.
 * <p>Created by Jeff Gaynor<br>
 * on Jun 7, 2011 at  11:37:35 AM
 */
public class PEMFormatUtil {
    /**
     * Strip off the head and tail of a PEM encoded string. This just returns the body.
     *
     * @param pem
     * @param head
     * @param tail
     * @return
     */
    public static String getBody(String pem, String head, String tail) {
        // Be forgiving of trailing whitespace and line feeds
        pem = pem.trim();
        String linefeed = "\n";    // Good old OS/2. Oh, um, and Unix too...
        if (pem.endsWith("\r")) {
            // older Macs
            linefeed = "\r";
        } else if (pem.endsWith("\r\n")) {
            // Some Windows systems
            linefeed = "\r\n";
        }
        while (pem.endsWith(linefeed)) {
            pem = pem.substring(0, pem.length() - linefeed.length());
        }
        if (!pem.startsWith(head) || !pem.endsWith(tail)) {
            throw new IllegalArgumentException("Error: unrecognized format. The PEM encoding must start with " + head + " and end with " + tail);
        }
        return pem.substring(head.length() + 1, pem.length() - (tail.length() + 1));
    }

    /**
     * Gets the body bytes, i.e., what is between the head and tail (which you must supply) of the pem.
     * @param pem
     * @param head
     * @param tail
     * @return
     */
    public static byte[] getBodyBytes(String pem, String head, String tail) {
        return Base64.decodeBase64(getBody(pem, head, tail));
    }

    /**
     * Roughly the inverse of (@link {@link PEMFormatUtil#getBodyBytes(String, String, String)},
     * This will take any array of bytes, base 64 encode it and slap the head and tail around it.
     * @param body
     * @param head
     * @param tail
     * @return
     */
    public static String delimitBody(byte[] body, String head, String tail) {
        return delimitBody(bytesToChunkedString(body), head, tail);
    }

    /**
     * Utility to delimit a string (usually base 4 encoded DER byte array) with specific
     * head and tail. This checks that there are not extra carriage returns (which would invalidate
     * the output).
     *
     * @param body
     * @param head
     * @param tail
     * @return
     */
    public static String delimitBody(String body, String head, String tail) {
        StringWriter sw = new StringWriter();
        delimitBody(body, head, tail, sw);
        return sw.getBuffer().toString();
    }

    /**
     * Same as {@link PEMFormatUtil#delimitBody(byte[], String, String)}, but send the result to
     * the stream.
     * @param body
     * @param head
     * @param tail
     * @param outputStream
     */
    public static void delimitBody(byte[] body, String head, String tail, OutputStream outputStream) {
        delimitBody(bytesToChunkedString(body), head, tail, outputStream);
    }

    /**
     * Fixes OAUTH-212: upgrade to version 1.10 of apache commons no longer chunks strings (writes them at 76 characters
     * per line, except the last line), so PEM format of
     * all keys and certs are no longer readable by Open SSL, e.g.
     * @param body
     * @return
     */
    public static String bytesToChunkedString(byte[] body){
        byte[] out = Base64.encodeBase64Chunked(body);
        String foo = new String(out);
        return foo;
    }

    /**
     * Same as {@link PEMFormatUtil#delimitBody(String, String, String)} but send the result to a {@link PrintWriter}.
     * @param body
     * @param head
     * @param tail
     * @param pw
     */
    protected static void delimitBody(String body, String head, String tail, PrintWriter pw) {
        pw.println(head);
        String body2 = body.replaceAll("\r\n", "\n"); //commons library sticks return + linefeed no matter what, so strip it out.
        if (body2.endsWith("\n")) {
            pw.print(body2); //otherwise an extra linefeed occurs and the format is invalid.
        } else {
            pw.println(body2);
        }
        pw.print(tail);
        pw.flush();

    }

    /**
     * Same as {@link PEMFormatUtil#delimitBody(String, String, String)}  but send output to a writer
     * @param body
     * @param head
     * @param tail
     * @param writer
     */
    public static void delimitBody(String body, String head, String tail, Writer writer) {
        delimitBody(body, head, tail, new PrintWriter(writer));
    }

    /**
     * Same as {@link PEMFormatUtil#delimitBody(String, String, String)} but send output to a stream.
     * @param body
     * @param head
     * @param tail
     * @param outputStream
     */
    public static void delimitBody(String body, String head, String tail, OutputStream outputStream) {
        delimitBody(body, head, tail, new PrintWriter(outputStream));
    }

    /**
     * Take a reader and stick its contents into a string. This is needed, e.g., to pass to the
     * base64 decoder.
     *
     * @param f
     * @return
     * @throws IOException
     */
    public static String readerToString(Reader f) throws IOException {
        StringBuffer fileData = new StringBuffer(1000);
        BufferedReader reader = new BufferedReader(f);
        char[] buf = new char[1024];
        int numRead = 0;
        while ((numRead = reader.read(buf)) != -1) {
            String readData = String.valueOf(buf, 0, numRead);
            fileData.append(readData);
            buf = new char[1024];
        }
        reader.close();
        return fileData.toString();
    }

}
