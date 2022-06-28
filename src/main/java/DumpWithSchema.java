import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import util.Util;

import java.nio.file.Paths;

import static util.Util.jom;

public class DumpWithSchema {

    public static void usage(String msg) {
        System.err.println("Command line error: " + msg);
        System.err.println("Usage: java class asn_schema_file top_type_name ber_data_file\";");

        System.exit(10);
    }

    public static void main(String[] args) {
        try {
            if (args.length != 3) {
                usage("missing argument - only have " + args.length);
            }
            SchemaNode node = AsantiSchemaExperiment.createNodes(Paths.get(args[0]), "MMTelRecord", false);
            try (ASN1InputStream ais = new ASN1InputStream(Util.create(Paths.get(args[2])))) {
                int i = 0;
                long len = 0;
                StringBuilder buf = new StringBuilder(1024);
                StringBuilder conv = new StringBuilder(1024);
                while (ais.available() > 0) {
                    ASN1Primitive obj = ais.readObject();
                    String s = Asn1DumpWithSchema.dumpAsString(node, buf, obj, true);
                    String c = conv.toString();
                    conv.setLength(0);
                    buf.setLength(0);
                    i++;
                    len += s.length();
                    System.out.println("orig");
                    System.out.println(s);
                    System.out.println("conv");
                    System.out.println(c);
                    if ( i> 2)
                        break;
                }

            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
