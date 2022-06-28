import com.google.common.base.Stopwatch;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import util.Util;

import java.nio.file.Paths;

public class BouncyWalkTest {

    public static void usage(String msg) {
        System.err.println("Command line error: " + msg);
        System.exit(10);
    }

    public static void main(String[] args) {
        for (int j = 0; j < 10; j++) {

            try {
                Stopwatch sw = Stopwatch.createStarted();
                if (args.length != 1)
                    usage("missing argument");
                ASN1InputStream ais = new ASN1InputStream(Util.create(Paths.get(args[0])));
                int i = 0;
                long len = 0;
                StringBuilder buf = new StringBuilder(1024);
                while (ais.available() > 0) {
                    ASN1Primitive obj = ais.readObject();
//                if ( obj instanceof BERSet) {
//                    BERSet berSet = (BERSet) obj;
////                    ASN1Encodable enc = berSet.getObjectAt(0);
////                    ASN1TaggedObject taggedObject = (DLTaggedObject)enc;
//                    System.out.println(obj.getClass().getSimpleName() + " size: " + berSet.size());
//                }
                    i++;
                    String s = ASN1Dump.dumpAsString(buf, obj, true);
                    buf.setLength(0);
                    len += s.length();
                    System.out.println(s);
                    if ( i++ > 3) System.exit(1);
                }
                ais.close();
                double r = ((double)i*1000.0)/sw.elapsed().toMillis();
                System.out.printf("read %d objects in %s  len: %d  rate: %.1f\n", i, sw.elapsed(), len,r);

            } catch (Exception e) {
                e.printStackTrace();
            }
        }

    }


}
