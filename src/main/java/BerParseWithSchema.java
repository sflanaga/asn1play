import asanti.AsantiPaths;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.*;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.*;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.event.Level;
import picocli.CommandLine;
import util.PhaseTrack;
import util.Util;

import java.io.BufferedOutputStream;
import java.io.PrintStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Set;
import java.util.concurrent.TimeUnit;

@Slf4j
public class BerParseWithSchema {
    public static class Cli {

        @CommandLine.Option(names = {"-f", "--files_to_parse"}, arity = "1..*", required = true,
                description = "files to decode")
        Path[] files;

        @CommandLine.Option(names = {"-o", "--output_file"}, arity = "1..*", required = false,
                description = "write every thing to this single txt file")
        Path outputPath;

        @CommandLine.Option(names = {"-s", "--asn1_schema_path"}, required = true,
                description = "location of the asn1 schema file")
        Path asnSchemaFile;

        @CommandLine.Option(names = {"-t", "--topname_from_schema"}, required = true,
                description = "top name to get from the schema to map")
        String asnTopName;

        @CommandLine.Option(names = {"-x", "--hex_also"},
                description = "always write hex with decodable strings")
        boolean hexAlso;

        @CommandLine.Option(names = {"-i", "--index_list"}, arity = "0..*",
                description = "write only some of the records, starting index is 1 - e.g. -i 100 2000 3001")
        Set<Integer> writeOnly;

        @CommandLine.Option(names = {"-d", "--debug_info"}, defaultValue = "false",
                description = "during processing write tags paths and final type")
        boolean debug;

        @CommandLine.Option(names = {"-h",
                "--help"}, usageHelp = true, description = "display this help message\nsample cmdline: java -cp hdfs_du2-1.0-SNAPSHOT.jar:lib/* org.HdfsDu2 /prod test --krb5_user adm_sflanag1@HDPQUANTUMPROD.COM --krb5_key_tab /etc/security/keytabs/adm_sflanag1.user.keytab")
        boolean usageHelpRequested;
    }

    static Cli cli = null;
    static ObjectMapper om = new ObjectMapper();

    static long nodeCount = 0;

    static LinkedHashMap<String, AsantiPaths.FieldInfo> schema;
    static PrintStream ps = null;
    private static String toStr(byte[] bytes) {
        try {
            String s = Util.carefulBytesToString(bytes);
            if (cli.hexAlso)
                s += ", HEX: " + Strings.fromByteArray(Hex.encode(bytes));
            return s;
        } catch (Exception e) {
            return "HEX: " + Strings.fromByteArray(Hex.encode(bytes));

        }
    }

    public static int peekForTag(ASN1Primitive obj) {
        if (obj instanceof ASN1TaggedObject) {
            ASN1TaggedObject o = (ASN1TaggedObject) obj;
            return o.getTagNo();
        } else
            return -1;
    }

    public static String getSchemaString(String path) {
        var o = schema.get(path);
        if ( o == null ) {
            throw new RuntimeException("No connection to schema for tag path: " + path);
        } else {
            return o.toString();
        }
    }

    public static void walk(boolean debugWriteThisOne, int depth, StringBuilder tagStack, ASN1Primitive obj) {
        nodeCount++;
        final int tag = peekForTag(obj);
        String strTag = null;
        int tagStackMarker = tagStack.length();
        if (tag >= 0 )
            tagStack.append('/').append(tag);

        if (obj instanceof ASN1TaggedObject) {
            walk(debugWriteThisOne, depth + 1, tagStack, ((ASN1TaggedObject) obj).getBaseObject().toASN1Primitive());
        } else if (obj instanceof org.bouncycastle.util.Iterable) {
            if (obj instanceof ASN1Sequence) {
                var seq = (ASN1Sequence) obj;
                handleSequence(debugWriteThisOne, depth, tagStack, seq);
            } else if (obj instanceof ASN1Set) {
                handleSet(debugWriteThisOne, depth, tagStack, (ASN1Set) obj);
            } else {
                throw new RuntimeException("Unable handled interable: " + obj.getClass().getName());
            }
        } else if (obj instanceof ASN1OctetString) {
            ASN1OctetString os = (ASN1OctetString) obj;
            String path = tagStack.toString();
            String s = toStr((os).getOctets());
            write(ps,os,tagStack);
            if (debugWriteThisOne)
                write(System.out,os,tagStack);
        } else if (obj instanceof ASN1GraphicString) {
            String s = ((ASN1GraphicString) obj).getString();
            if (debugWriteThisOne)
                write(System.out, obj, tagStack,s);

            write(ps,obj, tagStack, s);
        } else if (obj instanceof ASN1UTF8String) {
            String s = ((ASN1UTF8String) obj).getString();
            write(ps,obj,tagStack,s);
            if (debugWriteThisOne)
                write(System.out, obj, tagStack,s);
        } else if (obj instanceof ASN1Integer) {
            BigInteger bi = ((ASN1Integer) obj).getValue();
            write(ps, obj,tagStack,bi.toString());
            if (debugWriteThisOne)
                write(System.out, obj, tagStack,bi.toString());
        } else {
            throw new RuntimeException("unable handled type: " + obj.getClass().getSimpleName());
        }
        if (tag >= 0 )
            tagStack.setLength(tagStackMarker);
    }

    private static void write(PrintStream printStream, ASN1Primitive obj, StringBuilder tagStack, String s) {
        if ( printStream != null ) {
            var path = tagStack.toString();
            var ss = getSchemaString(path);
            printStream.println(path + "," + ss + "," + obj.getClass().getSimpleName() + "," + s);
        }
    }

    private static void write(PrintStream printStream, ASN1OctetString oct, StringBuilder tagStack) {
        if ( printStream != null ) {
            var path = tagStack.toString();
            var fieldInfo =schema.get(path);
            String s;
            byte[] bytes = oct.getOctets();
            if ( fieldInfo.enumDef!=null ) {
                s = "(" + getEnumString(bytes, fieldInfo.enumDef) + ")";
            } else {
                switch (fieldInfo.builtinType) {
                    case Integer:
                        s = bytesIntegerToString(bytes);
                        break;
                    default:
                        s = toStr(bytes);
                        break;
                }
            }
            var ss = getSchemaString(path);
            printStream.println(path + "," + ss + "," + oct.getClass().getSimpleName() + "," + s);
        }
    }

    private static String getEnumString(byte[] bytes, HashMap<Integer, String> enumDef) {
        int i = (int)bytesToLong(bytes);
        String en = enumDef.get(i);
        if ( en == null ) {
            // TODO: these do occur - just write the number?
            return bytesIntegerToString(bytes);
        }
        return en;
    }
    private static long bytesToLong(byte[] bytes) {
        long l = -1;
        if (bytes.length == 1) {
            l = (long) bytes[0];
        } else {
            BigInteger bi = new BigInteger(bytes);
            l = bi.longValue();
        }
        return l;
    }
    private static String bytesIntegerToString(byte[] bytes) {
        if (bytes.length == 1) {
            return String.valueOf(bytes[0]);
        } else {
            BigInteger bi = new BigInteger(bytes);
            return bi.toString();
        }
    }

    private static void writeBottom(ASN1Primitive obj, ASN1OctetString os, String path) {
        if (ps!=null) {
            String s = toStr(os.getOctets());
            ps.println(getSchemaString(path) + " " + s + " " + obj.getClass().getSimpleName());
        }
    }

    private static void handleSet(boolean debugWriteThisOne, int depth, StringBuilder tagStack, ASN1Set set) {

        // TODO: should handle set have the same either array or object or both logic used below in sequence
        ObjectNode onset = om.createObjectNode();
        for (int i = 0, count = set.size(); i < count; ++i) {
            walk(debugWriteThisOne, depth + 1, tagStack, set.getObjectAt(i).toASN1Primitive());
        }
    }

    private static void handleSequence(boolean debugWriteThisOne, int depth, StringBuilder tagStack, ASN1Sequence seq) {
        for (int i = 0, count = seq.size(); i < count; ++i)
            walk(debugWriteThisOne, depth + 1, tagStack, seq.getObjectAt(i).toASN1Primitive());
    }


    public static void main(String[] args) {
        cli = new Cli();
        try {
            CommandLine cl = new CommandLine(cli);
            cl.parseArgs(args);
            if (cli.usageHelpRequested) {
                cl.usage(System.err);
                return;
            }
        } catch (Exception e) {
            System.err.println("cli related exception: " + e);
            return;
        }
//        for (int i = 0; i < 3; i++)
        try {
            schema = AsantiPaths.createParsingSchema(cli.asnSchemaFile, cli.asnTopName);

            if ( cli.outputPath!=null)
                ps = new PrintStream(new BufferedOutputStream(Files.newOutputStream(cli.outputPath)));
            StringBuilder tagStack = new StringBuilder(16);
            for (var path : cli.files) {
                int recordNo = 0;
                try (ASN1InputStream ais = new ASN1InputStream(Util.create(path))) {
                    PhaseTrack.start();
                    long len = 0;
                    while (ais.available() > 0) {
                        recordNo++;
                        boolean writeThisOne = false;
                        if (cli.writeOnly != null) {
                            if (cli.writeOnly.contains(recordNo))
                                writeThisOne = true;
                        } else
                            writeThisOne = true;

                        if (writeThisOne)
                            System.out.println("R# " + recordNo);

                        if ( ps!=null)
                            ps.println("R# " + recordNo);

                        ASN1Primitive obj = ais.readObject();


                        walk(cli.debug & writeThisOne, 0, tagStack, obj);
                        tagStack.setLength(0);

                        if (writeThisOne) {
//                            String prettyJson = om.writerWithDefaultPrettyPrinter().writeValueAsString(jo);
//                            System.out.println("Record no: " + recordNo + "\n" + prettyJson);
//                            len += prettyJson.length();
                        }

                    }
                    System.out.printf("recs: %d  len: %d\n", recordNo, len);
                    long deltaT = PhaseTrack.startToNowNanos();
                    long recRate = (recordNo * 1_000_000_000L) / deltaT;
                    long nodeRate = (nodeCount * 1_000_000_000L) / deltaT;
                    nodeCount = 0L;
                    String msg = String.format(" rec rate: %d/s node rate: %d/s", recRate, nodeRate);
                    PhaseTrack.recordTimePoint("done");
                    PhaseTrack.logTimes(msg, Level.INFO, TimeUnit.MILLISECONDS);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

}

