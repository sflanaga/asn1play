import com.fasterxml.jackson.databind.JsonNode;
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

import java.math.BigInteger;
import java.util.Set;
import java.util.concurrent.TimeUnit;

@Slf4j
public class Asn1ToJson2_1 {
    public static class Cli {

        @CommandLine.Option(names = {"-f", "--properties_file"}, arity = "1..*", required = true,
                description = "files to decode")
        java.nio.file.Path[] files;

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

    public static JsonNode walk(boolean debugWriteThisOne, int depth, TagStack tagStack, ASN1Primitive obj) {
        nodeCount++;
        JsonNode node;
        final int tag = peekForTag(obj);
        String strTag = null;
        if (tag >= 0) {
            tagStack.push(tag);
            // strTag = "" + tag;
        }

        if (debugWriteThisOne)
            System.out.println(tagStack + " : " + depth + " : " + obj.getClass().getSimpleName());


        if (obj instanceof ASN1TaggedObject) {
            node = walk(debugWriteThisOne, depth + 1, tagStack, ((ASN1TaggedObject) obj).getBaseObject().toASN1Primitive());
        } else if (obj instanceof org.bouncycastle.util.Iterable) {
            if (obj instanceof ASN1Sequence) {
                var seq = (ASN1Sequence) obj;
                node = handleSequence(debugWriteThisOne, depth, tagStack, seq);
            } else if (obj instanceof ASN1Set) {
                node = handleSet(debugWriteThisOne, depth, tagStack, (ASN1Set) obj);
            } else {
                throw new RuntimeException("Unable handled interable: " + obj.getClass().getName());
            }
        } else if (obj instanceof ASN1OctetString) {
            ASN1OctetString os = (ASN1OctetString) obj;
            node = new TextNode(toStr((os).getOctets()));
        } else if (obj instanceof ASN1GraphicString) {
            String s = ((ASN1GraphicString) obj).getString();
            node = new TextNode(s);
        } else if (obj instanceof ASN1UTF8String) {
            String s = ((ASN1UTF8String) obj).getString();
            node = new TextNode(s);
        } else if (obj instanceof ASN1Integer) {
            BigInteger bi = ((ASN1Integer) obj).getValue();
            node = new BigIntegerNode(bi);
        }  else {
            throw new RuntimeException("unable handled type: " + obj.getClass().getSimpleName());
        }
        if (tag >= 0) {
            tagStack.pop();
        }
        return node;
    }

    private static JsonNode handleSet(boolean debugWriteThisOne, int depth, TagStack tagStack, ASN1Set set) {

        // TODO: should handle set have the same either array or object or both logic used below in sequence
        JsonNode node;
        ObjectNode onset = om.createObjectNode();
        for (int i = 0, count = set.size(); i < count; ++i) {
            ASN1Primitive tagPeek = set.getObjectAt(i).toASN1Primitive();
            int t = peekForTag(tagPeek);
            String tagStr;
            if (t == -1)
                throw new RuntimeException("set child not tagged?"); // tagStr = "u" + i;
            else
                tagStr = "" + t;
            JsonNode primish = walk(debugWriteThisOne, depth +1, tagStack, set.getObjectAt(i).toASN1Primitive());
            onset.set(tagStr, primish);
        }
        node = onset;
        return node;
    }

    private static JsonNode handleSequence(boolean debugWriteThisOne, int depth, TagStack tagStack, ASN1Sequence seq) {
        JsonNode node;
        ObjectNode set = om.createObjectNode();
        ArrayNode an = om.createArrayNode();
        for (int i = 0, count = seq.size(); i < count; ++i) {
            ASN1Primitive tagPeek = seq.getObjectAt(i).toASN1Primitive();
            int t = peekForTag(tagPeek);
            String tagStr;
            if (t == -1) {
//                    log.error("set child not tagged? at {}", tagStack); // tagStr = "u" + i;
                an.add(walk(debugWriteThisOne, depth +1, tagStack, seq.getObjectAt(i).toASN1Primitive()));
            } else {
                tagStr = "" + t;
                JsonNode primish = walk(debugWriteThisOne, depth +1, tagStack, seq.getObjectAt(i).toASN1Primitive());
                set.set(tagStr, primish);
            }
        }
        if (set.size() > 0) {
            node = set;
            if (an.size() > 0) {
                set.set("array", an);
                throw new RuntimeException("i don't think sequence should mix tagged and untagged a the same level");
            }
        } else if (an.size() > 0)
            node = an;
        else
            throw new RuntimeException("nothing in this sequence that is array or tagged");
        return node;
    }


    private static boolean isValue(JsonNodeType nodeType) {
        switch (nodeType) {
            case ARRAY:
            case OBJECT:
            case POJO:
                return false;
            case BINARY:
            case BOOLEAN:
            case MISSING:
            case NULL:
            case NUMBER:
            case STRING:
                return true;
            default:
                return false;
        }
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

        try {
            for (var path : cli.files) {
                int recordNo = 0;
                try (ASN1InputStream ais = new ASN1InputStream(Util.create(path))) {
                    PhaseTrack.start();
                    long len = 0;
                    var tagStack = new TagStack();
                    while (ais.available() > 0) {
                        ASN1Primitive obj = ais.readObject();
                        recordNo++;

                        boolean writeThisOne = false;
                        if (cli.writeOnly != null) {
                            if (cli.writeOnly.contains(recordNo))
                                writeThisOne = true;
                        } else
                            writeThisOne = true;

                        JsonNode jo = walk(cli.debug & writeThisOne, 0, tagStack, obj);
                        tagStack.clear();

                        if (writeThisOne) {
                            String prettyJson = om.writerWithDefaultPrettyPrinter().writeValueAsString(jo);
                            System.out.println("Record no: " + recordNo + "\n" + prettyJson);
                            len += prettyJson.length();
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

