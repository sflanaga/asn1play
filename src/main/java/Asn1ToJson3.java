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
import util.TagStack;
import util.Util;

import java.math.BigInteger;
import java.nio.file.Path;
import java.util.Set;
import java.util.concurrent.TimeUnit;

@Slf4j
public class Asn1ToJson3 {
    public static class Cli {

        @CommandLine.Option(names = {"-f", "--ber_files"}, arity = "1..*", required = true,
                description = "files to decode")
        java.nio.file.Path[] files;

        @CommandLine.Option(names = {"-s", "--asn1_schema_path"},
                description = "location of the asn1 schema file")
        Path asnSchemaFile;

        @CommandLine.Option(names = {"-t", "--topname_from_schema"},
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

    public static JsonNode walk(boolean debugWriteThisOne, int depth, TagStack tagStack, ASN1Primitive obj, SchemaNode schemaNode) {
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
            ASN1TaggedObject subTag = (ASN1TaggedObject)obj;
            int subno = subTag.getTagNo();
            node = walk(debugWriteThisOne, depth + 1, tagStack, ((ASN1TaggedObject) obj).getBaseObject().toASN1Primitive(),schemaNode);
        } else if (obj instanceof org.bouncycastle.util.Iterable) {
            if (obj instanceof ASN1Sequence) {
                var seq = (ASN1Sequence) obj;
                node = handleSequence(debugWriteThisOne, depth, tagStack, seq, schemaNode);
            } else if (obj instanceof ASN1Set) {
                node = handleSet(debugWriteThisOne, depth, tagStack, (ASN1Set) obj,schemaNode);
            } else {
                throw new RuntimeException("Unable handled interable: " + obj.getClass().getName());
            }
        } else if (obj instanceof ASN1OctetString) {
            ASN1OctetString os = (ASN1OctetString) obj;
            node = fromOctetStringToJsonNode(debugWriteThisOne, depth, tagStack, os, schemaNode);
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

    private static JsonNode fromOctetStringToJsonNode(boolean debugWriteThisOne, int depth, TagStack tagStack, ASN1OctetString os, SchemaNode schemaNode) {
        JsonNode node;
        if ( schemaNode == null )
            throw new RuntimeException("No schema here");
        switch(schemaNode.primAsnBuiltinType) {
            case Enumerated: {
                var i = new BigInteger(os.getOctets());
                String name = schemaNode.enumDef.get(i.intValue());
                node = new TextNode(name);
            } break;

            case Ia5String:
            case OctetString:
            case GraphicString:
            case Utf8String: {
                node = new TextNode(toStr(os.getOctets()));
            }
            break;

            case Null: {
                node = NullNode.getInstance();
            }
            break;
            case Boolean: {
                node = os.getOctets()[0]>0 ? BooleanNode.TRUE : BooleanNode.FALSE;
            }
            break;
            case Integer: {
                var i = new BigInteger(os.getOctets());
                node = new BigIntegerNode(i);
            }
            break;
            case Choice: {
                SchemaNode chosenNode = null;
                try { chosenNode = schemaNode.choices.get(tagStack.peek()); }
                catch(Exception e) {

                    System.out.println("ouch " + tagStack.toString());
                    chosenNode = schemaNode.choices.get(tagStack.peek());
                }
                ObjectNode cNode = om.createObjectNode();
                cNode.set(chosenNode.fieldName, fromOctetStringToJsonNode(debugWriteThisOne, depth+1, tagStack, os, chosenNode));
                node = cNode;
            }
            case SequenceOf: {
                node = new TextNode("NO SEQ OF") ;
            }
            break;
            case Set: {
                node = new TextNode("NO SET ") ;
            }
            break;
            case SetOf: {
                node = new TextNode("NO SET OF") ;
            }
            break;
            default:
                throw new RuntimeException("type: " + schemaNode.primAsnBuiltinType.toString() + " not yet handled here");
        }
        return node;
    }

    private static JsonNode handleSet(boolean debugWriteThisOne, int depth, TagStack tagStack, ASN1Set set, SchemaNode schemaNode) {

        // TODO: should handle set have the same either array or object or both logic used below in sequence
        JsonNode node;
        ObjectNode onset = om.createObjectNode();
        for (int i = 0, count = set.size(); i < count; ++i) {
            ASN1Primitive tagPeek = set.getObjectAt(i).toASN1Primitive();
            int t = peekForTag(tagPeek);
            SchemaNode childSchema = null;
            String tagStr=null;
            if ( schemaNode!=null) {
                childSchema = schemaNode.children.get(t);
                if ( childSchema != null )
                    tagStr = childSchema.fieldName + ":" + t;
                else
                    childSchema = schemaNode;
            }
            if ( tagStr == null ) {
                if (t == -1)
                    throw new RuntimeException("set child not tagged?"); // tagStr = "u" + i;
                else
                    tagStr = "" + t;
            }
            if ( t==110 ) {
                System.out.println("hey");
            }
            JsonNode primish = walk(debugWriteThisOne, depth +1, tagStack, set.getObjectAt(i).toASN1Primitive(), childSchema);
            onset.set(tagStr, primish);
        }
        node = onset;
        return node;
    }

    private static JsonNode handleSequence(boolean debugWriteThisOne, int depth, TagStack tagStack, ASN1Sequence seq,  SchemaNode schemaNode) {
        JsonNode node;
        ObjectNode set = om.createObjectNode();
        ArrayNode an = om.createArrayNode();
        for (int i = 0, count = seq.size(); i < count; ++i) {
            ASN1Primitive tagPeek = seq.getObjectAt(i).toASN1Primitive();
            int t = peekForTag(tagPeek);
            SchemaNode childSchema = null;
            String tagStr=null;
            childSchema = schemaNode.children.get(t);
            if ( childSchema != null )
                tagStr = childSchema.fieldName;
            else
                childSchema = schemaNode;
            if ( tagStr == null ) {
                if (t == -1) {
                    var aEntry = walk(debugWriteThisOne, depth + 1, tagStack, seq.getObjectAt(i).toASN1Primitive(), childSchema);
                    an.add(aEntry);
                } else
                    tagStr = "" + t;
            }
            if ( tagStr != null && tagStr.equals("list-of-subscription-ID"))
                System.out.println("hey list");
            if (t == -1) {
                an.add(walk(debugWriteThisOne, depth +1, tagStack, seq.getObjectAt(i).toASN1Primitive(), childSchema));
            } else {
                JsonNode primish = walk(debugWriteThisOne, depth +1, tagStack, seq.getObjectAt(i).toASN1Primitive(), childSchema);
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
            SchemaNode schemaNode=null;
            if ( cli.asnSchemaFile != null ) {
                if ( cli.asnTopName == null )
                    throw new RuntimeException("schema must also have the top schema name specified to make it usefule");
                schemaNode = AsantiSchemaExperiment.createNodes(cli.asnSchemaFile, cli.asnTopName, false);

                SchemaNode test = schemaNode.find(new int[] {110,0,0});
                int jjj=0;
            }
            for (var path : cli.files) {
                int recordNo = 0;
                try (ASN1InputStream ais = new ASN1InputStream(Util.create(path))) {
                    PhaseTrack.start();
                    long len = 0;
                    var tagStack = new TagStack();
                    while (ais.available() > 0) {
                        boolean writeThisOne = false;
                        if (cli.writeOnly != null) {
                            if (cli.writeOnly.contains(recordNo))
                                writeThisOne = true;
                        } else
                            writeThisOne = true;

                        if ( writeThisOne ) {
                            System.out.println("Record no: " + recordNo);
                        }


                        ASN1Primitive obj = ais.readObject();
                        recordNo++;


                        JsonNode jo = walk(cli.debug & writeThisOne, 0, tagStack, obj, schemaNode);
                        tagStack.clear();

                        if (writeThisOne) {
                            String prettyJson = om.writerWithDefaultPrettyPrinter().writeValueAsString(jo);
                            System.out.println(prettyJson);
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

