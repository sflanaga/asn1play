import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.*;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.*;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.event.Level;
import util.PhaseTrack;
import util.Util;

import java.nio.file.Paths;
import java.util.concurrent.TimeUnit;

@Slf4j
public class Asn1ToJson2_1 {
    static ObjectMapper om = new ObjectMapper();

    private static String toStr(byte[] bytes) {
        try {
            return Util.carefulBytesToString(bytes);
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

    public static JsonNode walk(TagStack tagStack, ASN1Primitive obj) {
        JsonNode node = null;
        final int tag = peekForTag(obj);
        String strTag = null;
        if ( tag >= 0 ) {
            tagStack.push(tag);
            strTag = "" + tag;
        }

        System.out.println(obj.getClass().getSimpleName() + " >>> " + tagStack);
//        if (peekTag > 0) {
//            on.set("tag", new IntNode(peekTag));
//        else
//            peekTag = -1;

        if ( tagStack.peek() == 301) {
            ;
        }

        if (obj instanceof ASN1TaggedObject) {
            node = walk(tagStack, ((ASN1TaggedObject) obj).getBaseObject().toASN1Primitive());
        } else if (obj instanceof ASN1Sequence) {
            var seq = (ASN1Sequence) obj;
            ObjectNode set = om.createObjectNode();
            ArrayNode an = om.createArrayNode();
            for (int i = 0, count = seq.size(); i < count; ++i) {
                ASN1Primitive tagPeek = seq.getObjectAt(i).toASN1Primitive();
                int t = peekForTag(tagPeek);
                String tagStr;
                if (t == -1) {
//                    log.error("set child not tagged? at {}", tagStack); // tagStr = "u" + i;
                    an.add(walk(tagStack, seq.getObjectAt(i).toASN1Primitive()));
                } else {
                    tagStr = "" + t;
                    JsonNode primish = walk(tagStack, seq.getObjectAt(i).toASN1Primitive());
                    set.set(tagStr, primish);
                }
            }
            if ( set.size() > 0 ) {
                node = set;
                if ( an.size()>0 ) {
                    set.set("array", an);
                    throw new RuntimeException("i don't think sequence should mix tagged and untagged a the same level");
                }
            } else if ( an.size() > 0 )
                node = an;
            else
                throw new RuntimeException("nothing in this sequence that is array or tagged");

//            var seq = (ASN1Sequence) obj;
//            ArrayNode an = om.createArrayNode();
//            for (int i = 0, count = seq.size(); i < count; ++i) {
//                an.add(walk(tagStack, seq.getObjectAt(i).toASN1Primitive()));
//            }
//            node = an;
        } else if (obj instanceof ASN1Set) {
            var set = (ASN1Set) obj;
            ObjectNode onset = om.createObjectNode();
            for (int i = 0, count = set.size(); i < count; ++i) {
                ASN1Primitive tagPeek = set.getObjectAt(i).toASN1Primitive();
                int t = peekForTag(tagPeek);
                String tagStr;
                if (t == -1)
                    throw new RuntimeException("set child not tagged?"); // tagStr = "u" + i;
                else
                    tagStr = "" + t;
                JsonNode primish = walk(tagStack, set.getObjectAt(i).toASN1Primitive());
                onset.set(tagStr, primish);
            }
            node = onset;
        } else if (obj instanceof ASN1GraphicString) {
            String s = ((ASN1GraphicString) obj).getString();
            node = new TextNode(s);
        } else if (obj instanceof ASN1OctetString) {
            node = new TextNode(toStr(((ASN1OctetString) obj).getOctets()));
        } else {
            throw new RuntimeException("unable handled type");
        }
        if ( tag >= 0 ) {
            tagStack.pop();
        }
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
        try {
            for (int k = 0; k < 3; k++)

                try (ASN1InputStream ais = new ASN1InputStream(Util.create(Paths.get(args[0])))) {
                    PhaseTrack.start();
                    int i = 0;
                    long len = 0;
                    var tagStack = new TagStack();
                    while (ais.available() > 0) {
                        ASN1Primitive obj = ais.readObject();
                        JsonNode jo = walk(tagStack, obj);
                        tagStack.clear();
                        String prettyJson = om.writerWithDefaultPrettyPrinter().writeValueAsString(jo);
                        len += prettyJson.length();
                        i++;
                        if (i < 3) {
                            System.out.println(prettyJson);
                        }
                        if ( i > 1 ) break;

                    }
                    System.out.printf("recs: %d  len: %d\n", i, len);

                    PhaseTrack.recordTimePoint("done");
                    PhaseTrack.logTimes("all times", Level.INFO, TimeUnit.MILLISECONDS);
                }
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

}

