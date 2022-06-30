import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.*;
import com.google.common.base.Function;
import org.bouncycastle.asn1.*;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.event.Level;
import util.PhaseTrack;
import util.Util;

import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.concurrent.TimeUnit;

public class Asn1ToJson2 {
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

    public static JsonNode procDlTaggedObject(DLTaggedObject obj) {
        return walkRecurse(obj.getBaseObject().toASN1Primitive());
    }

    public static JsonNode procBERSet(BERSet set) {
        ObjectNode on = om.createObjectNode();
        for (int i = 0, count = set.size(); i < count; ++i) {
            ASN1Primitive tagPeek = set.getObjectAt(i).toASN1Primitive();
            int t = peekForTag(tagPeek);
            String tagStr;
            if (t == -1)
                throw new RuntimeException("set child not tagged?"); // tagStr = "u" + i;
            else
                tagStr = "" + t;
            on.set(tagStr, walkRecurse(set.getObjectAt(i).toASN1Primitive()));
        }
        return on;
    }

    public static JsonNode procDEROctetString(DEROctetString obj) {
        return new TextNode(toStr(obj.getOctets()));
    }

    public static JsonNode procDERGraphicString(DERGraphicString obj) {
        String s = obj.getString();
        return new TextNode(s);
    }


    public static JsonNode procBERSequence(BERSequence sequence) {
        ArrayNode an = om.createArrayNode();
        for (int i = 0, count = sequence.size(); i < count; ++i) {
            an.add(walkRecurse(sequence.getObjectAt(i).toASN1Primitive()));
        }
        return an;
    }

    private static HashMap<Class, Function<ASN1Primitive, JsonNode>> typeHandlers = new HashMap<>();

    static {
        typeHandlers.put(BERTaggedObject.class, (obj) -> procBERTaggedObject((BERTaggedObject) obj));
        typeHandlers.put(DLTaggedObject.class, (obj) -> procDlTaggedObject((DLTaggedObject) obj));
        typeHandlers.put(BERSequence.class, (obj) -> procBERSequence((BERSequence) obj));
        typeHandlers.put(BERSet.class, (obj) -> procBERSet((BERSet) obj));
        typeHandlers.put(DERGraphicString.class, (obj) -> procDERGraphicString((DERGraphicString) obj));
        typeHandlers.put(DEROctetString.class, (obj) -> procDEROctetString((DEROctetString) obj));
    }

    private static JsonNode procBERTaggedObject(BERTaggedObject obj) {
        return walkRecurse(obj.getBaseObject().toASN1Primitive());
    }

    public static JsonNode walkRecurse(ASN1Primitive obj) {
        var handler = typeHandlers.get(obj.getClass());
        if (handler == null)
            throw new RuntimeException("no handler for class: " + obj.getClass().getName());
        else {
            return handler.apply(obj);
        }
    }

    public static void main(String[] args) {

        try {
            for (int k = 0; k < 3; k++)

            try (ASN1InputStream ais = new ASN1InputStream(Util.create(Paths.get(args[0])))) {
                PhaseTrack.start();
                int i = 0;
                long len = 0;
                while (ais.available() > 0) {
                    ASN1Primitive obj = ais.readObject();
                    JsonNode jo = walkRecurse(obj);
                    String prettyJson = om.writerWithDefaultPrettyPrinter().writeValueAsString(jo);
                    len += prettyJson.length();
//                    System.out.println(prettyJson);
//                    System.out.println("==============");
                    i++;
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

