import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;
import com.google.common.base.Function;
import io.github.classgraph.ClassGraph;
import io.github.classgraph.ClassInfo;
import io.github.classgraph.ScanResult;
import org.bouncycastle.asn1.*;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.event.Level;
import util.PhaseTrack;
import util.Util;

import java.nio.file.Paths;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
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

    public static JsonNode procASN1TaggedObject(ASN1TaggedObject obj) {
        return walkRecurse(obj.getBaseObject().toASN1Primitive());
    }

    public static JsonNode procASN1Set(ASN1Set set) {
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

    public static JsonNode procASN1OctetString(ASN1OctetString obj) {
        return new TextNode(toStr(obj.getOctets()));
    }

    public static JsonNode procASN1GraphicString(ASN1GraphicString obj) {
        String s = obj.getString();
        return new TextNode(s);
    }


    public static JsonNode procASN1Sequence(ASN1Sequence sequence) {
        ArrayNode an = om.createArrayNode();
        for (int i = 0, count = sequence.size(); i < count; ++i) {
            an.add(walkRecurse(sequence.getObjectAt(i).toASN1Primitive()));
        }
        return an;
    }

    public static JsonNode doNothing(Object obj) {
        throw new RuntimeException("class" + obj.getClass().getName() + " is not mapped to a handler yet");
    }

    static ScanResult classResults = null;

    static ScanResult classScan() {
        if ( classResults == null ) {
            PhaseTrack.start();
            classResults = new ClassGraph()
                    .enableClassInfo().acceptPackages("org.bouncycastle").scan();
            PhaseTrack.logTimes("done scanning", Level.INFO, TimeUnit.MILLISECONDS);
        }
        return classResults;

    }
    private static HashMap<Class, Function<ASN1Primitive, JsonNode>> typeHandlers = null;

    static {
        HashMap<Class, Function<ASN1Primitive, JsonNode>> tmp1 = new HashMap<>();
        tmp1.put(ASN1TaggedObject.class, (obj) -> procASN1TaggedObject((ASN1TaggedObject) obj));
        tmp1.put(ASN1Sequence.class, (obj) -> procASN1Sequence((ASN1Sequence) obj));
        tmp1.put(ASN1Set.class, (obj) -> procASN1Set((ASN1Set) obj));
        tmp1.put(ASN1GraphicString.class, (obj) -> procASN1GraphicString((ASN1GraphicString) obj));
        tmp1.put(ASN1OctetString.class, (obj) -> procASN1OctetString((ASN1OctetString) obj));
        // map all possible sub types in this map so we do not miss anything
        // the match in the hash for a class does not take into account subtype - only
        // perfect class matches
        HashMap<Class, Function<ASN1Primitive, JsonNode>> tmp = new HashMap<>();
        for(var e: tmp1.entrySet()) {
            Class c = e.getKey();
            // map any sub types directly
            for(ClassInfo ci: classScan().getSubclasses(c))
                tmp.put(ci.loadClass(), e.getValue());
        }
        for(var e: tmp.entrySet()) {
            tmp1.put(e.getKey(), e.getValue());
        }
        typeHandlers =new HashMap<>(tmp1.size());
        for(var e: tmp1.entrySet()) {
            typeHandlers.put(e.getKey(), e.getValue());
        }
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
                        i++;
                        if ( i < 0 ) {
                            System.out.println(prettyJson);
                        }
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

