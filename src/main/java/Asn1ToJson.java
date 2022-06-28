import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.*;
import org.bouncycastle.asn1.*;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.event.Level;
import util.PhaseTrack;
import util.Util;

import java.math.BigInteger;
import java.nio.file.Paths;
import java.util.concurrent.TimeUnit;

public class Asn1ToJson {
    static ObjectMapper om = new ObjectMapper();

    private static final String TAB = "    ";
    private static final int SAMPLE_SIZE = 32;

    private static boolean writeStringBuf = true;

    /**
     * dump a DER object as a formatted string with indentation
     *
     * @param obj the ASN1Primitive to be dumped out.
     */
    static JsonNode _dumpAsString(
            String indent,
            boolean verbose,
            ASN1Primitive obj,
            StringBuilder buf) {
        String nl = Strings.lineSeparator();
        if (obj instanceof ASN1Null) {
            return NullNode.instance;
//            buf.append(indent);
//            buf.append("NULL");
//            buf.append(nl);
        } else if (obj instanceof ASN1Sequence) {
            ArrayNode an = om.createArrayNode();
            buf.append(indent);
            if (writeStringBuf)
                if (obj instanceof BERSequence) {
                    buf.append("BER Sequence");
                } else if (obj instanceof DERSequence) {
                    buf.append("DER Sequence");
                } else {
                    buf.append("Sequence");
                }
            if (writeStringBuf)
                buf.append(nl);

            ASN1Sequence sequence = (ASN1Sequence) obj;
            String elementsIndent = indent + TAB;

            for (int i = 0, count = sequence.size(); i < count; ++i) {
                an.add(_dumpAsString(elementsIndent, verbose, sequence.getObjectAt(i).toASN1Primitive(), buf));
            }
            return an;
        } else if (obj instanceof ASN1Set) {
            if (writeStringBuf)
                buf.append(indent);
            if (writeStringBuf)
                if (obj instanceof BERSet) {
                    buf.append("BER Set");
                } else if (obj instanceof DERSet) {
                    buf.append("DER Set");
                } else {
                    buf.append("Set");
                }
            buf.append(nl);

            ASN1Set set = (ASN1Set) obj;
            String elementsIndent = indent + TAB;

            ObjectNode on = om.createObjectNode();
            for (int i = 0, count = set.size(); i < count; ++i) {
                ASN1Primitive tagPeek = set.getObjectAt(i).toASN1Primitive();
                int t = peekForTag(tagPeek);
                String tagStr;
                if (t == -1)
                    throw new RuntimeException("set child not tagged?"); // tagStr = "u" + i;
                else
                    tagStr = "" + t;
                on.set(tagStr, _dumpAsString(elementsIndent, verbose, set.getObjectAt(i).toASN1Primitive(), buf));
            }
            return on;
        } else if (obj instanceof ASN1ApplicationSpecific) {
            return _dumpAsString(indent, verbose, ((ASN1ApplicationSpecific) obj).getTaggedObject(), buf);
        } else if (obj instanceof ASN1TaggedObject) {
            ASN1TaggedObject o = (ASN1TaggedObject) obj;

            if (writeStringBuf) {
                if (obj instanceof BERTaggedObject) {
                    buf.append("BER Tagged ");
                } else if (obj instanceof DERTaggedObject) {
                    buf.append("DER Tagged ");
                } else {
                    buf.append("Tagged ");
                }
                buf.append(ASN1Util.getTagText(o));

                if (!o.isExplicit()) {
                    buf.append(" IMPLICIT ");
                }

                buf.append(nl);
            }
            String baseIndent = indent + TAB;

            return _dumpAsString(baseIndent, verbose, o.getBaseObject().toASN1Primitive(), buf);
        } else if (obj instanceof ASN1OctetString) {
            ASN1OctetString oct = (ASN1OctetString) obj;
            String s = "";

            if (writeStringBuf)
                if (obj instanceof BEROctetString) {
                    buf.append(indent + "BER Constructed Octet String" + "[" + oct.getOctets().length + "] ");
                } else {
                    buf.append(indent + "DER Octet String" + "[" + oct.getOctets().length + "] ");
                }

            if (writeStringBuf)
                if (verbose) {
                    buf.append(s);
                } else {
                    buf.append(nl);
                }
            s = toStr(oct.getOctets());
            return new TextNode(s);

        } else if (obj instanceof ASN1ObjectIdentifier) {
            String s = ((ASN1ObjectIdentifier) obj).getId();
            if (writeStringBuf)
                buf.append(indent + "ObjectIdentifier(" + s + ")" + nl);
            return new TextNode(s);
        } else if (obj instanceof ASN1RelativeOID) {
            String s = ((ASN1RelativeOID) obj).getId();
            if (writeStringBuf)
                buf.append(indent + "RelativeOID(" + s + ")" + nl);
            return new TextNode(s);
        } else if (obj instanceof ASN1Boolean) {
            boolean b = ((ASN1Boolean) obj).isTrue();
            if (writeStringBuf)
                buf.append(indent + "Boolean(" + b + ")" + nl);
            return b ? BooleanNode.TRUE : BooleanNode.FALSE;
        } else if (obj instanceof ASN1Integer) {
            BigInteger bi = ((ASN1Integer) obj).getValue();
            if (writeStringBuf)
                buf.append(indent + "Integer(" + bi + ")" + nl);
            return new BigIntegerNode(bi);
        } else if (obj instanceof ASN1BitString) {
            ASN1BitString bitString = (ASN1BitString) obj;

            byte[] bytes = bitString.getBytes();
            int padBits = bitString.getPadBits();

            if (writeStringBuf) {
                if (bitString instanceof DERBitString) {
                    buf.append(indent + "DER Bit String" + "[" + bytes.length + ", " + padBits + "] ");
                } else if (bitString instanceof DLBitString) {
                    buf.append(indent + "DL Bit String" + "[" + bytes.length + ", " + padBits + "] ");
                } else {
                    buf.append(indent + "BER Bit String" + "[" + bytes.length + ", " + padBits + "] ");
                }
                if (verbose) {
                    buf.append(dumpBinaryDataAsString(indent, bytes));
                } else {
                    buf.append(nl);
                }
            }
            String s = toStr(bytes);
            return new TextNode(s);
        } else if (obj instanceof ASN1IA5String) {
            String s = ((ASN1IA5String) obj).getString();
            if (writeStringBuf)
                buf.append(indent + "IA5String(" + s + ") " + nl);
            return new TextNode(s);
        } else if (obj instanceof ASN1UTF8String) {
            String s = ((ASN1UTF8String) obj).getString();
            if (writeStringBuf)
                buf.append(indent + "UTF8String(" + s + ") " + nl);
            return new TextNode(s);
        } else if (obj instanceof ASN1NumericString) {
            String s = ((ASN1NumericString) obj).getString();
            if (writeStringBuf)
                buf.append(indent + "NumericString(" + s + ") " + nl);
            return new TextNode(s);
        } else if (obj instanceof ASN1PrintableString) {
            String s = ((ASN1PrintableString) obj).getString();
            if (writeStringBuf)
                buf.append(indent + "PrintableString(" + s + ") " + nl);
            return new TextNode(s);
        } else if (obj instanceof ASN1VisibleString) {
            String s = ((ASN1VisibleString) obj).getString();
            if (writeStringBuf)
                buf.append(indent + "VisibleString(" + s + ") " + nl);
            return new TextNode(s);
        } else if (obj instanceof ASN1BMPString) {
            String s = ((ASN1BMPString) obj).getString();
            if (writeStringBuf)
                buf.append(indent + "BMPString(" + s + ") " + nl);
            return new TextNode(s);
        } else if (obj instanceof ASN1T61String) {
            String s = ((ASN1T61String) obj).getString();
            if (writeStringBuf)
                buf.append(indent + "T61String(" + s + ") " + nl);
            return new TextNode(s);
        } else if (obj instanceof ASN1GraphicString) {
            String s = ((ASN1GraphicString) obj).getString();
            if (writeStringBuf)
                buf.append(indent + "GraphicString(" + s + ") " + nl);
            return new TextNode(s);
        } else if (obj instanceof ASN1VideotexString) {
            String s = ((ASN1VideotexString) obj).getString();
            if (writeStringBuf)
                buf.append(indent + "VideotexString(" + s + ") " + nl);
            return new TextNode(s);
        } else if (obj instanceof ASN1UTCTime) {
            String s = ((ASN1UTCTime) obj).getTime();
            if (writeStringBuf)
                buf.append(indent + "UTCTime(" + s + ") " + nl);
            return new TextNode(s);
        } else if (obj instanceof ASN1GeneralizedTime) {
            String s = ((ASN1GeneralizedTime) obj).getTime();
            if (writeStringBuf)
                buf.append(indent + "GeneralizedTime(" + s + ") " + nl);
            return new TextNode(s);
        } else if (obj instanceof ASN1Enumerated) {
            ASN1Enumerated en = (ASN1Enumerated) obj;
            BigInteger bi = en.getValue();
            if (writeStringBuf)
                buf.append(indent + "DER Enumerated(" + en + ")" + nl);
            return new BigIntegerNode(bi);
        } else if (obj instanceof ASN1ObjectDescriptor) {
            ASN1ObjectDescriptor od = (ASN1ObjectDescriptor) obj;
            String s = od.getBaseGraphicString().getString();
            if (writeStringBuf)
                buf.append(indent + "ObjectDescriptor(" + s + ") " + nl);
            return new TextNode(s);
        } else if (obj instanceof ASN1External) {
            ASN1External ext = (ASN1External) obj;
            if (writeStringBuf)
                buf.append(indent + "External " + nl);
            String tab = indent + TAB;
            if (ext.getDirectReference() != null) {
                buf.append(tab + "Direct Reference: " + ext.getDirectReference().getId() + nl);
            }
            if (verbose) {
                if (ext.getIndirectReference() != null) {
                    buf.append(tab + "Indirect Reference: " + ext.getIndirectReference().toString() + nl);
                }
                if (ext.getDataValueDescriptor() != null) {
                    _dumpAsString(tab, verbose, ext.getDataValueDescriptor(), buf);
                }
                buf.append(tab + "Encoding: " + ext.getEncoding() + nl);
            }
            throw new RuntimeException("externals not handled");
        } else {
            String s = obj.toString();
            if (writeStringBuf)
                buf.append(indent + obj.toString() + nl);
            return new TextNode(s);
        }
    }

    /**
     * dump out a DER object as a formatted string, in non-verbose mode.
     *
     * @param obj the ASN1Primitive to be dumped out.
     * @return the resulting string.
     */
    public static JsonNode dumpAsString(
            Object obj, StringBuilder bld) {
        return dumpAsString(obj, bld, false);
    }

    /**
     * Dump out the object as a string.
     *
     * @param obj     the object to be dumped
     * @param verbose if true, dump out the contents of octet and bit strings.
     * @return the resulting string.
     */
    public static JsonNode dumpAsString(
            Object obj,
            StringBuilder bld,
            boolean verbose) {
        ASN1Primitive primitive;
        if (obj instanceof ASN1Primitive) {
            primitive = (ASN1Primitive) obj;
        } else if (obj instanceof ASN1Encodable) {
            primitive = ((ASN1Encodable) obj).toASN1Primitive();
        } else {
            throw new RuntimeException("unknown object type " + obj.toString());
        }
        ObjectNode on = om.createObjectNode();
        return _dumpAsString("", verbose, primitive, bld);
    }

    private static String toStr(byte[] bytes) {
        try {
            return Util.carefulBytesToString(bytes);
        } catch (Exception e) {
            return "HEX: " + Strings.fromByteArray(Hex.encode(bytes));

        }
    }

    private static String dumpBinaryDataAsString(String indent, byte[] bytes) {
        String nl = Strings.lineSeparator();
        StringBuffer buf = new StringBuffer();

        indent += TAB;

        buf.append(nl);
        for (int i = 0; i < bytes.length; i += SAMPLE_SIZE) {
            if (bytes.length - i > SAMPLE_SIZE) {
                buf.append(indent);
                buf.append(Strings.fromByteArray(Hex.encode(bytes, i, SAMPLE_SIZE)));
                buf.append(TAB);
                buf.append(calculateAscString(bytes, i, SAMPLE_SIZE));
                buf.append(nl);
            } else {
                buf.append(indent);
                buf.append(Strings.fromByteArray(Hex.encode(bytes, i, bytes.length - i)));
                for (int j = bytes.length - i; j != SAMPLE_SIZE; j++) {
                    buf.append("  ");
                }
                buf.append(TAB);
                buf.append(calculateAscString(bytes, i, bytes.length - i));
                buf.append(nl);
            }
        }

        return buf.toString();
    }

    private static String calculateAscString(byte[] bytes, int off, int len) {
        StringBuffer buf = new StringBuffer();

        for (int i = off; i != off + len; i++) {
            if (bytes[i] >= ' ' && bytes[i] <= '~') {
                buf.append((char) bytes[i]);
            }
        }

        return buf.toString();
    }

    public static void main(String[] args) {
        for (int k = 0; k < 3; k++)
            try {
                PhaseTrack.start();
                try (ASN1InputStream ais = new ASN1InputStream(Util.create(Paths.get(args[0])))) {
                    int i = 0;
                    long len = 0;
                    StringBuilder buf = new StringBuilder(1024);
                    while (ais.available() > 0) {
                        ASN1Primitive obj = ais.readObject();
                        JsonNode jo = dumpAsString(obj, buf, true);
                        String prettyJson = om.writerWithDefaultPrettyPrinter().writeValueAsString(jo);
                        len += prettyJson.length();
//                    System.out.println(prettyJson);
//                    System.out.println("==============");
//                    System.out.println(buf.toString());
//                    System.out.println("\n\n\n");
                        buf.setLength(0);
                        i++;
                        if (i % 1000 == 0) {
                            PhaseTrack.recordTimePoint("" + i);
                        }
                    }
                    System.out.printf("recs: %d  len: %d\n", i, len);

                }
                PhaseTrack.recordTimePoint("done");
                PhaseTrack.logTimes("all times", Level.INFO, TimeUnit.MILLISECONDS);
            } catch (Exception e) {
                e.printStackTrace();
            }

    }

    public static int peekForTag(ASN1Primitive obj) {
        if (obj instanceof ASN1TaggedObject) {
            ASN1TaggedObject o = (ASN1TaggedObject) obj;
            return o.getTagNo();
        } else
            return -1;
    }
}

