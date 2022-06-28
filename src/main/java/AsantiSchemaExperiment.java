import com.brightsparklabs.asanti.model.schema.AsnSchema;
import com.brightsparklabs.asanti.model.schema.AsnSchemaImpl;
import com.brightsparklabs.asanti.model.schema.AsnSchemaModule;
import com.brightsparklabs.asanti.model.schema.type.*;
import com.brightsparklabs.asanti.model.schema.typedefinition.AsnSchemaTypeDefinition;
import com.brightsparklabs.asanti.model.schema.typedefinition.AsnSchemaTypeDefinitionImpl;
import com.brightsparklabs.asanti.reader.AsnSchemaReader;
import com.google.common.base.Charsets;
import com.google.common.collect.ImmutableMap;
import com.google.common.io.CharSource;
import com.google.common.io.Files;
import util.Util;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.file.Path;
import java.util.Optional;
import java.util.stream.Collectors;

import static util.Util.getPrivateField;

public class AsantiSchemaExperiment {

    public static void main(String[] args) {
        try {
            final CharSource schemaFile = Files.asCharSource(new File("data/tas.asn"), Charsets.UTF_8);
            final AsnSchema schema = AsnSchemaReader.read(schemaFile);
            final AsnSchemaImpl schemaImpl = (AsnSchemaImpl) schema;
            String topTypeName = "MMTelRecord";

            Optional<AsnSchemaType> type = schema.getType(topTypeName);

            AsnSchemaType inner = type.get();

            SchemaNode node = new SchemaNode(null, false, -1, null);
            walk(node, topTypeName, inner, null, 0, true);
            System.out.println("================done");

            walkNodes(node, 0);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static SchemaNode createNodes(Path asnSchemaPath, String topTypeName, boolean logit) throws IOException {
        final CharSource schemaFile = Files.asCharSource(new File("data/tas.asn"), Charsets.UTF_8);
        final AsnSchema schema = AsnSchemaReader.read(schemaFile);

        Optional<AsnSchemaType> type = schema.getType(topTypeName);

        var inner = type.get();
        SchemaNode node = new SchemaNode(null, false, -1, null);
        walk(node, topTypeName, inner, null, 0, logit);
        return node;
    }

    public ImmutableMap<String, AsnSchemaTypeDefinition> getModuleTypeDef(AsnSchema schema) {
        final AsnSchemaImpl asnSchemaImp = (AsnSchemaImpl)schema;
        AsnSchemaModule asnSchemaModule = (AsnSchemaModule) getPrivateField(asnSchemaImp, "primaryModule");
        return (ImmutableMap<String, AsnSchemaTypeDefinition>) getPrivateField(asnSchemaModule, "types");
    }

     public static void walkNodes(SchemaNode node, int depth) {
        System.out.printf("%s%s tag: %d type: %s\n", ind(depth), node.fieldName, node.tagged, node.primAsnBuiltinType);
        System.out.printf("%sTagged Children: %d\n", ind(depth), node.children.size());
        for(var e: node.children.entrySet()) {
            System.out.printf("%s%d\n", ind(depth), e.getKey());
            walkNodes(e.getValue(), depth+1);
        }
        if ( node.choices.size() > 0) {
            System.out.printf("%sChoices only\n", ind(depth));
            for (var e : node.choices) {
                walkNodes(e, depth + 1);
            }
        }

    }

    public static void walk(SchemaNode node, String name, AsnSchemaType type, AsnSchemaComponentType parentCompType, int depth, boolean logit) {

        AsnSchemaTypePlaceholder holder = null;
        AsnSchemaTypeConstructed constructed = null;

        if ( type instanceof AsnSchemaTypePlaceholder)
            holder = (AsnSchemaTypePlaceholder) type;
        else if ( type instanceof AsnSchemaTypeConstructed )
            constructed = (AsnSchemaTypeConstructed) type;



        node.primAsnBuiltinType = type.getBuiltinType();
        boolean choice = false;
        boolean bottom = true;
        String en = "";
        switch (type.getBuiltinType()) {
            case Enumerated: {
//            System.out.println("hey");
                AsnSchemaTypeWithNamedTags tags = (AsnSchemaTypeWithNamedTags) holder.getIndirectType();
                String list = tags.getTagsToNamedValues()
                        .values()
                        .stream()
                        .map(asnSchemaNamedTag -> asnSchemaNamedTag.getTagName() + ":" + asnSchemaNamedTag.getTag())
                        .collect(Collectors.joining(","));
                en = " of (" + list + ") as " + holder.getTypeName();
                bottom=true;
            }
            break;
            case Set: {
                if (holder != null) {
                    en = " of " + holder.getTypeName();
                } else if (constructed != null ) {
                }
                bottom=false;

            }
            break;
            case SequenceOf: {
                if (holder != null) {
                    en = " " + holder.getTypeName();
                } else if (type instanceof AsnSchemaTypeConstructed) {
                }
                bottom=false;
            }
            case Sequence: {
                if (holder != null) {
                    en = " " + holder.getTypeName();
                } else if (type instanceof AsnSchemaTypeConstructed) {
                }
                bottom=false;
            }
            break;
            case Choice: {
                if (holder!=null) {
                    en = " choice defined inside of " + holder.getTypeName();
                } else if (type instanceof AsnSchemaTypeConstructed) {
                }
                choice = true;
                bottom=false;

            }
            break;
            default:
                break;
        }

        String optional = "";
        String tagNo = "";
        if ( parentCompType != null ) {
            if ( parentCompType.getTag() == null || parentCompType.getTag().equals(""))
                node.tagged = -1;
            else
                node.tagged = Integer.parseInt(parentCompType.getTag());
            tagNo = "[" + parentCompType.getTag() + "] ";
            if ( parentCompType.isOptional()) {
                optional = "OPTIONAL ";
                node.optional=true;
            }
        }
        node.fieldName = name;
        node.bottom = bottom;
        if ( logit )
            System.out.println(ind(depth) + name + ": " + type.getClass().getSimpleName() + " is "
                    + tagNo + optional + type.getBuiltinType() + en);
        for (int i = 0; i < type.getAllComponents().size(); i++) {
            AsnSchemaComponentType compType = type.getAllComponents().get(i);
            String subname = compType.getName();

            SchemaNode childnode = new SchemaNode(null, false, -1, node);
            node.addChild(childnode);
            walk(childnode, subname, compType.getType(), compType, depth + 1, logit);
            node.addChild(childnode);
            if ( childnode.tagged >= 0 ) {
                node.addTaggedChild(childnode.tagged, childnode);
            }
            if ( choice ) {
                node.addChoiceChild(childnode);
                if ( logit )
                    System.out.println("added child node with tag " + childnode.tagged);
            }
            if ( !choice && childnode.tagged < 0) {
                if ( logit )
                    System.out.println("Child never got tagged AND not just a choice: " + childnode.fieldName);
            }

            if (choice && i != type.getAllComponents().size() - 1)
                if ( logit )
                    System.out.println(ind(depth + 1) + "OR");
        }
//        node.auditTheseChildren();
    }

    public static void walk2(AsnSchemaImpl schema, String name, AsnSchemaType type, int depth) {
        if (type instanceof AsnSchemaTypeConstructed) {
            AsnSchemaTypeConstructed realtype = (AsnSchemaTypeConstructed) type;
//            realtype.accept()

        }


    }

    public static String ind(int depth) {
        return "    ".repeat(depth);
    }
}
