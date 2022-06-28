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

import java.io.File;
import java.lang.reflect.Field;
import java.util.Optional;
import java.util.stream.Collectors;

public class DumpByModuleDefinition {
    public static ImmutableMap<String, AsnSchemaTypeDefinition> typeDefs=null;
    public static void main(String[] args) {
        try {
            final CharSource schemaFile = Files.asCharSource(new File("data/tas.asn"), Charsets.UTF_8);
            final AsnSchema schema = AsnSchemaReader.read(schemaFile);

            Optional<AsnSchemaType> type = schema.getType("MMTelRecord");

            var thing = schema.getType("MMTelChargingDataTypes");

            final AsnSchemaImpl asnSchemaImp = (AsnSchemaImpl) schema;
            AsnSchemaModule asnSchemaModule = (AsnSchemaModule) getPrivateField(asnSchemaImp, "primaryModule");
            typeDefs = (ImmutableMap<String, AsnSchemaTypeDefinition>) getPrivateField(asnSchemaModule, "types");

            for (var e : typeDefs.entrySet()) {
                AsnSchemaTypeDefinitionImpl schemaTypeDefinition = (AsnSchemaTypeDefinitionImpl) e.getValue();
                System.out.println("Major type: " + schemaTypeDefinition.getName());
                walk(schemaTypeDefinition.getName(), schemaTypeDefinition.getType(), null, 0, true);
                System.out.println("\n\n");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    public static Object getPrivateField(Object obj, String fieldName) {
        try {
            Field field = obj.getClass().getDeclaredField(fieldName);
            field.setAccessible(true);
            Object value = field.get(obj);
            return value;
        } catch (NoSuchFieldException | IllegalAccessException e) {
            throw new RuntimeException(e);
        }
    }

    public static void walk(String name, AsnSchemaType type, AsnSchemaComponentType parentCompType, int depth, boolean logit) {

        AsnSchemaTypePlaceholder holder = null;
        AsnSchemaTypeConstructed constructed = null;

        if (type instanceof AsnSchemaTypePlaceholder)
            holder = (AsnSchemaTypePlaceholder) type;
        else if (type instanceof AsnSchemaTypeConstructed)
            constructed = (AsnSchemaTypeConstructed) type;


        boolean choice = false;
        boolean bottom = true;
        String en = "";
        switch (type.getBuiltinType()) {
            case Enumerated: {
                // getting the "typename" here is redundant at depth = 0;
                AsnSchemaTypeWithNamedTags tags = null;
                String enTypeName = "n/a";
                if (holder != null) {
                    tags = (AsnSchemaTypeWithNamedTags) holder.getIndirectType();
                    enTypeName = holder.getTypeName().toString();
                } else {
                    tags = (AsnSchemaTypeWithNamedTags) type;
                }
                if (tags != null) {
                    String list = tags.getTagsToNamedValues()
                            .values()
                            .stream()
                            .map(asnSchemaNamedTag -> asnSchemaNamedTag.getTagName() + ":" + asnSchemaNamedTag.getTag())
                            .collect(Collectors.joining(","));
                    if ( depth > 0)
                        en = " of (" + list + ") as " + enTypeName;
                    else
                        en = " of (" + list + ")";
                } else {
                    System.out.println("what - no tag in here at all???");
                }
                bottom = true;
            }
            break;
            case Set: {
                if (holder != null) {
                    en = " of " + holder.getTypeName();
                } else if (constructed != null) {
                }
                bottom = false;

            }
            break;
            case SequenceOf: {
                if (holder != null) {
                    en = " " + holder.getTypeName();
                } else if (type instanceof AsnSchemaTypeConstructed) {
                }
                bottom = false;
            }
            case Sequence: {
                if (holder != null) {
                    en = " " + holder.getTypeName();
                } else if (type instanceof AsnSchemaTypeConstructed) {
                }
                bottom = false;
            }
            break;
            case Choice: {
                if (holder != null) {
                    en = " choice defined inside of " + holder.getTypeName();
                } else if (type instanceof AsnSchemaTypeConstructed) {
                }
                choice = true;
                bottom = false;

            }
            break;
            default:
                break;
        }

        String optional = "";
        String tagNo = "";
        if (parentCompType != null) {
            tagNo = "[" + parentCompType.getTag() + "] ";
            if (parentCompType.isOptional()) {
                optional = "OPTIONAL ";
            }
        }
        if (logit)
            System.out.println(ind(depth) + name + ": " + type.getClass().getSimpleName() + " is "
                    + tagNo + optional + type.getBuiltinType() + en);
        for (int i = 0; i < type.getAllComponents().size(); i++) {
            AsnSchemaComponentType compType = type.getAllComponents().get(i);
            String subname = compType.getName();

            if ( typeDefs.containsKey(subname)) {
                System.out.println(ind(depth) + name + ": defined elsewhere");
            } else {
                walk(subname, compType.getType(), compType, depth + 1, logit);
            }
            if (choice && i != type.getAllComponents().size() - 1)
                if (logit)
                    System.out.println(ind(depth + 1) + "OR");
        }
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