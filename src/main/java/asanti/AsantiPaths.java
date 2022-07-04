package asanti;

import com.brightsparklabs.asanti.model.schema.AsnSchema;
import com.brightsparklabs.asanti.model.schema.type.AsnSchemaComponentType;
import com.brightsparklabs.asanti.model.schema.type.AsnSchemaType;
import com.brightsparklabs.asanti.reader.AsnSchemaReader;
import com.brightsparklabs.asanti.schema.AsnBuiltinType;
import com.google.common.base.Charsets;
import com.google.common.io.CharSource;
import com.google.common.io.Files;
import util.TagStack;

import java.io.File;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Optional;

import static util.Util.isEmpty;

public class AsantiPaths {

    public static class FieldInfo {
        public final AsnSchemaType asantiType;
        public final AsnBuiltinType builtinType;

        public final String fieldName;
        public final FieldInfo parent;

        public FieldInfo(FieldInfo parent, AsnBuiltinType builtinType, String fieldName, AsnSchemaType type) {
            this.parent = parent;
            this.builtinType = builtinType;
            this.fieldName = fieldName;
            this.asantiType = type;
        }

        @Override
        public String toString() {
            FieldInfo pfi = this.parent;
            ArrayList<FieldInfo> lineage = new ArrayList<>();
            while( pfi != null ) {
                lineage.add(pfi);
                pfi = pfi.parent;
            }
            String parentPath = "";
            for (int i = lineage.size()-1; i >= 0; i--) {
                parentPath += "/" + lineage.get(i).fieldName;
            }
//            StringBuilder parent = new StringBuilder(32);
            return parentPath + "/" + fieldName + "," + builtinType.toString();
        }
    }


    public static LinkedHashMap<String, FieldInfo> createParsingSchema(Path schemaPath, String topFieldName) {
        try {
            final CharSource charSource = Files.asCharSource(schemaPath.toFile(), Charsets.UTF_8);
            final AsnSchema schema = AsnSchemaReader.read(charSource);

            Optional<AsnSchemaType> oType = schema.getType(topFieldName);

            var type = oType.get();

            LinkedHashMap<String, FieldInfo> map = new LinkedHashMap<>();
            TagStack tagStack = new TagStack();
            walk(type, tagStack, topFieldName, null, map, false, 0);

//            for(var e: map.entrySet()) {
//                System.out.println(e.getKey() + "  " + e.getValue());
//            }
            return map;
        } catch (Exception e) {
           throw new RuntimeException("unable to process schema: " + e.getMessage(), e);
        }
    }

    private static void walk(AsnSchemaType type, TagStack tagStack, String fieldName, FieldInfo parent, LinkedHashMap<String, FieldInfo> map, boolean b, int depth) {
        var t = type.getBuiltinType();
        FieldInfo fieldInfo = null;
        if ( depth > 0 ) {
            fieldInfo = new FieldInfo(parent, t, fieldName, type);
            map.put(tagStack.toString(), fieldInfo);
        }


        for (int i = 0; i < type.getAllComponents().size(); i++) {
            AsnSchemaComponentType compType = type.getAllComponents().get(i);
            String subFieldName = compType.getName();
            String strTag = compType.getTag();
            if ( subFieldName.equals("gPRS-Charging-Id"))
                System.out.println("");
            int tag = -1;
            if (!isEmpty(strTag))
                tag = Integer.parseInt(strTag);

            if ( tag >= 0 )
                tagStack.push(tag);
            walk(compType.getType(), tagStack, subFieldName, fieldInfo, map, false, depth + 1);
            if ( tag >= 0 )
                tagStack.pop();
        }
    }
}
