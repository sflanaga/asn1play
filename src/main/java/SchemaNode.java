import com.brightsparklabs.asanti.schema.AsnBuiltinType;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;

public class SchemaNode {

    protected AsnBuiltinType primAsnBuiltinType;
    protected String fieldName;
    protected boolean bottom;
    protected int tagged;
    protected HashMap<Integer, String> enumDef = null;
    protected HashMap<Integer, SchemaNode> children;
    protected HashMap<String, SchemaNode> auditChild;
    protected ArrayList<SchemaNode> choices;
    protected SchemaNode parent;
    protected boolean optional;


    SchemaNode(AsnBuiltinType primAsnBuiltinType, boolean bottom, int tagged, SchemaNode parent) {
        this.primAsnBuiltinType = primAsnBuiltinType;
        this.bottom = bottom;
        this.tagged = tagged;
        this.parent = parent;
        this.optional = false;
        children = new HashMap<>();
        this.fieldName = "";
        auditChild = new HashMap<>();
        choices = new ArrayList<>();
    }

    public void addChild(SchemaNode node) {
        auditChild.put(node.fieldName, node);
    }

    public void addChoiceChild(SchemaNode node) {
        choices.add(node);
    }

    public void addTaggedChild(int tagged, SchemaNode node) {
        if (children.containsKey(tagged))
            System.out.println("duplicate tagged child skipped: " + tagged + " named: " + node.fieldName);
        else
            children.put(tagged, node);
    }

    public void auditTheseChildren() {
        for (var e : auditChild.entrySet()) {
            if (!children.containsKey(e.getValue().tagged))
                throw new RuntimeException("audit child field: " + e.getValue().fieldName + " not in map by tag list");
        }
        for (var e : children.entrySet()) {
            if (!auditChild.containsKey(e.getValue().fieldName))
                throw new RuntimeException("tag/mapped child field: " + e.getValue().fieldName + " not in map by tag list");
        }
    }

    public SchemaNode find(int[] path) {
        SchemaNode here = this;
        while ( here.parent != null) {
            here = here.parent;
        }
        SchemaNode next = here;
        for (int i = 0; i < path.length; i++) {
            int tag = path[i];
            next = next.children.get(tag);
            if ( next == null )
                throw new RuntimeException("Cannot find path: " + Arrays.toString(path) + " at " + i);
        }
        return next;
    }

    public boolean isTagged() {
        if ( this.tagged>=0 )
            return true;
        else
            return false;
    }

    public SchemaNode getTaggedParent() {
        if ( this.parent==null) {
            return this;
        }
        SchemaNode here = this;
        while(!here.isTagged()) {
            here = here.parent;
        }
        return here;
    }
}
