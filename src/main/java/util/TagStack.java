package util;

import java.util.Arrays;
import java.util.stream.Collectors;

public final class TagStack {

    final static int LIMIT = 32;

    private final int[] stack = new int[32];
    int depth = 0;
    public TagStack() {
    }

    public void push(int i) {
        stack[depth] = i;
        depth++;
        if ( depth >= LIMIT)
            throw new RuntimeException("over pushed this stack past the limit: " + LIMIT);
    }

    public int pop() {
        int ret = stack[depth];
        depth--;
        if ( depth < 0 )
            throw new RuntimeException("over popped this stack");
        return ret;

    }

    public int peek() {
        if ( depth == 0 ) {
            return -1;
        } else {
            return stack[depth-1];
        }
    }
    @Override
    public String toString() {
        if ( depth == 0 )
            return "/";
        else
            return "/" + Arrays.stream(stack).limit(depth).mapToObj(i->String.valueOf(i)).collect(Collectors.joining("/"));
    }



//    LinkedList<Integer> stack = new LinkedList<>();
//
//
//    public void push(int i) {
//        stack.addLast(i);
//    }
//
//    public int pop() {
//        int i = stack.removeLast();
//        return i;
//    }
//
//    public int peek() {
//        if (stack.size() > 0) {
//            int i = stack.peekLast();
//            return i;
//        } else
//            return -1;
//
//    }

//    @Override
//    public String toString() {
//        return stack.stream().map(i -> String.valueOf(i)).collect(Collectors.joining("/"));
//    }

    public void clear() {
        depth=0;
    }

    public static void main(String[] args) {
        try {
            TagStack s = new TagStack();
            s.push(4);
            s.push(1);
            s.push(3);
            System.out.println(s);
            System.out.println(s.peek());
            System.out.println(s);
            s.pop();
            s.push(10);
            System.out.println(s);
            System.out.println(s.peek());
            System.out.println(s);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
