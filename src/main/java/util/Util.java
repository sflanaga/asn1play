package util;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.luben.zstd.ZstdInputStream;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.concurrent.TimeUnit;
import java.util.zip.GZIPInputStream;

import static com.google.common.io.BaseEncoding.base16;

public class Util {
    public static BufferedInputStream create(Path path) throws IOException {
        FileInputStream is = new FileInputStream(path.toFile());
        System.out.println(path);
        if (path.toString().endsWith(".gz")) {
            return new BufferedInputStream(new GZIPInputStream(is));
        } else if (path.getFileName().endsWith(".zst")) {
            return new BufferedInputStream(new ZstdInputStream(is));
        } else {
            return new BufferedInputStream(is);
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

    public final static ObjectMapper jom = new ObjectMapper();

    public static ObjectMapper jom() { return jom; };

    static final CharsetDecoder utf8DecoderChecked = StandardCharsets.UTF_8
            .newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT);
    public static String carefulBytesToString(byte[] ray) {
        try {
            String s= utf8DecoderChecked.decode(ByteBuffer.wrap(ray)).toString();
            for (int i = 0; i < s.length(); i++) {
                int c = s.codePointAt(i);
                if ( Character.isISOControl(c))
                    return "hex[" + ray.length + "]: " + base16().encode(ray);
            }
            return s;
            // return new String(ray, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("Cannot safely decode message to UTF-8, byte array hex: " + base16().encode(ray), e);
        }
    }
    public static String toSIAbbreviation(final TimeUnit timeUnit) {
        if (timeUnit == null) {
            return "";
        }
        switch (timeUnit) {
            case DAYS:
                return "d";
            case HOURS:
                return "h";
            case MINUTES:
                return "min";
            case SECONDS:
                return "s";
            case MILLISECONDS:
                return "ms";
            case MICROSECONDS:
                return "\u03BCs"; // lower-greek-mu
            case NANOSECONDS:
                return "ns";
            default:
                return timeUnit.name();
        }
    }

    public static long convert(Duration dur, TimeUnit units) {
        switch(units) {
            case NANOSECONDS:
                return dur.toNanos();
            case MICROSECONDS:
                return dur.toMillis()/1000L;
            case MILLISECONDS:
                return dur.toMillis();
            case SECONDS:
                return dur.getSeconds();
            case MINUTES:
                return dur.toMinutes();
            case HOURS:
                return dur.toHours();
            case DAYS:
                return dur.toDays();
            default:
                throw new RuntimeException("Time unit not supported");
        }
    }


}
