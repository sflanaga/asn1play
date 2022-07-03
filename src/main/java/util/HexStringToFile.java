package util;

import java.nio.file.Files;
import java.nio.file.Paths;

public class HexStringToFile {

    static String s = "30308011 00FFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FF810646 616C636F 6E830100 A4048002 4650A50A 0C034361 720C0347 5053";

    public static byte[] hexStringToBytes(String str) {
        byte[] val = new byte[str.length() / 2];

        for (int i = 0; i < val.length; i++) {
            int index = i * 2;
            int j = Integer.parseInt(str.substring(index, index + 2), 16);
            val[i] = (byte) j;
        }
        return val;
    }

    public static void main(String[] args) {
        try {
            s = s.replace(" ", "");
            var b = hexStringToBytes(s);
            System.out.println(s);
            Files.write(Paths.get("data/sample.ber"), b);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
