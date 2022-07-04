package asanti;

import com.brightsparklabs.asanti.Asanti;
import com.brightsparklabs.asanti.model.data.RawAsnData;
import com.google.common.base.Charsets;
import com.google.common.collect.ImmutableList;
import com.google.common.io.ByteSink;
import com.google.common.io.ByteSource;
import com.google.common.io.CharSource;
import com.google.common.io.Files;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.checkerframework.checker.units.qual.C;
import picocli.CommandLine;
import util.Util;

import java.io.BufferedWriter;
import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Optional;
import java.util.Set;

public class ExpRaw {
    public static class Cli {

        @CommandLine.Option(names = {"-f", "--ber_files"}, arity = "1..*", required = true,
                description = "files to decode")
        java.nio.file.Path[] files;

//        @CommandLine.Option(names = {"-s", "--asn1_schema_path"},
//                description = "location of the asn1 schema file")
//        Path asnSchemaFile;
//
//        @CommandLine.Option(names = {"-t", "--topname_from_schema"},
//                description = "top name to get from the schema to map")
//        String asnTopName;
//        @CommandLine.Option(names = {"-x", "--hex_also"},
//                description = "always write hex with decodable strings")
//        boolean hexAlso;
//        @CommandLine.Option(names = {"-i", "--index_list"}, arity = "0..*",
//                description = "write only some of the records, starting index is 1 - e.g. -i 100 2000 3001")
//        Set<Integer> writeOnly;
//
//        @CommandLine.Option(names = {"-d", "--debug_info"}, defaultValue = "false",
//                description = "during processing write tags paths and final type")
//        boolean debug;
//
        @CommandLine.Option(names = {"-h",
                "--help"}, usageHelp = true, description = "display this help message\nsample cmdline: java -cp hdfs_du2-1.0-SNAPSHOT.jar:lib/* org.HdfsDu2 /prod test --krb5_user adm_sflanag1@HDPQUANTUMPROD.COM --krb5_key_tab /etc/security/keytabs/adm_sflanag1.user.keytab")
        boolean usageHelpRequested;
    }

    public static void main(String[] args) {
        Cli cli = new Cli();
        try {
            CommandLine cl = new CommandLine(cli);
            cl.parseArgs(args);
            if (cli.usageHelpRequested) {
                cl.usage(System.err);
                return;
            }
        } catch (Exception e) {
            System.err.println("cli related exception: " + e);
            return;
        }

        try {
            try(BufferedWriter wr = Files.newWriter(Paths.get("data/asanti.txt").toFile(),Charsets.UTF_8)) {
                for (var p : cli.files) {
                    wr.write(p.toString() + "\n");
                    final ByteSource byteSource = Files.asByteSource(p.toFile());
                    final ImmutableList<RawAsnData> allRawAsnData = Asanti.readAsnBerData(byteSource);
                    var i = allRawAsnData.stream().iterator();
                    int recno = 0;
                    while (i.hasNext()) {
                        var data = i.next();
                        recno++;
                        wr.write("R# " + recno + "\n");
                        for (var tag : data.getRawTags()) {
                            Optional<byte[]> field = data.getBytes(tag);
                            if (field.isEmpty())
                                wr.write(tag + " = empty\n");
                            else
                                wr.write(tag + " = " + toStr(field.get()) + "\n");
                        }
//                    if ( recno > 3)
//                        System.exit(1);
                    }

                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static String toStr(byte[] bytes) {
        try {
            String s = Util.carefulBytesToString(bytes);
            return s;
        } catch (Exception e) {
            return "HEX: " + Strings.fromByteArray(Hex.encode(bytes));

        }
    }

}
