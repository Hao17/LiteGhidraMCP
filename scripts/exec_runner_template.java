import ghidra.app.script.GhidraScript;
import java.io.*;

public class {CLASS_NAME} extends GhidraScript {

    @Override
    public void run() throws Exception {
        String resultPath = getScriptArgs()[0];
        StringBuilder stdout = new StringBuilder();
        PrintStream origOut = System.out;

        // Redirect System.out to capture println output
        System.setOut(new PrintStream(new OutputStream() {
            @Override
            public void write(int b) throws IOException {
                stdout.append((char) b);
                origOut.write(b);
            }
            @Override
            public void write(byte[] b, int off, int len) throws IOException {
                stdout.append(new String(b, off, len));
                origOut.write(b, off, len);
            }
        }));

        try {
            // ===== USER CODE BEGIN =====
            {USER_CODE}
            // ===== USER CODE END =====

            System.setOut(origOut);
            writeResult(resultPath, true, stdout.toString(), null, null);
        } catch (Exception e) {
            System.setOut(origOut);
            writeResult(resultPath, false, stdout.toString(), e.getMessage(), stackTrace(e));
        }
    }

    private void writeResult(String path, boolean success, String out, String error, String tb) throws IOException {
        try (PrintWriter w = new PrintWriter(new FileWriter(path))) {
            w.print("{");
            w.print("\"success\":" + success);
            if (out != null) {
                w.print(",\"stdout\":" + jsonStr(out));
            }
            if (error != null) {
                w.print(",\"error\":" + jsonStr(error));
            }
            if (tb != null) {
                w.print(",\"traceback\":" + jsonStr(tb));
            }
            w.print("}");
        }
    }

    private String jsonStr(String s) {
        if (s == null) return "null";
        StringBuilder sb = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':  sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\b': sb.append("\\b");  break;
                case '\f': sb.append("\\f");  break;
                case '\n': sb.append("\\n");  break;
                case '\r': sb.append("\\r");  break;
                case '\t': sb.append("\\t");  break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        sb.append("\"");
        return sb.toString();
    }

    private String stackTrace(Exception e) {
        StringWriter sw = new StringWriter();
        e.printStackTrace(new PrintWriter(sw));
        return sw.toString();
    }
}
