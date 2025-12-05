package com.packetanalyzer;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class WebAnalyzerServer {
    private static final int DEFAULT_PORT = 8080;
    private static final String ANALYZE_PATH = "/api/analyze";
    private static final String DOWNLOAD_PATH = "/download/";
    private static final Pattern SUMMARY_PATTERN = Pattern.compile("(?m)^\\s*(Total packets|Forwarded|Dropped|Active flows):\\s*(\\d+)");
    private static final Map<String, AnalysisSession> SESSIONS = new ConcurrentHashMap<>();

    private WebAnalyzerServer() {
    }

    public static void main(String[] args) throws IOException {
        int port = DEFAULT_PORT;
        String envPort = System.getenv("PORT");
        if (envPort != null && !envPort.isBlank()) {
            try {
                port = Integer.parseInt(envPort);
            } catch (NumberFormatException ignored) {
                port = DEFAULT_PORT;
            }
        }
        if (args.length > 0) {
            try {
                port = Integer.parseInt(args[0]);
            } catch (NumberFormatException ignored) {
                port = DEFAULT_PORT;
            }
        }

        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/", WebAnalyzerServer::handleIndex);
        server.createContext(ANALYZE_PATH, WebAnalyzerServer::handleAnalyze);
        server.createContext(DOWNLOAD_PATH, WebAnalyzerServer::handleDownload);
        server.setExecutor(Executors.newFixedThreadPool(4));
        server.start();

        System.out.println("Packet Analyzer web server started at http://localhost:" + port);
    }

    private static void handleIndex(HttpExchange exchange) throws IOException {
        if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendText(exchange, 405, "Method Not Allowed");
            return;
        }

        sendHtml(exchange, 200, INDEX_HTML);
    }

    private static void handleAnalyze(HttpExchange exchange) throws IOException {
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendText(exchange, 405, "Method Not Allowed");
            return;
        }

        Map<String, String> query = parseQuery(exchange.getRequestURI());
        String filename = query.getOrDefault("filename", "upload.pcap");
        boolean threaded = query.containsKey("threaded") && !query.get("threaded").isBlank();

        byte[] body;
        try (InputStream inputStream = exchange.getRequestBody()) {
            body = readAllBytes(inputStream);
        }

        Path tempInput = Files.createTempFile("packet-analyzer-input-", sanitizeSuffix(filename));
        Path tempOutput = Files.createTempFile("packet-analyzer-output-", ".pcap");
        Files.write(tempInput, body);

        ProcessResult result;
        try {
            result = runAnalyzer(tempInput, tempOutput, threaded, query);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            sendJson(exchange, 500, jsonError("Analysis interrupted", ex.getMessage()));
            return;
        } catch (IOException ex) {
            sendJson(exchange, 500, jsonError("Analysis failed", ex.getMessage()));
            return;
        }

        String sessionId = UUID.randomUUID().toString();
        AnalysisSession session = new AnalysisSession(
                sessionId,
                filename,
                tempInput,
                tempOutput,
                result.output(),
                result.exitCode(),
                Instant.now());
        SESSIONS.put(sessionId, session);

        AnalysisSummary summary = AnalysisSummary.from(result.output());
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("sessionId", sessionId);
        response.put("downloadUrl", "/download/" + sessionId);
        response.put("exitCode", result.exitCode());
        response.put("stdout", result.output());
        response.put("inputFile", filename);
        response.put("threaded", threaded);
        response.put("summary", summary.toMap());

        sendJson(exchange, 200, toJson(response));
    }

    private static void handleDownload(HttpExchange exchange) throws IOException {
        if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendText(exchange, 405, "Method Not Allowed");
            return;
        }

        String sessionId = exchange.getRequestURI().getPath().substring(DOWNLOAD_PATH.length());
        AnalysisSession session = SESSIONS.get(sessionId);
        if (session == null || !Files.exists(session.outputFile())) {
            sendText(exchange, 404, "Not Found");
            return;
        }

        Headers headers = exchange.getResponseHeaders();
        headers.set("Content-Type", "application/vnd.tcpdump.pcap");
        headers.set("Content-Disposition", "attachment; filename=filtered-" + sanitizeDownloadName(session.inputFile()) + ".pcap");

        long size = Files.size(session.outputFile());
        exchange.sendResponseHeaders(200, size);
        try (OutputStream outputStream = exchange.getResponseBody()) {
            Files.copy(session.outputFile(), outputStream);
        }
    }

    private static ProcessResult runAnalyzer(Path inputFile,
                                             Path outputFile,
                                             boolean threaded,
                                             Map<String, String> query) throws IOException, InterruptedException {
        List<String> command = new ArrayList<>();
        command.add(javaExecutable());
        command.add("-cp");
        command.add(System.getProperty("java.class.path"));
        command.add("com.packetanalyzer.PacketAnalyzerApp");
        if (threaded) {
            command.add("--threaded");
        }
        command.add(inputFile.toAbsolutePath().toString());
        command.add(outputFile.toAbsolutePath().toString());

        addRuleArgs(command, query.get("blockIp"), "--block-ip");
        addRuleArgs(command, query.get("blockApp"), "--block-app");
        addRuleArgs(command, query.get("blockDomain"), "--block-domain");

        ProcessBuilder builder = new ProcessBuilder(command);
        builder.redirectErrorStream(true);

        Process process = builder.start();
        String output;
        try (InputStream inputStream = process.getInputStream()) {
            output = new String(readAllBytes(inputStream), StandardCharsets.UTF_8);
        }

        int exitCode = process.waitFor();
        return new ProcessResult(exitCode, output);
    }

    private static void addRuleArgs(List<String> command, String rawValue, String optionName) {
        if (rawValue == null || rawValue.isBlank()) {
            return;
        }

        for (String value : splitValues(rawValue)) {
            command.add(optionName);
            command.add(value);
        }
    }

    private static List<String> splitValues(String rawValue) {
        if (rawValue == null || rawValue.isBlank()) {
            return Collections.emptyList();
        }

        String[] parts = rawValue.split(",");
        List<String> values = new ArrayList<>(parts.length);
        for (String part : parts) {
            String trimmed = part.trim();
            if (!trimmed.isEmpty()) {
                values.add(trimmed);
            }
        }
        return values;
    }

    private static Map<String, String> parseQuery(URI uri) {
        Map<String, String> values = new HashMap<>();
        String rawQuery = uri.getRawQuery();
        if (rawQuery == null || rawQuery.isBlank()) {
            return values;
        }

        for (String pair : rawQuery.split("&")) {
            int equals = pair.indexOf('=');
            if (equals < 0) {
                values.put(decode(pair), "");
            } else {
                values.put(decode(pair.substring(0, equals)), decode(pair.substring(equals + 1)));
            }
        }
        return values;
    }

    private static String decode(String value) {
        return URLDecoder.decode(value, StandardCharsets.UTF_8);
    }

    private static void sendHtml(HttpExchange exchange, int status, String html) throws IOException {
        sendResponse(exchange, status, html, "text/html; charset=utf-8");
    }

    private static void sendJson(HttpExchange exchange, int status, String json) throws IOException {
        sendResponse(exchange, status, json, "application/json; charset=utf-8");
    }

    private static void sendText(HttpExchange exchange, int status, String text) throws IOException {
        sendResponse(exchange, status, text, "text/plain; charset=utf-8");
    }

    private static void sendResponse(HttpExchange exchange, int status, String content, String contentType) throws IOException {
        byte[] bytes = content.getBytes(StandardCharsets.UTF_8);
        Headers headers = exchange.getResponseHeaders();
        headers.set("Content-Type", contentType);
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream outputStream = exchange.getResponseBody()) {
            outputStream.write(bytes);
        }
    }

    private static byte[] readAllBytes(InputStream inputStream) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int read;
        while ((read = inputStream.read(buffer)) != -1) {
            outputStream.write(buffer, 0, read);
        }
        return outputStream.toByteArray();
    }

    private static String jsonError(String error, String details) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("error", error);
        payload.put("details", details == null ? "" : details);
        return toJson(payload);
    }

    private static String toJson(Map<String, Object> values) {
        StringBuilder builder = new StringBuilder();
        builder.append('{');
        boolean first = true;
        for (Map.Entry<String, Object> entry : values.entrySet()) {
            if (!first) {
                builder.append(',');
            }
            first = false;
            builder.append('"').append(escapeJson(entry.getKey())).append('"').append(':');
            appendJsonValue(builder, entry.getValue());
        }
        builder.append('}');
        return builder.toString();
    }

    private static void appendJsonValue(StringBuilder builder, Object value) {
        if (value == null) {
            builder.append("null");
        } else if (value instanceof String string) {
            builder.append('"').append(escapeJson(string)).append('"');
        } else if (value instanceof Number || value instanceof Boolean) {
            builder.append(value);
        } else if (value instanceof Map<?, ?> map) {
            builder.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (!first) {
                    builder.append(',');
                }
                first = false;
                builder.append('"').append(escapeJson(String.valueOf(entry.getKey()))).append('"').append(':');
                appendJsonValue(builder, entry.getValue());
            }
            builder.append('}');
        } else if (value instanceof List<?> list) {
            builder.append('[');
            boolean first = true;
            for (Object item : list) {
                if (!first) {
                    builder.append(',');
                }
                first = false;
                appendJsonValue(builder, item);
            }
            builder.append(']');
        } else {
            builder.append('"').append(escapeJson(String.valueOf(value))).append('"');
        }
    }

    private static String escapeJson(String value) {
        StringBuilder builder = new StringBuilder(value.length() + 16);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> builder.append("\\\"");
                case '\\' -> builder.append("\\\\");
                case '\b' -> builder.append("\\b");
                case '\f' -> builder.append("\\f");
                case '\n' -> builder.append("\\n");
                case '\r' -> builder.append("\\r");
                case '\t' -> builder.append("\\t");
                default -> {
                    if (c < 0x20) {
                        builder.append(String.format("\\u%04x", (int) c));
                    } else {
                        builder.append(c);
                    }
                }
            }
        }
        return builder.toString();
    }

    private static String sanitizeSuffix(String filename) {
        String base = filename == null ? "upload" : filename;
        int dot = base.lastIndexOf('.');
        if (dot >= 0) {
            base = base.substring(0, dot);
        }
        base = base.replaceAll("[^a-zA-Z0-9._-]", "_");
        if (base.isBlank()) {
            base = "upload";
        }
        return "." + base + ".pcap";
    }

    private static String sanitizeDownloadName(String filename) {
        String name = filename == null ? "upload" : filename;
        name = name.replaceAll("[^a-zA-Z0-9._-]", "_");
        if (name.isBlank()) {
            name = "upload";
        }
        return name;
    }

    private static String javaExecutable() {
        String javaHome = System.getProperty("java.home");
        Path javaBin = Path.of(javaHome, "bin", isWindows() ? "java.exe" : "java");
        if (Files.exists(javaBin)) {
            return javaBin.toString();
        }
        return "java";
    }

    private static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase().contains("win");
    }

    private record ProcessResult(int exitCode, String output) {
    }

    private record AnalysisSession(String sessionId,
                                   String inputFile,
                                   Path inputPath,
                                   Path outputFile,
                                   String stdout,
                                   int exitCode,
                                   Instant createdAt) {
    }

    private record AnalysisSummary(long totalPackets,
                                   long forwarded,
                                   long dropped,
                                   long activeFlows) {
        static AnalysisSummary from(String stdout) {
            return new AnalysisSummary(
                    extractLong(stdout, "Total packets"),
                    extractLong(stdout, "Forwarded"),
                    extractLong(stdout, "Dropped"),
                    extractLong(stdout, "Active flows"));
        }

        Map<String, Long> toMap() {
            Map<String, Long> values = new LinkedHashMap<>();
            values.put("totalPackets", totalPackets);
            values.put("forwarded", forwarded);
            values.put("dropped", dropped);
            values.put("activeFlows", activeFlows);
            return values;
        }
    }

    private static long extractLong(String stdout, String label) {
        Matcher matcher = SUMMARY_PATTERN.matcher(stdout);
        while (matcher.find()) {
            if (label.equals(matcher.group(1))) {
                try {
                    return Long.parseLong(matcher.group(2));
                } catch (NumberFormatException ex) {
                    return 0L;
                }
            }
        }
        return 0L;
    }

        private static final String INDEX_HTML = """
                        <!doctype html>
                        <html lang="en">
                        <head>
                            <meta charset="utf-8" />
                            <meta name="viewport" content="width=device-width, initial-scale=1" />
                            <meta name="color-scheme" content="light dark" />
                            <title>Packet Analyzer</title>
                            <style>
                                :root {
                                    --bg: #f5f7fb;
                                    --bg-soft: rgba(255, 255, 255, 0.75);
                                    --panel: rgba(255, 255, 255, 0.86);
                                    --panel-strong: rgba(255, 255, 255, 0.96);
                                    --line: rgba(15, 23, 42, 0.08);
                                    --text: #0f172a;
                                    --muted: #5b6b84;
                                    --accent: #0f766e;
                                    --accent-2: #2563eb;
                                    --accent-3: #7c3aed;
                                    --danger: #dc2626;
                                    --shadow: 0 20px 60px rgba(15, 23, 42, 0.10);
                                    --chip: rgba(37, 99, 235, 0.08);
                                    --console: #0b1020;
                                    --console-text: #e8eefc;
                                }
                                :root[data-theme="dark"] {
                                    --bg: #07111f;
                                    --bg-soft: rgba(8, 15, 28, 0.8);
                                    --panel: rgba(10, 18, 34, 0.82);
                                    --panel-strong: rgba(14, 24, 44, 0.92);
                                    --line: rgba(148, 163, 184, 0.16);
                                    --text: #e5eefb;
                                    --muted: #8aa0bf;
                                    --accent: #2dd4bf;
                                    --accent-2: #60a5fa;
                                    --accent-3: #a78bfa;
                                    --danger: #fb7185;
                                    --shadow: 0 26px 90px rgba(0, 0, 0, 0.36);
                                    --chip: rgba(96, 165, 250, 0.12);
                                    --console: #050b16;
                                    --console-text: #d9e8ff;
                                }
                                * { box-sizing: border-box; }
                                html { color-scheme: light; }
                                html[data-theme="dark"] { color-scheme: dark; }
                                body {
                                    margin: 0;
                                    min-height: 100vh;
                                    color: var(--text);
                                    font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
                                    background:
                                        radial-gradient(circle at top left, rgba(45, 212, 191, 0.18), transparent 28%),
                                        radial-gradient(circle at top right, rgba(37, 99, 235, 0.18), transparent 24%),
                                        linear-gradient(135deg, var(--bg) 0%, color-mix(in srgb, var(--bg) 88%, white 12%) 100%);
                                    transition: background 180ms ease, color 180ms ease;
                                }
                                .shell { max-width: 1160px; margin: 0 auto; padding: 28px 18px 42px; }
                                .topbar {
                                    display: flex; align-items: center; justify-content: space-between; gap: 16px;
                                    margin-bottom: 20px;
                                }
                                .brand {
                                    display: flex; align-items: center; gap: 12px;
                                }
                                .mark {
                                    width: 42px; height: 42px; border-radius: 14px;
                                    background: linear-gradient(135deg, var(--accent), var(--accent-2));
                                    box-shadow: var(--shadow);
                                }
                                .brand h1 { margin: 0; font-size: 1rem; letter-spacing: 0.04em; text-transform: uppercase; }
                                .brand p { margin: 3px 0 0; color: var(--muted); font-size: 0.92rem; }
                                .toolbar { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
                                .button, button, .button-link {
                                    appearance: none; border: 0; cursor: pointer; text-decoration: none;
                                    display: inline-flex; align-items: center; justify-content: center; gap: 8px;
                                    min-height: 44px; padding: 0 16px; border-radius: 14px; font-weight: 700;
                                    transition: transform 140ms ease, box-shadow 140ms ease, background 140ms ease, color 140ms ease;
                                }
                                .button:hover, button:hover, .button-link:hover { transform: translateY(-1px); }
                                .button.primary, button.primary { color: white; background: linear-gradient(135deg, var(--accent), var(--accent-2)); box-shadow: var(--shadow); }
                                .button.secondary, .button-link, button.secondary { color: var(--text); background: var(--bg-soft); border: 1px solid var(--line); backdrop-filter: blur(16px); }
                                .hero {
                                    display: grid; grid-template-columns: 1.35fr 0.65fr; gap: 18px; margin-bottom: 18px;
                                }
                                .card {
                                    background: var(--panel); border: 1px solid var(--line); border-radius: 26px;
                                    box-shadow: var(--shadow); backdrop-filter: blur(16px);
                                }
                                .hero-main { padding: 28px; }
                                .eyebrow {
                                    display: inline-flex; align-items: center; gap: 8px; padding: 7px 12px;
                                    border-radius: 999px; background: var(--chip); color: var(--accent-2);
                                    font-size: 12px; letter-spacing: 0.08em; text-transform: uppercase; margin-bottom: 16px;
                                }
                                h2 { margin: 0; font-size: clamp(2.2rem, 4.8vw, 4rem); line-height: 1.02; letter-spacing: -0.05em; }
                                /* Prevent horizontal overflow */
                                html, body { overflow-x: hidden; }
                                .hero { align-items: start; }
                                /* Let the heading wrap naturally and never force a single long line */
                                .hero h2, .hero h2 .hero-title {
                                    white-space: normal !important;
                                    display: block;
                                    max-width: 100%;
                                    box-sizing: border-box;
                                }
                                /* Use deliberate line breaks instead of awkward word splits */
                                .hero h2 {
                                    font-size: clamp(1.6rem, 4.2vw, 3.4rem);
                                    max-width: min(1100px, calc(100% - 260px));
                                    line-height: 1.04;
                                    overflow-wrap: normal;
                                    word-break: normal;
                                    hyphens: manual;
                                }
                                .hero h2 .hero-title-line {
                                    display: block;
                                }
                                /* Ensure the toolbar doesn't overlap the title on narrow viewports */
                                .toolbar { z-index: 3; }
                                @media (min-width: 1200px) {
                                    .hero h2 { font-size: clamp(1.8rem, 3.4vw, 3.8rem); max-width: min(1200px, calc(100% - 260px)); }
                                }
                                @media (max-width: 980px) {
                                    .hero h2 { max-width: 100%; }
                                }
                                .hero h2 .hero-title {
                                    white-space: normal;
                                }
                                .lead { margin: 14px 0 0; max-width: 68ch; color: var(--muted); line-height: 1.7; font-size: 1.03rem; }
                                .hero-side { padding: 16px; display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }
                                .stat { padding: 18px; border-radius: 20px; background: var(--panel-strong); border: 1px solid var(--line); }
                                .stat .k { color: var(--muted); font-size: 12px; letter-spacing: 0.08em; text-transform: uppercase; }
                                .stat .v { margin-top: 8px; font-size: 1.25rem; font-weight: 800; }
                                .main { display: grid; grid-template-columns: 1fr 1fr; gap: 18px; }
                                .panel { padding: 22px; }
                                .section-title { margin: 0 0 14px; font-size: 1.02rem; }
                                .grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 14px; }
                                .field { display: flex; flex-direction: column; gap: 8px; }
                                label { color: var(--muted); font-size: 12px; letter-spacing: 0.08em; text-transform: uppercase; }
                                input[type="file"], input[type="text"] {
                                    width: 100%; padding: 13px 14px; border-radius: 14px; color: var(--text);
                                    border: 1px solid var(--line); background: var(--panel-strong);
                                    outline: none;
                                }
                                input[type="file"]::file-selector-button {
                                    margin-right: 14px; border: 0; border-radius: 11px; padding: 10px 12px; font-weight: 800;
                                    color: white; background: linear-gradient(135deg, var(--accent), var(--accent-2)); cursor: pointer;
                                }
                                input:focus { box-shadow: 0 0 0 4px color-mix(in srgb, var(--accent-2) 18%, transparent); }
                                .switches { display: flex; flex-wrap: wrap; gap: 14px; margin-top: 14px; align-items: center; }
                                .switch { display: inline-flex; align-items: center; gap: 8px; color: var(--text); }
                                .actions { display: flex; gap: 12px; flex-wrap: wrap; margin-top: 18px; }
                                .status {
                                    margin-top: 14px; min-height: 24px; color: var(--muted);
                                }
                                .status.error { color: var(--danger); }
                                .results {
                                    display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 14px; margin: 18px 0;
                                }
                                .result {
                                    padding: 18px; border-radius: 20px; background: var(--panel);
                                    border: 1px solid var(--line);
                                }
                                .result .k { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.08em; }
                                .result .v { margin-top: 8px; font-size: 1.75rem; font-weight: 800; }
                                .console-card { padding: 22px; }
                                pre {
                                    margin: 0; min-height: 320px; max-height: 520px; overflow: auto;
                                    padding: 18px; border-radius: 18px; border: 1px solid var(--line);
                                    background: var(--console); color: var(--console-text); line-height: 1.55; font-size: 13px;
                                    white-space: pre-wrap; word-break: break-word;
                                }
                                .meta {
                                    display: flex; gap: 10px; flex-wrap: wrap; margin-top: 12px;
                                }
                                .chip {
                                    padding: 8px 12px; border-radius: 999px; border: 1px solid var(--line);
                                    background: var(--bg-soft); color: var(--muted); font-size: 13px;
                                }
                                .hidden { display: none !important; }
                                .progress-bar {
                                    height: 3px; background: var(--line); border-radius: 999px; margin: 14px 0;
                                    overflow: hidden; display: none;
                                }
                                .progress-bar.active { display: block; }
                                .progress-bar .fill {
                                    height: 100%; background: linear-gradient(90deg, var(--accent), var(--accent-2));
                                    width: 0%; animation: progress 2.4s ease-in-out forwards;
                                }
                                @keyframes progress {
                                    0% { width: 0%; }
                                    50% { width: 70%; }
                                    100% { width: 100%; }
                                }
                                .dropzone {
                                    position: relative; border: 2px dashed var(--line); border-radius: 18px;
                                    padding: 18px; text-align: center; color: var(--muted); font-size: 14px;
                                    cursor: pointer; transition: all 180ms ease; background: transparent;
                                }
                                .dropzone:hover, .dropzone.dragover {
                                    border-color: var(--accent-2); background: var(--chip); color: var(--accent-2);
                                }
                                .dropzone input[type="file"] { display: none; }
                                /* Responsive adjustments */
                                @media (max-width: 980px) {
                                    .hero { grid-template-columns: 1fr; gap: 12px; }
                                    .main { grid-template-columns: 1fr; gap: 12px; }
                                    .grid { grid-template-columns: 1fr; gap: 12px; }
                                    .results { grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }
                                    .hero-side { grid-template-columns: 1fr; }
                                    h2 { font-size: clamp(1.6rem, 5.5vw, 2.6rem); line-height: 1.08; }
                                    .shell { padding: 20px 14px 32px; }
                                }
                                @media (max-width: 620px) {
                                    .results { grid-template-columns: 1fr; }
                                    .result { padding: 14px; }
                                    .card { border-radius: 18px; }
                                    h2 { font-size: clamp(1.4rem, 6.2vw, 2.1rem); }
                                    pre { min-height: 220px; max-height: 360px; }
                                    .mark { width: 36px; height: 36px; }
                                    .brand h1 { font-size: 0.95rem; }
                                    .toolbar { gap: 8px; }
                                    .shell { padding: 14px 12px 22px; }
                                }
                            </style>
                        </head>
                        <body>
                            <div class="shell">
                                <div class="topbar">
                                    <div class="brand">
                                       
                                        <div>
                                            <h1>Packet Analyzer</h1>
                                            
                                        </div>
                                    </div>
                                    <div class="toolbar">
                                        <button id="themeBtn" class="button secondary" type="button" aria-label="Toggle theme" title="Toggle theme"><span id="themeIcon" aria-hidden="true">☀</span></button>
                                        <a class="button secondary" href="/" title="Reload page">Refresh</a>
                                    </div>
                                </div>

                                <section class="hero">
                                    
                                        
                                        <h2>
                                            <span class="hero-title">
                                                <span class="hero-title-line">Upload a PCAP,</span>
                                                <span class="hero-title-line">set rules, and see</span>
                                                <span class="hero-title-line">the filtered result instantly.</span>
                                            </span>
                                        </h2>
                                        
                                    
                                    
                                </section>

                                <div class="results">
                                    <div class="result"><div class="k">Packets</div><div class="v" id="totalPackets">-</div></div>
                                    <div class="result"><div class="k">Forwarded</div><div class="v" id="forwardedPackets">-</div></div>
                                    <div class="result"><div class="k">Dropped</div><div class="v" id="droppedPackets">-</div></div>
                                    <div class="result"><div class="k">Flows</div><div class="v" id="activeFlows">-</div></div>
                                </div>

                                <section class="main">
                                    <div class="card panel">
                                        <h3 class="section-title">Analyze capture</h3>
                                        <div class="dropzone" id="dropzone">
                                            <input id="pcapFile" type="file" accept=".pcap,.cap,.pcapng" />
                                            <p style="margin: 0;">📤 Drop your PCAP file here or <span style="color: var(--accent-2); font-weight: 700; text-decoration: underline; cursor: pointer;">click to upload</span></p>
                                            <p style="margin: 6px 0 0; font-size: 12px; color: var(--muted);" id="fileName">No file chosen</p>
                                        </div>
                                        <div class="progress-bar" id="progressBar"><div class="fill"></div></div>
                                        <div class="grid" style="margin-top: 14px;">
                                            <div class="field"><label for="blockIp">Blocked IPs</label><input id="blockIp" type="text" placeholder="192.168.1.50, 10.0.0.8" /></div>
                                            <div class="field"><label for="blockApp">Blocked apps</label><input id="blockApp" type="text" placeholder="YouTube, TikTok" /></div>
                                            <div class="field"><label for="blockDomain">Blocked domains</label><input id="blockDomain" type="text" placeholder="facebook, tiktok" /></div>
                                            <div class="field"><label>&nbsp;</label><label class="switch"><input id="threaded" type="checkbox" /> Run threaded analyzer</label></div>
                                        </div>

                                        <div class="actions">
                                            <button id="analyzeBtn" class="primary" type="button">Analyze capture</button>
                                            <a id="downloadLink" class="button-link hidden" href="#">Download filtered PCAP</a>
                                        </div>

                                        <div id="status" class="status">Ready.</div>
                                        <div class="meta">
                                            <span class="chip" id="sessionChip">Session: -</span>
                                            <span class="chip" id="exitChip">Exit code: -</span>
                                        </div>
                                    </div>

                                    <div class="card console-card">
                                        <h3 class="section-title">Analyzer output</h3>
                                        <pre id="console">No analysis yet.</pre>
                                    </div>
                                </section>
                            </div>

                            <script>
                                const analyzeBtn = document.getElementById('analyzeBtn');
                                const pcapFile = document.getElementById('pcapFile');
                                const blockIp = document.getElementById('blockIp');
                                const blockApp = document.getElementById('blockApp');
                                const blockDomain = document.getElementById('blockDomain');
                                const threaded = document.getElementById('threaded');
                                const status = document.getElementById('status');
                                const consoleBox = document.getElementById('console');
                                const downloadLink = document.getElementById('downloadLink');
                                const themeBtn = document.getElementById('themeBtn');
                                const themeIcon = document.getElementById('themeIcon');
                                const themeStat = document.getElementById('themeStat');
                                const sessionChip = document.getElementById('sessionChip');
                                const exitChip = document.getElementById('exitChip');
                                const dropzone = document.getElementById('dropzone');
                                const fileName = document.getElementById('fileName');
                                const progressBar = document.getElementById('progressBar');

                                const storageKey = 'packet-analyzer-theme';

                                function setStatus(text, isError = false) {
                                    status.textContent = text;
                                    status.classList.toggle('error', isError);
                                }

                                function applyTheme(theme) {
                                    document.documentElement.dataset.theme = theme;
                                    localStorage.setItem(storageKey, theme);
                                    if (themeStat) {
                                        themeStat.textContent = theme === 'dark' ? 'Dark' : 'Light';
                                    }
                                    themeIcon.textContent = theme === 'dark' ? '☀' : '☾';
                                    themeBtn.setAttribute('aria-label', theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode');
                                    themeBtn.setAttribute('title', theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode');
                                }

                                function currentTheme() {
                                    const saved = localStorage.getItem(storageKey);
                                    if (saved === 'dark' || saved === 'light') {
                                        return saved;
                                    }
                                    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
                                }

                                function updateResults(summary) {
                                    document.getElementById('totalPackets').textContent = summary.totalPackets ?? '-';
                                    document.getElementById('forwardedPackets').textContent = summary.forwarded ?? '-';
                                    document.getElementById('droppedPackets').textContent = summary.dropped ?? '-';
                                    document.getElementById('activeFlows').textContent = summary.activeFlows ?? '-';
                                }

                                themeBtn.addEventListener('click', () => {
                                    applyTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark');
                                });

                                applyTheme(currentTheme());
                                threaded.checked = false;

                                function showProgress(show) {
                                    if (show) {
                                        progressBar.classList.add('active');
                                    } else {
                                        progressBar.classList.remove('active');
                                    }
                                }

                                dropzone.addEventListener('click', () => pcapFile.click());
                                dropzone.addEventListener('dragover', (e) => {
                                    e.preventDefault();
                                    dropzone.classList.add('dragover');
                                });
                                dropzone.addEventListener('dragleave', () => {
                                    dropzone.classList.remove('dragover');
                                });
                                dropzone.addEventListener('drop', (e) => {
                                    e.preventDefault();
                                    dropzone.classList.remove('dragover');
                                    const files = e.dataTransfer.files;
                                    if (files.length > 0) {
                                        pcapFile.files = files;
                                        fileName.textContent = `Selected: ${files[0].name}`;
                                        analyzeBtn.click();
                                    }
                                });

                                pcapFile.addEventListener('change', (e) => {
                                    if (e.target.files.length > 0) {
                                        fileName.textContent = `Selected: ${e.target.files[0].name}`;
                                    } else {
                                        fileName.textContent = 'No file chosen';
                                    }
                                });

                                analyzeBtn.addEventListener('click', async () => {
                                    const file = pcapFile.files[0];
                                    if (!file) {
                                        setStatus('Choose a PCAP file first.', true);
                                        return;
                                    }

                                    analyzeBtn.disabled = true;
                                    downloadLink.classList.add('hidden');
                                    showProgress(true);
                                    setStatus('Uploading and analyzing capture...');
                                    consoleBox.textContent = 'Processing...';
                                    sessionChip.textContent = 'Session: -';
                                    exitChip.textContent = 'Exit code: -';

                                    try {
                                        const params = new URLSearchParams();
                                        params.set('filename', file.name);
                                        if (blockIp.value.trim()) params.set('blockIp', blockIp.value.trim());
                                        if (blockApp.value.trim()) params.set('blockApp', blockApp.value.trim());
                                        if (blockDomain.value.trim()) params.set('blockDomain', blockDomain.value.trim());
                                        if (threaded.checked) params.set('threaded', 'true');

                                        const response = await fetch(`/api/analyze?${params.toString()}`, {
                                            method: 'POST',
                                            headers: { 'Content-Type': 'application/octet-stream' },
                                            body: await file.arrayBuffer()
                                        });

                                        const payload = await response.json();
                                        if (!response.ok || payload.error) {
                                            throw new Error(payload.details || payload.error || `Request failed (${response.status})`);
                                        }

                                        consoleBox.textContent = payload.stdout || '';
                                        updateResults(payload.summary || {});
                                        sessionChip.textContent = `Session: ${payload.sessionId.substring(0, 8)}`;
                                        exitChip.textContent = `Exit code: ${payload.exitCode}`;
                                        downloadLink.href = payload.downloadUrl;
                                        downloadLink.classList.remove('hidden');
                                        setStatus('Analysis complete. Download the filtered PCAP or try another file.');
                                    } catch (error) {
                                        setStatus(error.message || 'Analysis failed.', true);
                                        consoleBox.textContent = String(error.stack || error);
                                    } finally {
                                        showProgress(false);
                                        analyzeBtn.disabled = false;
                                    }
                                });
                            </script>
                        </body>
                        </html>
                        """;
}
