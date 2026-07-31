import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

/** Runnable JAR bootstrap for the Python APK Analyzer application. */
public final class ApkAnalyzerLauncher {
    private ApkAnalyzerLauncher() {}

    public static void main(String[] args) {
        Path runtimeDir = null;
        int exitCode = 1;
        try {
            List<String> python = findPython3();
            if (python == null) {
                throw new IOException("Python 3.8 or newer was not found on PATH");
            }

            runtimeDir = Files.createTempDirectory("apkanalyzer-");
            Path script = extract("/apkAnalyzer.py", runtimeDir.resolve("apkAnalyzer.py"));
            extract(
                "/frida_scripts/universal_bypass.js",
                runtimeDir.resolve("frida_scripts").resolve("universal_bypass.js")
            );

            List<String> command = new ArrayList<String>(python);
            command.add(script.toString());
            command.addAll(Arrays.asList(args));

            ProcessBuilder builder = new ProcessBuilder(command);
            builder.directory(new java.io.File(System.getProperty("user.dir")));
            builder.environment().put("PYTHONUTF8", "1");
            builder.inheritIO();
            exitCode = builder.start().waitFor();
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
            System.err.println("APK Analyzer was interrupted.");
            exitCode = 130;
        } catch (IOException error) {
            System.err.println("Could not start APK Analyzer: " + error.getMessage());
            exitCode = 1;
        } finally {
            if (runtimeDir != null) {
                deleteTree(runtimeDir);
            }
        }
        System.exit(exitCode);
    }

    private static Path extract(String resource, Path destination) throws IOException {
        Files.createDirectories(destination.getParent());
        InputStream input = ApkAnalyzerLauncher.class.getResourceAsStream(resource);
        if (input == null) {
            throw new IOException("JAR resource is missing: " + resource);
        }
        try {
            Files.copy(input, destination, StandardCopyOption.REPLACE_EXISTING);
        } finally {
            input.close();
        }
        return destination;
    }

    private static List<String> findPython3() {
        List<List<String>> candidates = new ArrayList<List<String>>();
        String configured = System.getenv("APKANALYZER_PYTHON");
        if (configured != null && !configured.trim().isEmpty()) {
            candidates.add(Arrays.asList(configured.trim()));
        }
        candidates.add(Arrays.asList("python3"));
        candidates.add(Arrays.asList("python"));
        if (System.getProperty("os.name", "").toLowerCase().contains("win")) {
            candidates.add(Arrays.asList("py", "-3"));
        }

        for (List<String> candidate : candidates) {
            List<String> probe = new ArrayList<String>(candidate);
            probe.add("-c");
            probe.add("import sys; raise SystemExit(0 if sys.version_info >= (3, 8) else 1)");
            try {
                Process process = new ProcessBuilder(probe)
                    .redirectErrorStream(true)
                    .start();
                if (process.waitFor(10, TimeUnit.SECONDS) && process.exitValue() == 0) {
                    return new ArrayList<String>(candidate);
                }
                process.destroyForcibly();
            } catch (IOException ignored) {
                // Try the next common interpreter name.
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                return null;
            }
        }
        return null;
    }

    private static void deleteTree(Path root) {
        try (Stream<Path> paths = Files.walk(root)) {
            paths.sorted(Comparator.reverseOrder()).forEach(path -> {
                try {
                    Files.deleteIfExists(path);
                } catch (IOException ignored) {
                    // Temporary files are best-effort cleanup only.
                }
            });
        } catch (IOException ignored) {
            // Temporary files are best-effort cleanup only.
        }
    }
}
