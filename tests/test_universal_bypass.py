import json
import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "frida_scripts" / "universal_bypass.js"


NODE_PROBE_HARNESS = r"""
const fs = require("fs");
const vm = require("vm");

const payload = JSON.parse(fs.readFileSync(0, "utf8"));
const logs = [];

function mockPointer(value) {
    return {
        isNull: function () { return Number(value) === 0; },
        toString: function () { return "0x" + Number(value).toString(16); }
    };
}

const sandbox = {
    console: {
        log: function (value) { logs.push(String(value)); }
    },
    ptr: mockPointer,
    Process: {
        id: 4242,
        arch: "arm64",
        platform: "linux",
        pointerSize: 8,
        findModuleByName: function () { return null; },
        findModuleByAddress: function () { return null; },
        enumerateModules: function () { return []; }
    },
    Module: {},
    Interceptor: {
        attach: function () {},
        replace: function () {}
    },
    NativeCallback: function (callback) { return callback; },
    NativeFunction: function () { return function () {}; },
    Memory: {},
    rpc: { exports: {} },
    setImmediate: payload.runStartup ?
        function (callback) { callback(); } : function () {}
};

vm.runInNewContext(
    payload.source + "\n" + payload.probe,
    sandbox,
    { filename: "universal_bypass.js" }
);
process.stdout.write(JSON.stringify({ result: sandbox.__result, logs: logs }));
"""


class UniversalBypassTests(unittest.TestCase):
    def run_javascript_probe(self, probe, run_startup=False):
        node = shutil.which("node")
        if not node:
            self.skipTest("Node.js is unavailable")
        payload = {
            "source": SCRIPT.read_text(encoding="utf-8"),
            "probe": probe,
            "runStartup": run_startup,
        }
        result = subprocess.run(
            [node, "-e", NODE_PROBE_HARNESS],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_script_is_valid_utf8_and_has_no_target_specific_patches(self):
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('const VERSION = "2.1.0"', source)
        self.assertIn("Module.findGlobalExportByName", source)
        self.assertIn("Process.attachModuleObserver", source)
        for obsolete in (
            "CRASH_OFFSET",
            "libvosWrapperEx",
            "Memory.patchCode",
            "ARM64_RET",
            "Interceptor.replace(pAbort",
        ):
            self.assertNotIn(obsolete, source)

    def test_javascript_syntax(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("Node.js is unavailable")
        result = subprocess.run(
            [node, "--check", str(SCRIPT)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_native_only_startup_reports_readiness(self):
        output = self.run_javascript_probe(
            r"""
            globalThis.__result = status();
            """,
            run_startup=True,
        )
        self.assertEqual(output["result"]["version"], "2.1.0")
        self.assertTrue(output["result"]["nativeReady"])
        self.assertEqual(output["result"]["javaState"], "unavailable")
        self.assertEqual(output["result"]["nativeErrors"], 0)
        self.assertEqual(output["result"]["javaErrors"], 0)

    def test_suspicious_command_matching_respects_token_boundaries(self):
        output = self.run_javascript_probe(
            r"""
            globalThis.__result = {
                surfaceflinger: isSuspiciousCommand(
                    "ls /system/bin/surfaceflinger"
                ),
                suspend: isSuspiciousCommand("/system/bin/suspend --help"),
                echoSu: isSuspiciousCommand("echo su"),
                su: isSuspiciousCommand("su -c id"),
                whichSu: isSuspiciousCommand("which su"),
                normalizedSu: isSuspiciousCommand(
                    "ls /system/bin/../bin/su"
                ),
                shellWrapped: isSuspiciousCommand(
                    "echo ok; sh -c 'command -v su'"
                ),
                ifTest: isSuspiciousCommand(
                    "if test -x /system/xbin/su; then echo rooted; fi"
                ),
                ifBracket: isSuspiciousCommand(
                    "if [ -x /system/xbin/su ]; then echo rooted; fi"
                ),
                doubleBracket: isSuspiciousCommand(
                    "if [[ -x /system/xbin/su ]]; then echo rooted; fi"
                ),
                subshell: isSuspiciousCommand(
                    "(test -x /system/xbin/su)"
                ),
                commandSubstitution: isSuspiciousCommand(
                    "echo $(test -x /system/xbin/su)"
                ),
                quotedCommandSubstitution: isSuspiciousCommand(
                    "echo \"$(test -x /system/xbin/su)\""
                ),
                bracketCommandSubstitution: isSuspiciousCommand(
                    "if [ \"$(which su)\" ]; then echo rooted; fi"
                ),
                backtickSubstitution: isSuspiciousCommand(
                    "echo `test -x /system/xbin/su`"
                ),
                escapedSubstitution: isSuspiciousCommand(
                    "echo \\$(which su)"
                ),
                singleQuotedSubstitution: isSuspiciousCommand(
                    "echo '$(which su)'"
                ),
                arithmeticExpansion: isSuspiciousCommand(
                    "echo $((su + 1))"
                ),
                shellComment: isSuspiciousCommand(
                    "echo ok # harmless; su"
                ),
                substitutionInComment: isSuspiciousCommand(
                    "echo ok # $(which su)"
                ),
                quotedData: isSuspiciousCommand(
                    "printf '%s' 'harmless; su | which su && su'"
                ),
                quotedPipe: isSuspiciousCommand(
                    "echo \"harmless | su && which su\""
                ),
                escapedSemicolon: isSuspiciousCommand(
                    "echo harmless\\; su"
                ),
                assignedSu: isSuspiciousCommand("MODE=test su -c id"),
                javaEcho: isSuspiciousCommandParts(["echo", "su"], 0),
                envSu: isSuspiciousCommandParts(
                    ["env", "MODE=test", "/system/xbin/su"], 0
                ),
                qemuProperty: isSuspiciousCommandParts(
                    ["getprop", "ro.kernel.qemu"], 0
                ),
                ordinaryProperty: isSuspiciousCommandParts(
                    ["getprop", "ro.product.model"], 0
                )
            };
            """
        )
        self.assertEqual(
            output["result"],
            {
                "surfaceflinger": False,
                "suspend": False,
                "echoSu": False,
                "su": True,
                "whichSu": True,
                "normalizedSu": True,
                "shellWrapped": True,
                "ifTest": True,
                "ifBracket": True,
                "doubleBracket": True,
                "subshell": True,
                "commandSubstitution": True,
                "quotedCommandSubstitution": True,
                "bracketCommandSubstitution": True,
                "backtickSubstitution": True,
                "escapedSubstitution": False,
                "singleQuotedSubstitution": False,
                "arithmeticExpansion": False,
                "shellComment": False,
                "substitutionInComment": False,
                "quotedData": False,
                "quotedPipe": False,
                "escapedSemicolon": False,
                "assignedSu": True,
                "javaEcho": False,
                "envSu": True,
                "qemuProperty": True,
                "ordinaryProperty": False,
            },
        )

    def test_verifier_hook_preserves_java_return_types(self):
        output = self.run_javascript_probe(
            """
            let implementationFactory = null;
            hookJavaOverloads = function (_className, _methodName, factory) {
                implementationFactory = factory;
                return 1;
            };
            hookSuccessfulVerifier("Verifier", "verify", "accepted");

            function invoke(returnType) {
                const implementation = implementationFactory({
                    returnType: { className: returnType }
                });
                return implementation();
            }

            globalThis.__result = {
                booleanResult: invoke("boolean"),
                voidIsUndefined: invoke("void") === undefined,
                versionedPackage: packageNameFromQuery({
                    $className: "android.content.pm.VersionedPackage",
                    getPackageName: function () {
                        return "com.topjohnwu.magisk";
                    }
                })
            };
            """
        )
        self.assertEqual(
            output["result"],
            {
                "booleanResult": True,
                "voidIsUndefined": True,
                "versionedPackage": "com.topjohnwu.magisk",
            },
        )

    def test_module_scoped_export_lookup_does_not_use_global_collision(self):
        output = self.run_javascript_probe(
            """
            let globalLookups = 0;
            let moduleLookups = 0;
            Process.findModuleByName = function () {
                return {
                    findExportByName: function () {
                        moduleLookups++;
                        return null;
                    }
                };
            };
            Module.findGlobalExportByName = function () {
                globalLookups++;
                return { toString: function () { return "0xdead"; } };
            };
            delete Module.findExportByName;
            const result = findExport("target_export", "missing.so");
            globalThis.__result = {
                missing: result === null,
                moduleLookups: moduleLookups,
                globalLookups: globalLookups
            };
            """
        )
        self.assertEqual(
            output["result"],
            {"missing": True, "moduleLookups": 1, "globalLookups": 0},
        )

    def test_unloaded_module_listeners_are_detached_and_can_be_rehooked(self):
        output = self.run_javascript_probe(
            """
            function numericPointer(value) {
                return {
                    value: value,
                    add: function(offset) { return numericPointer(value + offset); },
                    compare: function(other) {
                        return value === other.value ? 0 : (value < other.value ? -1 : 1);
                    },
                    toString: function () { return "0x" + value.toString(16); }
                };
            }
            let detached = 0;
            STATE.listeners.inside = {
                address: numericPointer(0x1100),
                listener: { detach: function () { detached++; } }
            };
            STATE.listeners.outside = {
                address: numericPointer(0x3000),
                listener: { detach: function () { detached++; } }
            };
            STATE.attached.inside = true;
            STATE.attached.outside = true;
            STATE.nativeHooks = 2;

            detachNativeHooksInModule({ base: numericPointer(0x1000), size: 0x1000 });
            globalThis.__result = {
                detached: detached,
                insideListenerRemoved: !STATE.listeners.inside,
                insideKeyRemoved: !STATE.attached.inside,
                outsideListenerRetained: !!STATE.listeners.outside,
                outsideKeyRetained: !!STATE.attached.outside,
                nativeHooks: STATE.nativeHooks
            };
            """
        )
        self.assertEqual(
            output["result"],
            {
                "detached": 1,
                "insideListenerRemoved": True,
                "insideKeyRemoved": True,
                "outsideListenerRetained": True,
                "outsideKeyRetained": True,
                "nativeHooks": 1,
            },
        )

    def test_x509_verify_cert_only_rewrites_verification_failure(self):
        output = self.run_javascript_probe(
            """
            const verifyAddress = {
                toString: function () { return "0x1234"; }
            };
            let verifyCallbacks = null;
            Interceptor.attach = function (address, callbacks) {
                if (address === verifyAddress) verifyCallbacks = callbacks;
            };
            const sslModule = {
                name: "libssl-test.so",
                findExportByName: function (name) {
                    return name === "X509_verify_cert" ? verifyAddress : null;
                }
            };
            installNativeTlsHooksForModule(sslModule);

            function runResult(initial) {
                const replacements = [];
                verifyCallbacks.onLeave({
                    toInt32: function () { return initial; },
                    replace: function (value) { replacements.push(value); }
                });
                return replacements;
            }

            globalThis.__result = {
                callbackInstalled: verifyCallbacks !== null,
                internalError: runResult(-1),
                rejected: runResult(0),
                accepted: runResult(1)
            };
            """
        )
        self.assertEqual(
            output["result"],
            {
                "callbackInstalled": True,
                "internalError": [],
                "rejected": [1],
                "accepted": [],
            },
        )

    def test_frida_port_probe_is_blocked_without_calling_connect(self):
        output = self.run_javascript_probe(
            """
            let replacementFactory = null;
            replaceAt = function (_label, _address, _returnType, _args, factory) {
                replacementFactory = factory;
                return true;
            };
            findExport = function () {
                return { toString: function () { return "0x9876"; } };
            };
            isApplicationAddress = function (address) {
                return address === "app";
            };

            installFridaPortConcealment();
            let originalCalls = 0;
            const replacement = replacementFactory(function () {
                originalCalls++;
                return 73;
            });

            function ipv4(port, firstOctet) {
                const bytes = [
                    (port >> 8) & 0xff,
                    port & 0xff,
                    firstOctet,
                    0,
                    0,
                    1
                ];
                return {
                    isNull: function () { return false; },
                    readU16: function () { return 2; },
                    add: function (offset) {
                        return {
                            readU8: function () { return bytes[offset - 2]; }
                        };
                    }
                };
            }

            const blockedContext = { returnAddress: "app", errno: 0 };
            const blocked = replacement.call(
                blockedContext, 4, ipv4(27042, 127), 16
            );
            const ordinary = replacement.call(
                { returnAddress: "app", errno: 0 }, 4, ipv4(443, 127), 16
            );
            const platform = replacement.call(
                { returnAddress: "platform", errno: 0 },
                4,
                ipv4(27042, 127),
                16
            );

            globalThis.__result = {
                blocked: blocked,
                blockedErrno: blockedContext.errno,
                ordinary: ordinary,
                platform: platform,
                originalCalls: originalCalls
            };
            """
        )
        self.assertEqual(
            output["result"],
            {
                "blocked": -1,
                "blockedErrno": 111,
                "ordinary": 73,
                "platform": 73,
                "originalCalls": 2,
            },
        )

    def test_java_frida_port_and_system_app_origin_detection(self):
        output = self.run_javascript_probe(
            """
            function endpoint(port, loopback, host) {
                return {
                    getPort: function () { return port; },
                    getAddress: function () {
                        return {
                            isLoopbackAddress: function () { return loopback; }
                        };
                    },
                    getHostString: function () { return host; }
                };
            }
            Process.findModuleByAddress = function (address) {
                return { path: address };
            };
            globalThis.__result = {
                loopbackFrida: isBlockedJavaSocketAddress(
                    endpoint(27042, true, "localhost")
                ),
                ordinaryPort: isBlockedJavaSocketAddress(
                    endpoint(443, true, "localhost")
                ),
                remoteFridaPort: isBlockedJavaSocketAddress(
                    endpoint(27042, false, "example.com")
                ),
                dataApp: isApplicationAddress(
                    "/data/app/com.example/lib/arm64/libtarget.so"
                ),
                systemApp: isApplicationAddress(
                    "/system/priv-app/Settings/lib/arm64/libtarget.so"
                ),
                platformLibrary: isApplicationAddress(
                    "/system/lib64/libandroid_runtime.so"
                )
            };
            """
        )
        self.assertEqual(
            output["result"],
            {
                "loopbackFrida": True,
                "ordinaryPort": False,
                "remoteFridaPort": False,
                "dataApp": True,
                "systemApp": True,
                "platformLibrary": False,
            },
        )

    def test_native_termination_includes_sigterm(self):
        output = self.run_javascript_probe(
            """
            const replacements = {};
            findExport = function (name) {
                return { toString: function () { return name; } };
            };
            replaceAt = function (label, _address, _returnType, _args, factory) {
                let calls = 0;
                replacements[label] = {
                    invoke: factory(function () {
                        calls++;
                        return 73;
                    }),
                    calls: function () { return calls; }
                };
                return true;
            };
            installNativeTerminationHooks();
            globalThis.__result = {
                selfSigterm: replacements.kill.invoke(SELF_PID, 15),
                otherSigterm: replacements.kill.invoke(SELF_PID + 1, 15),
                raiseSigterm: replacements.raise.invoke(15),
                raiseInterrupt: replacements.raise.invoke(2),
                killOriginalCalls: replacements.kill.calls(),
                raiseOriginalCalls: replacements.raise.calls()
            };
            """
        )
        self.assertEqual(
            output["result"],
            {
                "selfSigterm": 0,
                "otherSigterm": 73,
                "raiseSigterm": 0,
                "raiseInterrupt": 73,
                "killOriginalCalls": 1,
                "raiseOriginalCalls": 1,
            },
        )

    def test_native_command_probes_do_not_spawn_a_shell_or_pipe(self):
        output = self.run_javascript_probe(
            """
            const replacements = {};
            attachExport = function () { return true; };
            findExport = function (name) {
                return { toString: function () { return name; } };
            };
            replaceAt = function (label, _address, _returnType, _args, factory) {
                let calls = 0;
                replacements[label] = {
                    invoke: factory(function () {
                        calls++;
                        return 73;
                    }),
                    calls: function () { return calls; }
                };
                return true;
            };
            function nativeString(value) {
                return {
                    isNull: function () { return false; },
                    readByteArray: function (limit) {
                        const bytes = new Uint8Array(limit);
                        for (let i = 0; i < value.length && i < limit - 1; i++) {
                            bytes[i] = value.charCodeAt(i);
                        }
                        bytes[Math.min(value.length, limit - 1)] = 0;
                        if (value.length + 1 < limit) bytes[value.length + 1] = 0xff;
                        return bytes.buffer;
                    }
                };
            }

            installNativeFileHooks();
            installNativeCommandHooks();
            const systemBlocked = replacements["root-command:system"].invoke(
                nativeString("which su")
            );
            const systemAllowed = replacements["root-command:system"].invoke(
                nativeString("echo su")
            );
            const popenContext = { errno: 0 };
            const popenBlocked = replacements["root-command:popen"].invoke.call(
                popenContext,
                nativeString("/system/bin/su -c id"),
                nativeString("r")
            );

            globalThis.__result = {
                systemBlocked: systemBlocked,
                systemAllowed: systemAllowed,
                systemOriginalCalls: replacements["root-command:system"].calls(),
                popenBlockedIsNull: popenBlocked.isNull(),
                popenErrno: popenContext.errno,
                popenOriginalCalls: replacements["root-command:popen"].calls()
            };
            """
        )
        self.assertEqual(
            output["result"],
            {
                "systemBlocked": 127 << 8,
                "systemAllowed": 73,
                "systemOriginalCalls": 1,
                "popenBlockedIsNull": True,
                "popenErrno": 2,
                "popenOriginalCalls": 0,
            },
        )

    def test_java_proc_reads_are_tracked_without_broad_framework_tracking(self):
        output = self.run_javascript_probe(
            """
            const callbacks = {};
            attachExport = function (name, handlers) {
                callbacks[name] = handlers;
                return true;
            };
            Process.findModuleByAddress = function (address) {
                return address && address.moduleName ? {
                    name: address.moduleName,
                    path: address.modulePath || ("/apex/test/" + address.moduleName)
                } : null;
            };
            function nativePath(value) {
                return {
                    isNull: function () { return false; },
                    readByteArray: function (limit) {
                        const bytes = new Uint8Array(limit);
                        for (let i = 0; i < value.length && i < limit - 1; i++) {
                            bytes[i] = value.charCodeAt(i);
                        }
                        bytes[Math.min(value.length, limit - 1)] = 0;
                        return bytes.buffer;
                    }
                };
            }
            trackProcOpen("open", 0);

            function invoke(moduleName, fd) {
                const context = {
                    returnAddress: {
                        moduleName: moduleName,
                        modulePath: "/apex/com.android.art/lib64/" + moduleName
                    }
                };
                callbacks.open.onEnter.call(context, [nativePath("/proc/self/maps")]);
                callbacks.open.onLeave.call(context, {
                    toInt32: function () { return fd; }
                });
                return !!PROC_FDS[fd];
            }

            globalThis.__result = {
                openJdk: invoke("libopenjdk.so", 41),
                javaCore: invoke("libjavacore.so", 42),
                unrelatedFramework: invoke("libart.so", 43)
            };
            """
        )
        self.assertEqual(
            output["result"],
            {"openJdk": True, "javaCore": True, "unrelatedFramework": False},
        )

    def test_logging_escapes_terminal_controls_and_bounds_output(self):
        output = self.run_javascript_probe(
            r"""
            log("!\n\x1b", "line1\nline2\r\t\x1b\x07\u202eend");
            log("+", "\x1b".repeat(MAX_LOG_CHARS + 50));
            globalThis.__result = { maxLogChars: MAX_LOG_CHARS };
            """
        )
        hostile_line, bounded_line = output["logs"]

        for line in output["logs"]:
            self.assertFalse(
                any(
                    ord(character) <= 0x1F
                    or 0x7F <= ord(character) <= 0x9F
                    or ord(character) in {
                        0x200E,
                        0x200F,
                        0x2028,
                        0x2029,
                        *range(0x202A, 0x202F),
                        *range(0x2066, 0x206A),
                    }
                    for character in line
                ),
                repr(line),
            )

        for escaped in (r"\n", r"\r", r"\t", r"\x1b", r"\x07", r"\u202e"):
            self.assertIn(escaped, hostile_line)

        max_log_chars = output["result"]["maxLogChars"]
        self.assertEqual(bounded_line.count(r"\x1b"), max_log_chars)
        self.assertTrue(bounded_line.endswith("…"))
        self.assertLessEqual(len(bounded_line), (max_log_chars * 4) + 32)

    def test_read_c_string_scans_to_nul_with_a_finite_byte_limit(self):
        output = self.run_javascript_probe(
            """
            const requestedLimits = [];
            function bytesFor(value, limit, terminated) {
                const bytes = new Uint8Array(limit);
                bytes.fill(0x41);
                for (let i = 0; i < value.length && i < limit; i++) {
                    bytes[i] = value.charCodeAt(i);
                }
                if (terminated && value.length < limit) {
                    bytes[value.length] = 0;
                    if (value.length + 1 < limit) bytes[value.length + 1] = 0xff;
                }
                return bytes.buffer;
            }
            const address = {
                isNull: function () { return false; },
                readByteArray: function (limit) {
                    requestedLimits.push(limit);
                    return bytesFor("bounded", limit, true);
                }
            };
            const unterminated = {
                isNull: function () { return false; },
                readByteArray: function (limit) {
                    return bytesFor("unterminated", limit, false);
                }
            };
            const unicodeAddress = {
                isNull: function () { return false; },
                readByteArray: function (limit) {
                    const bytes = new Uint8Array(limit);
                    bytes[0] = 0xc3;
                    bytes[1] = 0xa9;
                    bytes[2] = 0;
                    return bytes.buffer;
                },
                readUtf8String: function (length) {
                    return length === 2 ? "é" : "wrong length";
                }
            };
            const defaultValue = readCString(address);
            const explicitValue = readCString(address, 17);
            const unterminatedValue = readCString(unterminated, 17);
            const unicodeValue = readCString(unicodeAddress, 8);
            let rangeLookupWasMasked = false;
            const taggedAddress = {
                isNull: function () { return false; },
                and: function (_mask) {
                    rangeLookupWasMasked = true;
                    return {
                        sub: function () {
                            return { toString: function () { return "0x4"; } };
                        }
                    };
                },
                readByteArray: function (limit) {
                    return bytesFor("tagged", limit, true);
                }
            };
            Process.findRangeByAddress = function (candidate) {
                if (candidate === taggedAddress) return null;
                return { base: {}, size: 64, protection: "rw-" };
            };
            globalThis.__result = {
                defaultValue: defaultValue,
                explicitValue: explicitValue,
                unterminatedValue: unterminatedValue,
                unicodeValue: unicodeValue,
                taggedValue: readCString(taggedAddress, 16),
                rangeLookupWasMasked: rangeLookupWasMasked,
                requestedLimits: requestedLimits,
                configuredMaximum: MAX_NATIVE_STRING_BYTES
            };
            """
        )
        result = output["result"]
        self.assertEqual(result["defaultValue"], "bounded")
        self.assertEqual(result["explicitValue"], "bounded")
        self.assertEqual(result["unterminatedValue"], "")
        self.assertEqual(result["unicodeValue"], "é")
        self.assertEqual(result["taggedValue"], "tagged")
        self.assertTrue(result["rangeLookupWasMasked"])
        self.assertEqual(
            result["requestedLimits"],
            [result["configuredMaximum"], 17],
        )
        self.assertGreater(result["configuredMaximum"], 0)


if __name__ == "__main__":
    unittest.main()
