/*
 * Universal Android security-testing bypass for Frida 16 and 17.
 *
 * Covers common TLS pinning, root, emulator, debugger, process-termination,
 * and anti-Frida checks without app-specific offsets or code patching.
 * Use only on applications you are authorized to assess.
 *
 * Recommended usage (spawn mode installs hooks before application startup):
 *   frida -U -f com.example.app -l universal_bypass.js
 *
 * Edit CONFIG below to disable a family of hooks when isolating a crash.
 */

"use strict";

const VERSION = "2.0.0";

const CONFIG = Object.freeze({
    sslPinning: true,
    rootDetection: true,
    emulatorDetection: true,
    debuggerDetection: true,
    processTermination: true,
    fridaDetection: true,
    verbose: false
});

const STATE = {
    nativeHooks: 0,
    javaHooks: 0,
    bypasses: 0,
    seenCount: 0,
    seen: Object.create(null),
    attached: Object.create(null),
    replacements: [],
    callbacks: [],
    moduleObserver: null,
    java: Object.create(null)
};

const NULL_PTR = ptr(0);
const SELF_PID = Process.id;

function log(level, message) {
    console.log("[UniversalBypass][" + level + "] " + message);
}

function info(message) {
    log("*", message);
}

function warn(message) {
    log("!", message);
}

function debug(message) {
    if (CONFIG.verbose) log("debug", message);
}

function bypass(key, message) {
    STATE.bypasses++;
    if (!STATE.seen[key] && STATE.seenCount < 512) {
        STATE.seen[key] = true;
        STATE.seenCount++;
        log("+", message);
    }
}

function safeString(value) {
    try {
        if (value === null || value === undefined) return "";
        return String(value);
    } catch (_) {
        return "";
    }
}

function readCString(address) {
    try {
        if (!address || address.isNull()) return "";
        return address.readUtf8String() || "";
    } catch (_) {
        return "";
    }
}

function containsAny(value, values) {
    const lower = safeString(value).toLowerCase();
    for (let i = 0; i < values.length; i++) {
        if (lower.indexOf(values[i]) !== -1) return true;
    }
    return false;
}

function findExport(name, moduleName) {
    try {
        if (moduleName) {
            const module = Process.findModuleByName(moduleName);
            if (module) {
                const address = module.findExportByName(name);
                if (address) return address;
            }
        }
    } catch (_) {
        // Continue with a global lookup.
    }

    try {
        if (typeof Module.findGlobalExportByName === "function") {
            return Module.findGlobalExportByName(name);
        }
    } catch (_) {
        // Frida 16 fallback below.
    }

    try {
        if (typeof Module.findExportByName === "function") {
            return Module.findExportByName(null, name);
        }
    } catch (_) {
        // Export is unavailable.
    }
    return null;
}

function attachAt(label, address, callbacks) {
    if (!address) return false;
    const key = label + "@" + address.toString();
    if (STATE.attached[key]) return false;
    try {
        Interceptor.attach(address, callbacks);
        STATE.attached[key] = true;
        STATE.nativeHooks++;
        debug("native hook installed: " + label);
        return true;
    } catch (error) {
        warn(label + " hook failed: " + error);
        return false;
    }
}

function attachExport(name, callbacks, moduleName, label) {
    return attachAt(label || name, findExport(name, moduleName), callbacks);
}

function replaceAt(label, address, returnType, argumentTypes, replacementFactory) {
    if (!address) return false;
    const key = "replace:" + label + "@" + address.toString();
    if (STATE.attached[key]) return false;
    try {
        const original = new NativeFunction(address, returnType, argumentTypes);
        const callback = new NativeCallback(
            replacementFactory(original),
            returnType,
            argumentTypes
        );
        Interceptor.replace(address, callback);
        STATE.callbacks.push(callback);
        STATE.replacements.push({ address: address, original: original });
        STATE.attached[key] = true;
        STATE.nativeHooks++;
        debug("native replacement installed: " + label);
        return true;
    } catch (error) {
        warn(label + " replacement failed: " + error);
        return false;
    }
}

function isApplicationAddress(address) {
    try {
        const module = Process.findModuleByAddress(address);
        if (!module) return false;
        const path = (module.path || "").toLowerCase();
        return path.indexOf("/data/app/") !== -1 ||
            path.indexOf("/data/user/") !== -1 ||
            path.indexOf("/data/data/") !== -1 ||
            path.indexOf("/mnt/expand/") !== -1;
    } catch (_) {
        return false;
    }
}

function javaUse(className) {
    try {
        return Java.use(className);
    } catch (error) {
        debug("Java class unavailable: " + className + " (" + error + ")");
        return null;
    }
}

function markJavaHook(label, count) {
    const installed = count || 1;
    STATE.javaHooks += installed;
    debug("Java hook installed: " + label + " (" + installed + ")");
}

function hookJavaOverloads(className, methodName, implementationFactory) {
    const klass = javaUse(className);
    if (!klass || !klass[methodName]) return 0;

    let count = 0;
    klass[methodName].overloads.forEach(function (overload) {
        try {
            overload.implementation = implementationFactory(overload);
            count++;
        } catch (error) {
            debug(className + "." + methodName + " overload skipped: " + error);
        }
    });
    if (count > 0) markJavaHook(className + "." + methodName, count);
    return count;
}

// -------------------------------------------------------------------------
// TLS pinning bypass - Java
// -------------------------------------------------------------------------

function getOrCreateTrustManager() {
    if (STATE.java.trustManagers) return STATE.java.trustManagers;

    const X509TrustManager = javaUse("javax.net.ssl.X509TrustManager");
    if (!X509TrustManager) return null;

    let TrustAllManager = javaUse("org.apkAnalyzer.TrustAllManager");
    if (!TrustAllManager) {
        TrustAllManager = Java.registerClass({
            name: "org.apkAnalyzer.TrustAllManager",
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function () {},
                checkServerTrusted: function () {},
                getAcceptedIssuers: function () {
                    return Java.array("java.security.cert.X509Certificate", []);
                }
            }
        });
    }

    STATE.java.trustManagers = Java.array(
        "javax.net.ssl.TrustManager",
        [TrustAllManager.$new()]
    );
    return STATE.java.trustManagers;
}

function getOrCreateHostnameVerifier() {
    if (STATE.java.hostnameVerifier) return STATE.java.hostnameVerifier;

    const HostnameVerifier = javaUse("javax.net.ssl.HostnameVerifier");
    if (!HostnameVerifier) return null;

    let AllowAllVerifier = javaUse("org.apkAnalyzer.AllowAllHostnameVerifier");
    if (!AllowAllVerifier) {
        AllowAllVerifier = Java.registerClass({
            name: "org.apkAnalyzer.AllowAllHostnameVerifier",
            implements: [HostnameVerifier],
            methods: {
                verify: function (hostname) {
                    bypass("hostname:" + hostname, "accepted TLS hostname: " + hostname);
                    return true;
                }
            }
        });
    }

    STATE.java.hostnameVerifier = AllowAllVerifier.$new();
    return STATE.java.hostnameVerifier;
}

function hookSslContext() {
    const SSLContext = javaUse("javax.net.ssl.SSLContext");
    const trustManagers = getOrCreateTrustManager();
    if (!SSLContext || !trustManagers) return;

    try {
        const init = SSLContext.init.overload(
            "[Ljavax.net.ssl.KeyManager;",
            "[Ljavax.net.ssl.TrustManager;",
            "java.security.SecureRandom"
        );
        init.implementation = function (keyManagers, _trustManagers, secureRandom) {
            bypass("sslcontext", "replaced SSLContext TrustManagers");
            return init.call(this, keyManagers, trustManagers, secureRandom);
        };
        markJavaHook("SSLContext.init");
    } catch (error) {
        warn("SSLContext.init hook failed: " + error);
    }

    hookJavaOverloads("javax.net.ssl.TrustManagerFactory", "getTrustManagers", function () {
        return function () {
            bypass("trust-manager-factory", "replaced TrustManagerFactory result");
            return trustManagers;
        };
    });
}

function hookHttpsUrlConnection() {
    const HttpsURLConnection = javaUse("javax.net.ssl.HttpsURLConnection");
    const verifier = getOrCreateHostnameVerifier();
    if (!HttpsURLConnection || !verifier) return;

    try {
        const setDefault = HttpsURLConnection.setDefaultHostnameVerifier.overload(
            "javax.net.ssl.HostnameVerifier"
        );
        setDefault.implementation = function () {
            bypass("https-default-verifier", "replaced default HostnameVerifier");
            return setDefault.call(this, verifier);
        };
        markJavaHook("HttpsURLConnection.setDefaultHostnameVerifier");
    } catch (error) {
        debug("default HostnameVerifier hook unavailable: " + error);
    }

    try {
        const setInstance = HttpsURLConnection.setHostnameVerifier.overload(
            "javax.net.ssl.HostnameVerifier"
        );
        setInstance.implementation = function () {
            bypass("https-verifier", "replaced connection HostnameVerifier");
            return setInstance.call(this, verifier);
        };
        markJavaHook("HttpsURLConnection.setHostnameVerifier");
    } catch (error) {
        debug("connection HostnameVerifier hook unavailable: " + error);
    }
}

function hookCertificatePinner(className) {
    ["check", "check$okhttp"].forEach(function (methodName) {
        hookJavaOverloads(className, methodName, function (overload) {
            return function () {
                const host = arguments.length > 0 ? safeString(arguments[0]) : "unknown";
                bypass(className + ":" + host, "bypassed " + className + " for " + host);
                const returnType = safeString(overload.returnType.className);
                if (returnType === "boolean") return true;
                return undefined;
            };
        });
    });
}

function hookBooleanVerifier(className, methodName) {
    hookJavaOverloads(className, methodName, function () {
        return function () {
            const host = arguments.length > 0 ? safeString(arguments[0]) : "unknown";
            bypass(className + ":" + methodName + ":" + host,
                "bypassed hostname verification in " + className);
            return true;
        };
    });
}

function hookVoidVerifier(className, methodName, description) {
    hookJavaOverloads(className, methodName, function () {
        return function () {
            bypass(className + ":" + methodName, description || ("bypassed " + className));
            return undefined;
        };
    });
}

function hookConscrypt() {
    [
        "com.android.org.conscrypt.TrustManagerImpl",
        "org.conscrypt.TrustManagerImpl"
    ].forEach(function (className) {
        hookJavaOverloads(className, "verifyChain", function () {
            return function () {
                bypass(className + ":verifyChain", "bypassed Conscrypt certificate chain validation");
                return arguments[0];
            };
        });

        hookJavaOverloads(className, "checkTrustedRecursive", function () {
            const ArrayList = javaUse("java.util.ArrayList");
            return function () {
                bypass(className + ":recursive", "bypassed Conscrypt recursive trust check");
                return ArrayList ? ArrayList.$new() : null;
            };
        });
    });

    hookJavaOverloads(
        "android.security.net.config.NetworkSecurityTrustManager",
        "checkPins",
        function () {
            return function () {
                bypass("network-security-pins", "bypassed Network Security Config pins");
                return undefined;
            };
        }
    );
}

function hookWebViewSslErrors() {
    function hookClientClass(className) {
        const key = "webview-client:" + className;
        if (STATE.java[key]) return;
        STATE.java[key] = true;
        const count = hookJavaOverloads(className, "onReceivedSslError", function (overload) {
            return function () {
                for (let i = 0; i < arguments.length; i++) {
                    const value = arguments[i];
                    if (value && typeof value.proceed === "function") {
                        bypass(className + ":ssl-error", "continued past a WebView TLS error");
                        value.proceed();
                        return undefined;
                    }
                }
                return overload.apply(this, arguments);
            };
        });
        if (count === 0) delete STATE.java[key];
    }

    hookClientClass("android.webkit.WebViewClient");
    hookClientClass("org.apache.cordova.CordovaWebViewClient");

    const WebView = javaUse("android.webkit.WebView");
    if (!WebView) return;
    try {
        const setClient = WebView.setWebViewClient.overload("android.webkit.WebViewClient");
        setClient.implementation = function (client) {
            try {
                if (client && client.$className) hookClientClass(client.$className);
            } catch (error) {
                debug("custom WebViewClient hook failed: " + error);
            }
            return setClient.call(this, client);
        };
        markJavaHook("WebView.setWebViewClient");
    } catch (error) {
        debug("WebView.setWebViewClient hook unavailable: " + error);
    }
}

function hookTrustKit() {
    hookBooleanVerifier(
        "com.datatheorem.android.trustkit.pinning.OkHostnameVerifier",
        "verify"
    );
    hookJavaOverloads(
        "com.datatheorem.android.trustkit.pinning.PinningTrustManager",
        "checkServerTrusted",
        function () {
            return function () {
                bypass("trustkit", "bypassed TrustKit certificate pinning");
                return undefined;
            };
        }
    );
}

function installJavaTlsHooks() {
    hookSslContext();
    hookHttpsUrlConnection();
    hookCertificatePinner("okhttp3.CertificatePinner");
    hookCertificatePinner("com.squareup.okhttp.CertificatePinner");
    hookBooleanVerifier("okhttp3.internal.tls.OkHostnameVerifier", "verify");
    hookBooleanVerifier("com.squareup.okhttp.internal.tls.OkHostnameVerifier", "verify");
    hookVoidVerifier(
        "org.apache.http.conn.ssl.AbstractVerifier",
        "verify",
        "bypassed Apache HTTP hostname verification"
    );
    hookVoidVerifier(
        "ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier",
        "verify",
        "bypassed HttpClientAndroidLib hostname verification"
    );
    [
        "com.android.org.conscrypt.OpenSSLSocketImpl",
        "com.android.org.conscrypt.OpenSSLEngineSocketImpl",
        "org.conscrypt.OpenSSLSocketImpl"
    ].forEach(function (className) {
        hookVoidVerifier(
            className,
            "verifyCertificateChain",
            "bypassed Conscrypt socket certificate verification"
        );
    });
    hookJavaOverloads(
        "android.net.http.CertificateChainValidator",
        "verifyServerCertificates",
        function () {
            return function () {
                bypass("certificate-chain-validator", "bypassed Android certificate chain validator");
                return null;
            };
        }
    );
    hookConscrypt();
    hookWebViewSslErrors();
    hookTrustKit();
}

// -------------------------------------------------------------------------
// Root and emulator detection - shared data
// -------------------------------------------------------------------------

const ROOT_PATHS = [
    "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su",
    "/vendor/bin/su", "/data/local/su", "/data/local/bin/su",
    "/data/local/xbin/su", "/system/app/superuser.apk",
    "/system/app/supersu.apk", "/system/etc/init.d/99supersu",
    "/data/adb/magisk", "/sbin/.magisk", "/cache/magisk.log",
    "/system/bin/busybox", "/system/xbin/busybox", "/system/bin/.ext/.su",
    "/system/xbin/daemonsu", "/system/sd/xbin/su", "/system/bin/failsafe/su",
    "/system/usr/we-need-root/su-backup", "/debug_ramdisk/.magisk",
    "/data/adb/magisk.db", "/data/adb/ksu", "/data/adb/ap",
    "/system/bin/magisk", "/system/xbin/magisk"
];

const EMULATOR_PATHS = [
    "/dev/socket/qemud", "/dev/qemu_pipe", "/system/lib/libc_malloc_debug_qemu.so",
    "/sys/qemu_trace", "/system/bin/qemu-props", "/dev/socket/genyd"
];

const ROOT_PACKAGES = [
    "com.topjohnwu.magisk", "eu.chainfire.supersu", "com.noshufou.android.su",
    "com.noshufou.android.su.elite", "com.koushikdutta.superuser",
    "com.thirdparty.superuser", "com.yellowes.su", "com.kingroot.kinguser",
    "com.kingo.root", "com.smedialink.oneclickroot", "com.zhiqupk.root.global",
    "com.alephzain.framaroot", "de.robv.android.xposed.installer",
    "org.meowcat.edxposed.manager", "org.lsposed.manager", "com.saurik.substrate",
    "me.weishu.kernelsu", "me.bmax.apatch"
];

const EMULATOR_PACKAGES = [
    "com.bluestacks", "com.bignox.app", "com.genymotion.superuser",
    "com.microvirt.launcher", "com.microvirt.guide", "com.mumu.launcher"
];

const PROPERTY_SPOOFS = Object.freeze({
    "ro.debuggable": "0",
    "ro.secure": "1",
    "ro.build.tags": "release-keys",
    "ro.build.type": "user",
    "ro.boot.vbmeta.device_state": "locked",
    "ro.boot.flash.locked": "1",
    "ro.boot.verifiedbootstate": "green",
    "ro.boot.veritymode": "enforcing",
    "ro.kernel.qemu": "0",
    "ro.boot.qemu": "0",
    "ro.hardware.virtual_device": "0"
});

function spoofedProperty(key) {
    if (PROPERTY_SPOOFS[key] === undefined) return undefined;
    if (key === "ro.debuggable") {
        return (CONFIG.rootDetection || CONFIG.debuggerDetection) ? PROPERTY_SPOOFS[key] : undefined;
    }
    if (key === "ro.kernel.qemu" || key === "ro.boot.qemu" ||
            key === "ro.hardware.virtual_device") {
        return CONFIG.emulatorDetection ? PROPERTY_SPOOFS[key] : undefined;
    }
    if (key === "ro.build.tags" || key === "ro.build.type") {
        return (CONFIG.rootDetection || CONFIG.emulatorDetection) ? PROPERTY_SPOOFS[key] : undefined;
    }
    return CONFIG.rootDetection ? PROPERTY_SPOOFS[key] : undefined;
}

const ROOT_PATH_SET = Object.create(null);
const ROOT_PACKAGE_SET = Object.create(null);
const EMULATOR_PATH_SET = Object.create(null);
const EMULATOR_PACKAGE_SET = Object.create(null);

ROOT_PATHS.forEach(function (item) { ROOT_PATH_SET[item] = true; });
ROOT_PACKAGES.forEach(function (item) { ROOT_PACKAGE_SET[item] = true; });
EMULATOR_PATHS.forEach(function (item) { EMULATOR_PATH_SET[item] = true; });
EMULATOR_PACKAGES.forEach(function (item) { EMULATOR_PACKAGE_SET[item] = true; });

function normalizePath(path) {
    let value = safeString(path).toLowerCase();
    while (value.length > 1 && value[value.length - 1] === "/") {
        value = value.slice(0, -1);
    }
    return value.replace(/\/+/g, "/");
}

function isBlockedPath(path) {
    const normalized = normalizePath(path);
    if (CONFIG.rootDetection && ROOT_PATH_SET[normalized]) return true;
    if (CONFIG.emulatorDetection && EMULATOR_PATH_SET[normalized]) return true;
    return false;
}

function isBlockedPackage(packageName) {
    const normalized = safeString(packageName).toLowerCase();
    if (CONFIG.rootDetection && ROOT_PACKAGE_SET[normalized]) return true;
    if (CONFIG.emulatorDetection && EMULATOR_PACKAGE_SET[normalized]) return true;
    return false;
}

function isSuspiciousCommand(command) {
    if (!CONFIG.rootDetection) return false;
    const value = safeString(command).toLowerCase().trim();
    if (!value) return false;
    if (containsAny(value, ROOT_PATHS)) return true;
    return /(^|[\s;&|])(su|busybox|magisk|resetprop)([\s;&|]|$)/.test(value) ||
        /(^|[\s;&|])which\s+su([\s;&|]|$)/.test(value) ||
        /(^|[\s;&|])getprop\s+(ro\.(debuggable|secure|build\.tags)|ro\.boot\.)/.test(value);
}

function javaCommandToString(value) {
    try {
        if (value && value.$className === "[Ljava.lang.String;") {
            const parts = [];
            for (let i = 0; i < value.length; i++) parts.push(safeString(value[i]));
            return parts.join(" ");
        }
    } catch (_) {
        // Treat it as a scalar below.
    }
    return safeString(value);
}

// -------------------------------------------------------------------------
// Root and emulator detection - Java
// -------------------------------------------------------------------------

function hookJavaFileChecks() {
    const File = javaUse("java.io.File");
    if (!File) return;

    ["exists", "canExecute", "isFile"].forEach(function (methodName) {
        try {
            const method = File[methodName].overload();
            method.implementation = function () {
                const path = safeString(this.getAbsolutePath());
                if (isBlockedPath(path)) {
                    bypass("file:" + normalizePath(path), "hid root/emulator path " + path);
                    return false;
                }
                return method.call(this);
            };
            markJavaHook("File." + methodName);
        } catch (error) {
            debug("File." + methodName + " hook unavailable: " + error);
        }
    });
}

function hookRuntimeCommands() {
    hookJavaOverloads("java.lang.Runtime", "exec", function (overload) {
        return function () {
            const args = Array.prototype.slice.call(arguments);
            if (args.length > 0 && isSuspiciousCommand(javaCommandToString(args[0]))) {
                const original = javaCommandToString(args[0]);
                if (args[0] && args[0].$className === "[Ljava.lang.String;") {
                    args[0] = Java.array("java.lang.String", ["sh", "-c", "exit 1"]);
                } else {
                    args[0] = "sh -c 'exit 1'";
                }
                bypass("runtime:" + original, "blocked root command: " + original);
            }
            return overload.apply(this, args);
        };
    });

    const ProcessBuilder = javaUse("java.lang.ProcessBuilder");
    if (!ProcessBuilder) return;
    try {
        const start = ProcessBuilder.start.overload();
        start.implementation = function () {
            try {
                const command = this.command();
                const parts = [];
                for (let i = 0; i < command.size(); i++) {
                    parts.push(safeString(command.get(i)));
                }
                const joined = parts.join(" ");
                if (isSuspiciousCommand(joined)) {
                    command.clear();
                    command.add("sh");
                    command.add("-c");
                    command.add("exit 1");
                    bypass("process-builder:" + joined, "blocked ProcessBuilder root command: " + joined);
                }
            } catch (error) {
                debug("ProcessBuilder command inspection failed: " + error);
            }
            return start.call(this);
        };
        markJavaHook("ProcessBuilder.start");
    } catch (error) {
        debug("ProcessBuilder.start hook unavailable: " + error);
    }
}

function hookPackageManager() {
    const className = "android.app.ApplicationPackageManager";

    ["getPackageInfo", "getApplicationInfo"].forEach(function (methodName) {
        hookJavaOverloads(className, methodName, function (overload) {
            return function () {
                const args = Array.prototype.slice.call(arguments);
                if (args.length > 0 && isBlockedPackage(args[0])) {
                    const requested = safeString(args[0]);
                    args[0] = "invalid.package.hidden.by.apk.analyzer";
                    bypass("package:" + requested, "hid root/emulator package " + requested);
                }
                return overload.apply(this, args);
            };
        });
    });

    ["getInstalledPackages", "getInstalledApplications"].forEach(function (methodName) {
        hookJavaOverloads(className, methodName, function (overload) {
            return function () {
                const result = overload.apply(this, arguments);
                if (!result) return result;
                try {
                    for (let i = result.size() - 1; i >= 0; i--) {
                        const item = result.get(i);
                        const packageName = safeString(item.packageName.value || item.packageName);
                        if (isBlockedPackage(packageName)) {
                            result.remove(i);
                            bypass("package-list:" + packageName,
                                "removed root/emulator package from enumeration: " + packageName);
                        }
                    }
                } catch (error) {
                    debug(methodName + " filtering failed: " + error);
                }
                return result;
            };
        });
    });
}

function hookJavaSystemProperties() {
    hookJavaOverloads("android.os.SystemProperties", "get", function (overload) {
        return function () {
            const key = arguments.length > 0 ? safeString(arguments[0]) : "";
            const replacement = spoofedProperty(key);
            if (replacement !== undefined) {
                bypass("property:" + key, "spoofed Android property " + key);
                return replacement;
            }
            return overload.apply(this, arguments);
        };
    });

    hookJavaOverloads("android.os.SystemProperties", "getInt", function (overload) {
        return function () {
            const key = arguments.length > 0 ? safeString(arguments[0]) : "";
            const replacement = spoofedProperty(key);
            if (replacement !== undefined && /^[-+]?\d+$/.test(replacement)) {
                bypass("property-int:" + key, "spoofed Android integer property " + key);
                return parseInt(replacement, 10);
            }
            return overload.apply(this, arguments);
        };
    });

    hookJavaOverloads("android.os.SystemProperties", "getLong", function (overload) {
        return function () {
            const key = arguments.length > 0 ? safeString(arguments[0]) : "";
            const replacement = spoofedProperty(key);
            if (replacement !== undefined && /^[-+]?\d+$/.test(replacement)) {
                bypass("property-long:" + key, "spoofed Android long property " + key);
                return parseInt(replacement, 10);
            }
            return overload.apply(this, arguments);
        };
    });

    hookJavaOverloads("android.os.SystemProperties", "getBoolean", function (overload) {
        return function () {
            const key = arguments.length > 0 ? safeString(arguments[0]) : "";
            const replacement = spoofedProperty(key);
            if (replacement !== undefined) {
                bypass("property-boolean:" + key, "spoofed Android boolean property " + key);
                return /^(1|true|y|yes|on)$/i.test(replacement);
            }
            return overload.apply(this, arguments);
        };
    });
}

function hookRootBeer() {
    const RootBeer = javaUse("com.scottyab.rootbeer.RootBeer");
    if (!RootBeer) return;
    [
        "isRooted", "isRootedWithoutBusyBoxCheck", "detectRootManagementApps",
        "detectPotentiallyDangerousApps", "checkForBinary", "checkForDangerousProps",
        "checkForRWPaths", "detectTestKeys", "checkSuExists", "checkForRootNative",
        "checkForMagiskBinary"
    ].forEach(function (methodName) {
        hookJavaOverloads("com.scottyab.rootbeer.RootBeer", methodName, function () {
            return function () {
                bypass("rootbeer:" + methodName, "bypassed RootBeer." + methodName);
                return false;
            };
        });
    });
}

function spoofBuildFields() {
    if (!CONFIG.emulatorDetection) return;
    const Build = javaUse("android.os.Build");
    if (!Build) return;

    const markers = [
        "generic", "unknown", "emulator", "sdk_gphone", "google_sdk", "vbox",
        "genymotion", "goldfish", "ranchu", "nox", "bluestacks", "test-keys"
    ];
    const replacements = {
        FINGERPRINT: "google/oriole/oriole:14/AP2A.240705.004/11875680:user/release-keys",
        MODEL: "Pixel 6",
        MANUFACTURER: "Google",
        BRAND: "google",
        DEVICE: "oriole",
        PRODUCT: "oriole",
        HARDWARE: "tensor",
        BOARD: "slider",
        TAGS: "release-keys",
        TYPE: "user"
    };

    Object.keys(replacements).forEach(function (field) {
        try {
            const current = safeString(Build[field].value);
            if (containsAny(current, markers)) {
                Build[field].value = replacements[field];
                bypass("build:" + field, "spoofed emulator Build." + field);
            }
        } catch (error) {
            debug("Build." + field + " spoof failed: " + error);
        }
    });
}

function hookDeveloperSettings() {
    const suspiciousKeys = {
        adb_enabled: true,
        development_settings_enabled: true,
        mock_location: true
    };

    ["android.provider.Settings$Secure", "android.provider.Settings$Global"].forEach(
        function (className) {
            hookJavaOverloads(className, "getInt", function (overload) {
                return function () {
                    const key = arguments.length > 1 ? safeString(arguments[1]) : "";
                    if (suspiciousKeys[key]) {
                        bypass("setting-int:" + key, "spoofed Android setting " + key);
                        return 0;
                    }
                    return overload.apply(this, arguments);
                };
            });
            hookJavaOverloads(className, "getString", function (overload) {
                return function () {
                    const key = arguments.length > 1 ? safeString(arguments[1]) : "";
                    if (suspiciousKeys[key]) {
                        bypass("setting-string:" + key, "spoofed Android setting " + key);
                        return "0";
                    }
                    return overload.apply(this, arguments);
                };
            });
        }
    );
}

function installJavaEnvironmentHooks() {
    if (CONFIG.rootDetection || CONFIG.emulatorDetection) {
        hookJavaFileChecks();
        hookPackageManager();
    }
    if (CONFIG.rootDetection) hookRuntimeCommands();
    hookJavaSystemProperties();
    if (CONFIG.rootDetection) hookRootBeer();
    if (CONFIG.emulatorDetection || CONFIG.debuggerDetection) {
        hookDeveloperSettings();
        spoofBuildFields();
    }
}

// -------------------------------------------------------------------------
// Debugger and process-termination bypass - Java
// -------------------------------------------------------------------------

function installJavaDebuggerHooks() {
    [
        ["android.os.Debug", "isDebuggerConnected"],
        ["android.os.Debug", "waitingForDebugger"],
        ["dalvik.system.VMDebug", "isDebuggerConnected"]
    ].forEach(function (entry) {
        hookJavaOverloads(entry[0], entry[1], function () {
            return function () {
                bypass("debugger:" + entry[0] + "." + entry[1],
                    "bypassed " + entry[0] + "." + entry[1]);
                return false;
            };
        });
    });
}

function installJavaTerminationHooks() {
    hookJavaOverloads("java.lang.System", "exit", function () {
        return function (status) {
            bypass("system-exit", "blocked System.exit(" + status + ")");
            return undefined;
        };
    });
    ["exit", "halt"].forEach(function (methodName) {
        hookJavaOverloads("java.lang.Runtime", methodName, function () {
            return function (status) {
                bypass("runtime-" + methodName, "blocked Runtime." + methodName + "(" + status + ")");
                return undefined;
            };
        });
    });
    hookJavaOverloads("android.os.Process", "killProcess", function (overload) {
        return function (pid) {
            if (Number(pid) === SELF_PID) {
                bypass("kill-process", "blocked Process.killProcess(self)");
                return undefined;
            }
            return overload.call(this, pid);
        };
    });
}

function installJavaHooks() {
    if (typeof Java === "undefined" || !Java.available) {
        warn("Java hooks skipped; Java bridge is unavailable");
        return;
    }

    Java.perform(function () {
        try {
            if (CONFIG.sslPinning) installJavaTlsHooks();
            if (CONFIG.rootDetection || CONFIG.emulatorDetection || CONFIG.debuggerDetection) {
                installJavaEnvironmentHooks();
            }
            if (CONFIG.debuggerDetection) installJavaDebuggerHooks();
            if (CONFIG.processTermination) installJavaTerminationHooks();
            info("Java hooks installed: " + STATE.javaHooks);
        } catch (error) {
            warn("Java hook installation failed: " + (error.stack || error));
        }
    });
}

// -------------------------------------------------------------------------
// TLS pinning bypass - native libraries
// -------------------------------------------------------------------------

const VERIFY_OK_CALLBACK = new NativeCallback(function () {
    return 0; // BoringSSL ssl_verify_ok
}, "int", ["pointer", "pointer"]);
STATE.callbacks.push(VERIFY_OK_CALLBACK);

function moduleExport(module, name) {
    try {
        return module.findExportByName(name);
    } catch (_) {
        return null;
    }
}

function installNativeTlsHooksForModule(module) {
    if (!CONFIG.sslPinning || !module) return;

    ["SSL_set_custom_verify", "SSL_CTX_set_custom_verify"].forEach(function (name) {
        const address = moduleExport(module, name);
        attachAt(module.name + "!" + name, address, {
            onEnter: function (args) {
                args[1] = NULL_PTR; // SSL_VERIFY_NONE
                args[2] = VERIFY_OK_CALLBACK;
                bypass("native:" + name, "bypassed native TLS custom verification");
            }
        });
    });

    ["SSL_set_verify", "SSL_CTX_set_verify"].forEach(function (name) {
        const address = moduleExport(module, name);
        attachAt(module.name + "!" + name, address, {
            onEnter: function (args) {
                args[1] = NULL_PTR; // SSL_VERIFY_NONE
                args[2] = NULL_PTR;
                bypass("native:" + name, "disabled native TLS peer verification");
            }
        });
    });

    const verifyResult = moduleExport(module, "SSL_get_verify_result");
    attachAt(module.name + "!SSL_get_verify_result", verifyResult, {
        onLeave: function (result) {
            if (result.toInt32() !== 0) {
                result.replace(0);
                bypass("native:SSL_get_verify_result", "cleared native TLS verification result");
            }
        }
    });

    const verifyCert = moduleExport(module, "X509_verify_cert");
    attachAt(module.name + "!X509_verify_cert", verifyCert, {
        onLeave: function (result) {
            if (result.toInt32() !== 1) {
                result.replace(1);
                bypass("native:X509_verify_cert", "accepted native X.509 certificate chain");
            }
        }
    });
}

function installNativeTlsHooks() {
    Process.enumerateModules().forEach(installNativeTlsHooksForModule);

    if (typeof Process.attachModuleObserver === "function") {
        STATE.moduleObserver = Process.attachModuleObserver({
            onAdded: function (module) {
                installNativeTlsHooksForModule(module);
            }
        });
        debug("module observer installed for late-loaded TLS libraries");
        return;
    }

    ["android_dlopen_ext", "dlopen"].forEach(function (name) {
        attachExport(name, {
            onLeave: function () {
                setImmediate(function () {
                    Process.enumerateModules().forEach(installNativeTlsHooksForModule);
                });
            }
        }, null, "tls-loader:" + name);
    });
}

// -------------------------------------------------------------------------
// Root, emulator, debugger, and termination bypass - native
// -------------------------------------------------------------------------

function redirectBlockedPath(invocation, args, index, label) {
    const path = readCString(args[index]);
    if (!isBlockedPath(path)) return;
    invocation.replacementPath = Memory.allocUtf8String(
        "/system/nonexistent/.apk-analyzer-hidden-" + SELF_PID
    );
    args[index] = invocation.replacementPath;
    bypass("native-path:" + normalizePath(path), "hid native root/emulator path " + path);
    debug("redirected by " + label);
}

function installNativeFileHooks() {
    ["open", "open64", "__open_2", "fopen", "fopen64", "access", "stat", "stat64", "lstat", "lstat64"].forEach(
        function (name) {
            attachExport(name, {
                onEnter: function (args) {
                    redirectBlockedPath(this, args, 0, name);
                }
            }, "libc.so", "root-file:" + name);
        }
    );

    ["openat", "openat64", "__openat_2", "faccessat", "fstatat", "newfstatat"].forEach(function (name) {
        attachExport(name, {
            onEnter: function (args) {
                redirectBlockedPath(this, args, 1, name);
            }
        }, "libc.so", "root-file:" + name);
    });

    ["execve", "execv", "execvp"].forEach(function (name) {
        attachExport(name, {
            onEnter: function (args) {
                const path = readCString(args[0]);
                if (isBlockedPath(path) || /(^|\/)su$/.test(normalizePath(path))) {
                    this.replacementPath = Memory.allocUtf8String(
                        "/system/nonexistent/.apk-analyzer-command"
                    );
                    args[0] = this.replacementPath;
                    bypass("native-exec:" + path, "blocked native root executable " + path);
                }
            }
        }, "libc.so", "root-exec:" + name);
    });

    ["system", "popen"].forEach(function (name) {
        attachExport(name, {
            onEnter: function (args) {
                const command = readCString(args[0]);
                if (isSuspiciousCommand(command)) {
                    this.safeCommand = Memory.allocUtf8String("sh -c 'exit 1'");
                    args[0] = this.safeCommand;
                    bypass("native-command:" + command, "blocked native root command: " + command);
                }
            }
        }, "libc.so", "root-command:" + name);
    });
}

function installNativePropertyHooks() {
    attachExport("__system_property_get", {
        onEnter: function (args) {
            this.name = readCString(args[0]);
            this.output = args[1];
        },
        onLeave: function (result) {
            const replacement = spoofedProperty(this.name);
            if (replacement === undefined || !this.output || this.output.isNull()) return;
            this.output.writeUtf8String(replacement);
            result.replace(replacement.length);
            bypass("native-property:" + this.name, "spoofed native Android property " + this.name);
        }
    }, "libc.so", "property-get");

    const readCallback = findExport("__system_property_read_callback", "libc.so");
    if (!readCallback) return;

    const callbackStacks = Object.create(null);
    const wrapper = new NativeCallback(function (cookie, nameAddress, valueAddress, serial) {
        const tid = Process.getCurrentThreadId();
        const stack = callbackStacks[tid];
        if (!stack || stack.length === 0) return;
        const record = stack.pop();
        record.called = true;
        if (stack.length === 0) delete callbackStacks[tid];

        const name = readCString(nameAddress);
        const replacement = spoofedProperty(name);
        if (replacement !== undefined) {
            const fake = Memory.allocUtf8String(replacement);
            bypass("native-property-callback:" + name,
                "spoofed callback Android property " + name);
            record.callback(cookie, nameAddress, fake, serial);
        } else {
            record.callback(cookie, nameAddress, valueAddress, serial);
        }
    }, "void", ["pointer", "pointer", "pointer", "uint32"]);
    STATE.callbacks.push(wrapper);

    attachAt("property-read-callback", readCallback, {
        onEnter: function (args) {
            if (args[1].isNull()) return;
            const tid = Process.getCurrentThreadId();
            if (!callbackStacks[tid]) callbackStacks[tid] = [];
            this.propertyCallbackTid = tid;
            this.propertyCallbackRecord = {
                called: false,
                callback: new NativeFunction(
                    args[1], "void", ["pointer", "pointer", "pointer", "uint32"]
                )
            };
            callbackStacks[tid].push(this.propertyCallbackRecord);
            args[1] = wrapper;
        },
        onLeave: function () {
            const record = this.propertyCallbackRecord;
            if (!record || record.called) return;
            const stack = callbackStacks[this.propertyCallbackTid];
            if (!stack) return;
            const index = stack.lastIndexOf(record);
            if (index !== -1) stack.splice(index, 1);
            if (stack.length === 0) delete callbackStacks[this.propertyCallbackTid];
        }
    });
}

function installNativeDebuggerHooks() {
    attachExport("ptrace", {
        onEnter: function (args) {
            this.blocked = args[0].toInt32() === 0; // PTRACE_TRACEME
            if (this.blocked) args[0] = ptr(0xffffffff);
        },
        onLeave: function (result) {
            if (!this.blocked) return;
            this.errno = 0;
            result.replace(0);
            bypass("ptrace", "bypassed PTRACE_TRACEME anti-debug check");
        }
    }, "libc.so", "debugger:ptrace");
}

const LETHAL_SIGNALS = { 6: true, 9: true };

function installNativeTerminationHooks() {
    replaceAt("kill", findExport("kill", "libc.so"), "int", ["int", "int"],
        function (original) {
            return function (pid, signal) {
                if (Number(pid) === SELF_PID && LETHAL_SIGNALS[Number(signal)]) {
                    bypass("native-kill:" + signal, "blocked kill(self, " + signal + ")");
                    return 0;
                }
                return original(pid, signal);
            };
        }
    );

    replaceAt("tgkill", findExport("tgkill", "libc.so"), "int", ["int", "int", "int"],
        function (original) {
            return function (threadGroup, threadId, signal) {
                if (Number(threadGroup) === SELF_PID && LETHAL_SIGNALS[Number(signal)]) {
                    bypass("native-tgkill:" + signal, "blocked tgkill(self, " + signal + ")");
                    return 0;
                }
                return original(threadGroup, threadId, signal);
            };
        }
    );

    replaceAt("raise", findExport("raise", "libc.so"), "int", ["int"],
        function (original) {
            return function (signal) {
                if (LETHAL_SIGNALS[Number(signal)]) {
                    bypass("native-raise:" + signal, "blocked raise(" + signal + ")");
                    return 0;
                }
                return original(signal);
            };
        }
    );
}

// -------------------------------------------------------------------------
// Anti-Frida concealment - only alter checks originating in app modules
// -------------------------------------------------------------------------

const FRIDA_MARKERS = [
    "frida", "gum-js", "gmain", "gdbus", "linjector", "frida-agent",
    "frida-gadget", "frida-server", "re.frida", "pool-frida"
];

const PROC_MARKERS = FRIDA_MARKERS.concat(
    ["/data/local/tmp"],
    CONFIG.rootDetection ? ["magisk", "kernelsu", "apatch", "zygisk", "riru", "lsposed"] : []
);
const PROC_FDS = Object.create(null);

function isSensitiveProcPath(path) {
    const normalized = normalizePath(path);
    if (!/^\/proc\/(self|\d+)\//.test(normalized)) return false;
    return /\/(maps|smaps|status|mounts|mountinfo)$/.test(normalized) ||
        /\/task\/\d+\/(maps|smaps|status|stat|comm)$/.test(normalized);
}

function trackProcOpen(name, pathIndex) {
    attachExport(name, {
        onEnter: function (args) {
            this.procPath = readCString(args[pathIndex]);
            this.trackProc = isSensitiveProcPath(this.procPath);
        },
        onLeave: function (result) {
            if (!this.trackProc) return;
            const fd = result.toInt32();
            if (fd >= 0) {
                PROC_FDS[fd] = this.procPath;
                debug("tracking proc fd " + fd + " for " + this.procPath);
            }
        }
    }, "libc.so", "frida-proc-open:" + name);
}

function sanitizeProcBuffer(buffer, length) {
    let data;
    try {
        data = new Uint8Array(buffer.readByteArray(length));
    } catch (_) {
        return false;
    }

    let text = "";
    for (let i = 0; i < data.length; i++) text += String.fromCharCode(data[i]);
    const lower = text.toLowerCase();
    let changed = false;

    PROC_MARKERS.forEach(function (marker) {
        let offset = 0;
        while (offset < lower.length) {
            const index = lower.indexOf(marker, offset);
            if (index === -1) break;
            for (let i = 0; i < marker.length; i++) data[index + i] = 0x5f;
            changed = true;
            offset = index + marker.length;
        }
    });

    const tracerPattern = /tracerpid:[\t ]*(\d+)/gi;
    let match;
    while ((match = tracerPattern.exec(text)) !== null) {
        const digitOffset = match.index + match[0].lastIndexOf(match[1]);
        for (let i = 0; i < match[1].length; i++) data[digitOffset + i] = 0x30;
        changed = true;
    }

    if (changed) buffer.writeByteArray(data);
    return changed;
}

function installProcConcealment() {
    trackProcOpen("open", 0);
    trackProcOpen("open64", 0);
    trackProcOpen("__open_2", 0);
    trackProcOpen("openat", 1);
    trackProcOpen("openat64", 1);
    trackProcOpen("__openat_2", 1);

    attachExport("close", {
        onEnter: function (args) {
            delete PROC_FDS[args[0].toInt32()];
        }
    }, "libc.so", "frida-proc-close");

    attachExport("dup", {
        onEnter: function (args) {
            this.sourceFd = args[0].toInt32();
        },
        onLeave: function (result) {
            const newFd = result.toInt32();
            if (newFd >= 0 && PROC_FDS[this.sourceFd]) {
                PROC_FDS[newFd] = PROC_FDS[this.sourceFd];
            }
        }
    }, "libc.so", "frida-proc-dup");

    ["dup2", "dup3"].forEach(function (name) {
        attachExport(name, {
            onEnter: function (args) {
                this.sourceFd = args[0].toInt32();
                this.targetFd = args[1].toInt32();
            },
            onLeave: function (result) {
                if (result.toInt32() < 0) return;
                if (PROC_FDS[this.sourceFd]) {
                    PROC_FDS[this.targetFd] = PROC_FDS[this.sourceFd];
                } else {
                    delete PROC_FDS[this.targetFd];
                }
            }
        }, "libc.so", "frida-proc-" + name);
    });

    ["read", "pread64"].forEach(function (name) {
        attachExport(name, {
            onEnter: function (args) {
                this.fd = args[0].toInt32();
                this.buffer = args[1];
            },
            onLeave: function (result) {
                const length = result.toInt32();
                if (length <= 0 || !PROC_FDS[this.fd]) return;
                if (sanitizeProcBuffer(this.buffer, length)) {
                    bypass("frida-proc-read", "filtered Frida/debug markers from /proc data");
                }
            }
        }, "libc.so", "frida-proc-read:" + name);
    });
}

function installStringConcealment() {
    ["strstr", "strcasestr"].forEach(function (name) {
        attachExport(name, {
            onEnter: function (args) {
                this.hide = isApplicationAddress(this.returnAddress) &&
                    containsAny(readCString(args[1]), FRIDA_MARKERS);
            },
            onLeave: function (result) {
                if (this.hide && !result.isNull()) {
                    result.replace(NULL_PTR);
                    bypass("frida-string:" + name, "hid Frida marker from app-native " + name);
                }
            }
        }, "libc.so", "frida-string:" + name);
    });

    attachExport("fgets", {
        onEnter: function (args) {
            this.buffer = args[0];
            this.capacity = args[1].toInt32();
            this.appCaller = isApplicationAddress(this.returnAddress);
        },
        onLeave: function (result) {
            if (!this.appCaller || result.isNull() || this.capacity < 2) return;
            const line = readCString(this.buffer);
            if (!containsAny(line, FRIDA_MARKERS)) return;
            this.buffer.writeByteArray([0x0a, 0x00]);
            bypass("frida-fgets", "filtered a Frida marker from an app-native text scan");
        }
    }, "libc.so", "frida-fgets");
}

function installReadlinkConcealment() {
    [
        { name: "readlink", buffer: 1, size: 2 },
        { name: "readlinkat", buffer: 2, size: 3 }
    ].forEach(function (spec) {
        attachExport(spec.name, {
            onEnter: function (args) {
                this.buffer = args[spec.buffer];
                this.capacity = args[spec.size].toUInt32();
                this.appCaller = isApplicationAddress(this.returnAddress);
            },
            onLeave: function (result) {
                const length = result.toInt32();
                if (!this.appCaller || length <= 0 || this.capacity === 0) return;
                let target = "";
                try {
                    target = this.buffer.readUtf8String(length);
                } catch (_) {
                    return;
                }
                if (!containsAny(target, FRIDA_MARKERS)) return;

                const replacement = "/system/lib/libc.so";
                const bytes = [];
                const count = Math.min(replacement.length, this.capacity);
                for (let i = 0; i < count; i++) bytes.push(replacement.charCodeAt(i));
                this.buffer.writeByteArray(bytes);
                result.replace(count);
                bypass("frida-readlink:" + spec.name,
                    "hid Frida marker from app-native " + spec.name);
            }
        }, "libc.so", "frida-readlink:" + spec.name);
    });
}

function installThreadNameConcealment() {
    attachExport("pthread_getname_np", {
        onEnter: function (args) {
            this.buffer = args[1];
            this.capacity = args[2].toUInt32();
            this.appCaller = isApplicationAddress(this.returnAddress);
        },
        onLeave: function (result) {
            if (!this.appCaller || result.toInt32() !== 0 || this.capacity < 2) return;
            const name = readCString(this.buffer);
            if (!containsAny(name, FRIDA_MARKERS)) return;
            const replacement = "Binder:" + SELF_PID;
            const safe = replacement.slice(0, Math.max(0, this.capacity - 1));
            this.buffer.writeUtf8String(safe);
            bypass("frida-thread", "hid Frida worker thread name");
        }
    }, "libc.so", "frida-thread-name");

    attachExport("prctl", {
        onEnter: function (args) {
            this.isGetName = args[0].toInt32() === 16; // PR_GET_NAME
            this.buffer = args[1];
            this.appCaller = isApplicationAddress(this.returnAddress);
        },
        onLeave: function (result) {
            if (!this.isGetName || !this.appCaller || result.toInt32() !== 0) return;
            const name = readCString(this.buffer);
            if (!containsAny(name, FRIDA_MARKERS)) return;
            this.buffer.writeUtf8String(("Binder:" + SELF_PID).slice(0, 15));
            bypass("frida-prctl", "hid Frida thread name from prctl");
        }
    }, "libc.so", "frida-prctl-name");
}

function installFridaPortConcealment() {
    const blockedPorts = { 27042: true, 27043: true, 27044: true };
    attachExport("connect", {
        onEnter: function (args) {
            this.blocked = false;
            const address = args[1];
            const length = args[2].toUInt32();
            if (address.isNull() || length < 4 || length > 128) return;

            try {
                const family = address.readU16();
                const port = (address.add(2).readU8() << 8) | address.add(3).readU8();
                if (!blockedPorts[port]) return;

                let loopback = false;
                if (family === 2 && length >= 8) { // AF_INET
                    loopback = address.add(4).readU8() === 127;
                } else if (family === 10 && length >= 24) { // AF_INET6
                    loopback = true;
                    for (let i = 0; i < 15; i++) {
                        if (address.add(8 + i).readU8() !== 0) loopback = false;
                    }
                    if (address.add(23).readU8() !== 1) loopback = false;
                }
                if (!loopback) return;

                this.safeAddress = Memory.alloc(length);
                this.safeAddress.writeByteArray(address.readByteArray(length));
                this.safeAddress.add(2).writeU8(0);
                this.safeAddress.add(3).writeU8(0);
                args[1] = this.safeAddress;
                this.blocked = true;
                this.port = port;
            } catch (error) {
                debug("connect inspection failed: " + error);
            }
        },
        onLeave: function (result) {
            if (!this.blocked) return;
            this.errno = 111; // ECONNREFUSED
            result.replace(-1);
            bypass("frida-port:" + this.port, "blocked loopback Frida port probe " + this.port);
        }
    }, "libc.so", "frida-port-probe");
}

function installFridaConcealment() {
    installProcConcealment();
    installStringConcealment();
    installReadlinkConcealment();
    installThreadNameConcealment();
    installFridaPortConcealment();
}

// -------------------------------------------------------------------------
// Startup and status
// -------------------------------------------------------------------------

function installNativeHooks() {
    if (Process.platform !== "linux") {
        warn("native Android hooks skipped on " + Process.platform);
        return;
    }
    if (CONFIG.sslPinning) installNativeTlsHooks();
    if (CONFIG.rootDetection || CONFIG.emulatorDetection) {
        installNativeFileHooks();
    }
    if (CONFIG.rootDetection || CONFIG.emulatorDetection || CONFIG.debuggerDetection) {
        installNativePropertyHooks();
    }
    if (CONFIG.debuggerDetection) installNativeDebuggerHooks();
    if (CONFIG.processTermination) installNativeTerminationHooks();
    if (CONFIG.fridaDetection) installFridaConcealment();
}

function status() {
    return {
        version: VERSION,
        pid: SELF_PID,
        architecture: Process.arch,
        nativeHooks: STATE.nativeHooks,
        javaHooks: STATE.javaHooks,
        bypasses: STATE.bypasses,
        config: CONFIG
    };
}

rpc.exports = {
    status: status
};

setImmediate(function () {
    info("Universal Android Bypass v" + VERSION + " starting");
    info("PID=" + SELF_PID + " arch=" + Process.arch);
    try {
        installNativeHooks();
        info("native hooks installed: " + STATE.nativeHooks);
    } catch (error) {
        warn("native hook installation failed: " + (error.stack || error));
    }
    installJavaHooks();
    info("ready; use rpc.exports.status() for counters");
});
