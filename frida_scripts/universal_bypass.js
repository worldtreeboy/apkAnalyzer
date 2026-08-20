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

const VERSION = "2.1.0";

const MAX_LOG_CHARS = 1200;
const MAX_BYPASS_KEY_CHARS = 256;
const MAX_NATIVE_STRING_BYTES = 4096;
const BLOCKED_FRIDA_PORTS = Object.freeze({ 27042: true, 27043: true, 27044: true });

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
    nativeErrors: 0,
    javaHooks: 0,
    bypasses: 0,
    seenCount: 0,
    seen: Object.create(null),
    attached: Object.create(null),
    listeners: Object.create(null),
    replacements: [],
    callbacks: [],
    moduleObserver: null,
    nativeReady: false,
    javaState: "pending",
    javaErrors: 0,
    java: Object.create(null)
};

const NULL_PTR = ptr(0);
const SELF_PID = Process.id;

function boundedString(value, maxChars) {
    const text = safeString(value);
    const limit = Math.max(0, Number(maxChars) || 0);
    if (text.length <= limit) return text;
    return text.slice(0, limit) + "\u2026";
}

function terminalSafe(value, maxChars) {
    const text = boundedString(value, maxChars);
    let output = "";

    for (let i = 0; i < text.length; i++) {
        const code = text.charCodeAt(i);
        if (code === 0x0a) {
            output += "\\n";
        } else if (code === 0x0d) {
            output += "\\r";
        } else if (code === 0x09) {
            output += "\\t";
        } else if (code <= 0x1f || (code >= 0x7f && code <= 0x9f)) {
            output += "\\x" + code.toString(16).padStart(2, "0");
        } else if ((code >= 0x202a && code <= 0x202e) ||
                (code >= 0x2066 && code <= 0x2069) ||
                code === 0x200e || code === 0x200f ||
                code === 0x2028 || code === 0x2029) {
            output += "\\u" + code.toString(16).padStart(4, "0");
        } else if (code >= 0xd800 && code <= 0xdbff) {
            const next = i + 1 < text.length ? text.charCodeAt(i + 1) : 0;
            if (next >= 0xdc00 && next <= 0xdfff) {
                output += text[i] + text[i + 1];
                i++;
            } else {
                output += "\ufffd";
            }
        } else if (code >= 0xdc00 && code <= 0xdfff) {
            output += "\ufffd";
        } else {
            output += text[i];
        }
    }
    return output;
}

function log(level, message) {
    console.log("[UniversalBypass][" + terminalSafe(level, 16) + "] " +
        terminalSafe(message, MAX_LOG_CHARS));
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
    const boundedKey = terminalSafe(key, MAX_BYPASS_KEY_CHARS);
    if (!STATE.seen[boundedKey] && STATE.seenCount < 512) {
        STATE.seen[boundedKey] = true;
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

function readCString(address, maxBytes) {
    try {
        if (!address || address.isNull()) return "";
        let limit = maxBytes === undefined || maxBytes === null ?
            MAX_NATIVE_STRING_BYTES : Number(maxBytes);
        if (!Number.isFinite(limit) || limit <= 0) return "";
        limit = Math.min(MAX_NATIVE_STRING_BYTES, Math.floor(limit));

        if (typeof Process.findRangeByAddress === "function") {
            // Android 11+ commonly uses top-byte-tagged arm64 heap pointers.
            // /proc/maps ranges are untagged, but the original pointer must be
            // retained for the actual read so MTE/TBI semantics stay intact.
            const rangeAddress = Process.arch === "arm64" &&
                    typeof address.and === "function" ?
                address.and(ptr("0x00ffffffffffffff")) : address;
            const range = Process.findRangeByAddress(rangeAddress);
            if (!range || safeString(range.protection).indexOf("r") === -1) return "";
            const offset = parseInt(rangeAddress.sub(range.base).toString(), 16);
            if (!Number.isFinite(offset) || offset < 0 || offset >= range.size) return "";
            limit = Math.min(limit, Math.floor(range.size - offset));
        }

        if (limit <= 0) return "";
        const bytes = new Uint8Array(address.readByteArray(limit));
        let nul = -1;
        for (let i = 0; i < bytes.length; i++) {
            if (bytes[i] === 0) {
                nul = i;
                break;
            }
        }
        if (nul === -1) return "";

        // Decode only the bytes before NUL. Frida's length-limited string
        // readers do not use the length as a C-string bound, so passing the
        // whole readable range can inspect bytes beyond the terminator.
        try {
            if (nul > 0 && typeof address.readUtf8String === "function") {
                return address.readUtf8String(nul);
            }
        } catch (_) {
            // Preserve ASCII security markers even when the native bytes are
            // not valid UTF-8 or the mapping changes between the two reads.
        }
        let value = "";
        for (let i = 0; i < nul; i++) {
            value += String.fromCharCode(bytes[i]);
        }
        return value;
    } catch (_) {
        return "";
    }
}

function containsAny(value, values) {
    const lower = boundedString(value, 32768).toLowerCase();
    for (let i = 0; i < values.length; i++) {
        if (lower.indexOf(values[i]) !== -1) return true;
    }
    return false;
}

function findExport(name, moduleName) {
    if (moduleName) {
        try {
            const module = Process.findModuleByName(moduleName);
            if (module) {
                const address = module.findExportByName(name);
                if (address) return address;
            }
        } catch (_) {
            // Use the Frida 16 module-scoped API below when available.
        }

        try {
            if (typeof Module.findExportByName === "function") {
                return Module.findExportByName(moduleName, name);
            }
        } catch (_) {
            // The export is unavailable in the requested module.
        }
        return null;
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
        // The global export is unavailable.
    }
    return null;
}

function attachAt(label, address, callbacks) {
    if (!address) return false;
    const key = label + "@" + address.toString();
    if (STATE.attached[key]) return false;
    try {
        const listener = Interceptor.attach(address, callbacks);
        STATE.attached[key] = true;
        STATE.listeners[key] = { address: address, listener: listener };
        STATE.nativeHooks++;
        debug("native hook installed: " + label);
        return true;
    } catch (error) {
        STATE.nativeErrors++;
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
        STATE.nativeErrors++;
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
            path.indexOf("/mnt/expand/") !== -1 ||
            path.indexOf("/system/app/") !== -1 ||
            path.indexOf("/system/priv-app/") !== -1 ||
            path.indexOf("/system_ext/app/") !== -1 ||
            path.indexOf("/system_ext/priv-app/") !== -1 ||
            path.indexOf("/product/app/") !== -1 ||
            path.indexOf("/product/priv-app/") !== -1 ||
            path.indexOf("/vendor/app/") !== -1 ||
            path.indexOf("/vendor/priv-app/") !== -1;
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

function nextJavaHelperClassName(simpleName) {
    STATE.java.helperClassSequence = (STATE.java.helperClassSequence || 0) + 1;
    return "org.apkAnalyzer.frida." + simpleName + "_" + SELF_PID + "_" +
        Date.now() + "_" + STATE.java.helperClassSequence;
}

// -------------------------------------------------------------------------
// TLS pinning bypass - Java
// -------------------------------------------------------------------------

function getOrCreateTrustManager() {
    if (STATE.java.trustManagers) return STATE.java.trustManagers;

    const X509TrustManager = javaUse("javax.net.ssl.X509TrustManager");
    if (!X509TrustManager) return null;

    try {
        const TrustAllManager = Java.registerClass({
            name: nextJavaHelperClassName("TrustAllManager"),
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function () {},
                checkServerTrusted: function () {},
                getAcceptedIssuers: function () {
                    return Java.array("java.security.cert.X509Certificate", []);
                }
            }
        });
        STATE.java.trustManagers = Java.array(
            "javax.net.ssl.TrustManager",
            [TrustAllManager.$new()]
        );
        return STATE.java.trustManagers;
    } catch (error) {
        STATE.javaErrors++;
        warn("trust-all manager creation failed: " + error);
        return null;
    }
}

function getOrCreateHostnameVerifier() {
    if (STATE.java.hostnameVerifier) return STATE.java.hostnameVerifier;

    const HostnameVerifier = javaUse("javax.net.ssl.HostnameVerifier");
    if (!HostnameVerifier) return null;

    try {
        const AllowAllVerifier = Java.registerClass({
            name: nextJavaHelperClassName("AllowAllHostnameVerifier"),
            implements: [HostnameVerifier],
            methods: {
                verify: function (hostname) {
                    bypass("hostname:" + hostname, "accepted TLS hostname: " + hostname);
                    return true;
                }
            }
        });
        STATE.java.hostnameVerifier = AllowAllVerifier.$new();
        return STATE.java.hostnameVerifier;
    } catch (error) {
        STATE.javaErrors++;
        warn("allow-all HostnameVerifier creation failed: " + error);
        return null;
    }
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

function hookSuccessfulVerifier(className, methodName, description) {
    hookJavaOverloads(className, methodName, function (overload) {
        const returnType = safeString(overload.returnType.className);
        if (returnType !== "void" && returnType !== "boolean") {
            throw new Error("unsupported verifier return type: " + returnType);
        }
        return function () {
            bypass(className + ":" + methodName, description || ("bypassed " + className));
            return returnType === "boolean" ? true : undefined;
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
    hookSuccessfulVerifier(
        "org.apache.http.conn.ssl.AbstractVerifier",
        "verify",
        "bypassed Apache HTTP hostname verification"
    );
    hookSuccessfulVerifier(
        "ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier",
        "verify",
        "bypassed HttpClientAndroidLib hostname verification"
    );
    [
        "com.android.org.conscrypt.OpenSSLSocketImpl",
        "com.android.org.conscrypt.OpenSSLEngineSocketImpl",
        "org.conscrypt.OpenSSLSocketImpl"
    ].forEach(function (className) {
        hookSuccessfulVerifier(
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
    "/vendor/bin/su", "/system_ext/bin/su", "/data/local/su", "/data/local/bin/su",
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
    "me.weishu.kernelsu", "me.bmax.apatch", "com.devadvance.rootcloak",
    "com.devadvance.rootcloakplus", "com.zachspong.temprootremovejb",
    "com.amphoras.hidemyroot", "com.amphoras.hidemyrootadfree",
    "com.formyhm.hiderootpremium", "com.formyhm.hideroot"
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
    let value = boundedString(path, 32768).toLowerCase();
    if (!value) return "";
    value = value.replace(/\/+/g, "/");

    const absolute = value[0] === "/";
    const output = [];
    value.split("/").forEach(function (part) {
        if (!part || part === ".") return;
        if (part === "..") {
            if (output.length > 0 && output[output.length - 1] !== "..") {
                output.pop();
            } else if (!absolute) {
                output.push(part);
            }
            return;
        }
        output.push(part);
    });

    if (absolute) {
        return "/" + output.join("/");
    }
    return output.join("/");
}

function isBlockedPath(path) {
    const normalized = normalizePath(path);
    if (CONFIG.rootDetection && ROOT_PATH_SET[normalized]) return true;
    if (CONFIG.emulatorDetection && EMULATOR_PATH_SET[normalized]) return true;
    return false;
}

function isBlockedPackage(packageName) {
    const normalized = boundedString(packageName, 512).toLowerCase();
    if (CONFIG.rootDetection && ROOT_PACKAGE_SET[normalized]) return true;
    if (CONFIG.emulatorDetection && EMULATOR_PACKAGE_SET[normalized]) return true;
    return false;
}

const ROOT_COMMAND_SET = Object.create(null);
["su", "busybox", "magisk", "resetprop"].forEach(function (item) {
    ROOT_COMMAND_SET[item] = true;
});

const PATH_PROBE_COMMAND_SET = Object.create(null);
["[", "[[", "cat", "ls", "readlink", "stat", "test"].forEach(function (item) {
    PATH_PROBE_COMMAND_SET[item] = true;
});

function executableBasename(value) {
    const normalized = normalizePath(value);
    const slash = normalized.lastIndexOf("/");
    return slash === -1 ? normalized : normalized.slice(slash + 1);
}

function isRootExecutable(value) {
    return CONFIG.rootDetection && !!ROOT_COMMAND_SET[executableBasename(value)];
}

const SHELL_COMMAND_PREFIX_SET = Object.freeze({
    "!": true,
    "{": true,
    "if": true,
    "then": true,
    "elif": true,
    "else": true,
    "while": true,
    "until": true,
    "do": true
});

const SHELL_COMMAND_END_SET = Object.freeze({
    "}": true,
    "fi": true,
    "done": true,
    "esac": true
});

function tokenizeShellCommands(command) {
    const value = boundedString(command, 32768);
    const commands = [];
    let parts = [];
    let token = "";
    let tokenStarted = false;
    let quote = "";
    let escaped = false;

    function finishToken() {
        if (!tokenStarted) return;
        if (parts.length < 128) parts.push(token);
        token = "";
        tokenStarted = false;
    }

    function finishCommand() {
        finishToken();
        if (parts.length > 0 && commands.length < 64) commands.push(parts);
        parts = [];
    }

    for (let i = 0; i < value.length; i++) {
        const character = value[i];

        if (escaped) {
            if (token.length < 4096) token += character;
            tokenStarted = true;
            escaped = false;
            continue;
        }

        if (quote === "'") {
            if (character === "'") {
                quote = "";
            } else if (token.length < 4096) {
                token += character;
            }
            tokenStarted = true;
            continue;
        }

        if (quote === "\"") {
            if (character === "\"") {
                quote = "";
            } else if (character === "\\") {
                escaped = true;
            } else if (token.length < 4096) {
                token += character;
            }
            tokenStarted = true;
            continue;
        }

        if (character === "\\") {
            escaped = true;
            tokenStarted = true;
        } else if (character === "'" || character === "\"") {
            quote = character;
            tokenStarted = true;
        } else if (character === "#" && !tokenStarted) {
            finishCommand();
            while (i + 1 < value.length && value[i + 1] !== "\n") i++;
        } else if (character === ";" || character === "|" || character === "&" ||
                character === "\n" || character === ")" ||
                (character === "(" && !tokenStarted)) {
            finishCommand();
        } else if (/\s/.test(character)) {
            finishToken();
        } else {
            if (token.length < 4096) token += character;
            tokenStarted = true;
        }
    }

    if (escaped && token.length < 4096) token += "\\";
    finishCommand();
    return commands;
}

function shellCommandSubstitutions(command) {
    const value = boundedString(command, 32768);
    const substitutions = [];
    let quote = "";
    let escaped = false;
    let atTokenStart = true;

    for (let i = 0; i < value.length && substitutions.length < 32; i++) {
        const character = value[i];

        if (escaped) {
            escaped = false;
            atTokenStart = false;
            continue;
        }
        if (character === "\\" && quote !== "'") {
            escaped = true;
            atTokenStart = false;
            continue;
        }
        if (quote === "'") {
            if (character === "'") quote = "";
            continue;
        }
        if (character === "'" && !quote) {
            quote = "'";
            atTokenStart = false;
            continue;
        }
        if (character === "\"") {
            quote = quote === "\"" ? "" : "\"";
            atTokenStart = false;
            continue;
        }
        if (!quote && character === "#" && atTokenStart) {
            while (i + 1 < value.length && value[i + 1] !== "\n") i++;
            atTokenStart = true;
            continue;
        }
        if (character === "`" && quote !== "'") {
            let end = i + 1;
            let innerEscaped = false;
            for (; end < value.length; end++) {
                if (innerEscaped) {
                    innerEscaped = false;
                } else if (value[end] === "\\") {
                    innerEscaped = true;
                } else if (value[end] === "`") {
                    break;
                }
            }
            if (end < value.length) {
                substitutions.push(value.slice(i + 1, end));
                i = end;
            }
            atTokenStart = false;
            continue;
        }
        if (character === "$" && value[i + 1] === "(" &&
                value[i + 2] !== "(") {
            let depth = 1;
            let innerQuote = "";
            let innerEscaped = false;
            let end = i + 2;
            for (; end < value.length; end++) {
                const inner = value[end];
                if (innerEscaped) {
                    innerEscaped = false;
                    continue;
                }
                if (inner === "\\" && innerQuote !== "'") {
                    innerEscaped = true;
                    continue;
                }
                if (innerQuote === "'") {
                    if (inner === "'") innerQuote = "";
                    continue;
                }
                if (inner === "'" && !innerQuote) {
                    innerQuote = "'";
                    continue;
                }
                if (inner === "\"") {
                    innerQuote = innerQuote === "\"" ? "" : "\"";
                    continue;
                }
                if (innerQuote) continue;
                if (inner === "(") {
                    depth++;
                } else if (inner === ")") {
                    depth--;
                    if (depth === 0) break;
                }
            }
            if (depth === 0) {
                substitutions.push(value.slice(i + 2, end));
                i = end;
            }
            atTokenStart = false;
            continue;
        }

        if (!quote && (/\s/.test(character) ||
                character === ";" || character === "|" || character === "&" ||
                character === "(" || character === ")")) {
            atTokenStart = true;
        } else {
            atTokenStart = false;
        }
    }
    return substitutions;
}

function shellCommandParts(parts) {
    let index = 0;
    while (index < parts.length &&
            /^[A-Za-z_][A-Za-z0-9_]*=/.test(safeString(parts[index]))) {
        index++;
    }

    while (index < parts.length) {
        const executable = executableBasename(parts[index]);
        if (SHELL_COMMAND_END_SET[executable]) return [];
        if (!SHELL_COMMAND_PREFIX_SET[executable]) break;
        index++;
        while (index < parts.length &&
                /^[A-Za-z_][A-Za-z0-9_]*=/.test(safeString(parts[index]))) {
            index++;
        }
    }
    return parts.slice(index);
}

function isSuspiciousCommandParts(parts, depth, shellSyntax) {
    if (!parts || parts.length === 0 || depth > 4) return false;
    const commandParts = shellSyntax ? shellCommandParts(parts) : parts;
    if (commandParts.length === 0) return false;

    const executable = executableBasename(commandParts[0]);
    if (!executable) return false;
    if (isRootExecutable(commandParts[0])) return true;

    if (executable === "getprop") {
        if (commandParts.length === 1) {
            return CONFIG.rootDetection || CONFIG.emulatorDetection || CONFIG.debuggerDetection;
        }
        return spoofedProperty(safeString(commandParts[1]).toLowerCase()) !== undefined;
    }

    if (CONFIG.rootDetection && (executable === "which" || executable === "type")) {
        for (let i = 1; i < commandParts.length; i++) {
            if (safeString(commandParts[i])[0] !== "-" &&
                    isRootExecutable(commandParts[i])) return true;
        }
    }

    if (CONFIG.rootDetection && executable === "command") {
        let commandIndex = 1;
        while (commandIndex < commandParts.length &&
                safeString(commandParts[commandIndex])[0] === "-") {
            commandIndex++;
        }
        if (commandIndex < commandParts.length &&
                isRootExecutable(commandParts[commandIndex])) return true;
    }

    if (CONFIG.rootDetection && PATH_PROBE_COMMAND_SET[executable]) {
        for (let i = 1; i < commandParts.length; i++) {
            if (isBlockedPath(commandParts[i])) return true;
        }
    }

    if (executable === "env") {
        let commandIndex = 1;
        while (commandIndex < commandParts.length &&
                (/^[A-Za-z_][A-Za-z0-9_]*=/.test(safeString(commandParts[commandIndex])) ||
                 safeString(commandParts[commandIndex])[0] === "-")) {
            commandIndex++;
        }
        return isSuspiciousCommandParts(
            commandParts.slice(commandIndex), depth + 1, shellSyntax
        );
    }

    if (executable === "toybox" || executable === "exec" || executable === "nohup" ||
            executable === "nice") {
        return isSuspiciousCommandParts(commandParts.slice(1), depth + 1, shellSyntax);
    }

    if (shellSyntax && executable === "eval") {
        return isSuspiciousCommand(commandParts.slice(1).join(" "), depth + 1);
    }

    if (executable === "sh" || executable === "bash" || executable === "dash" ||
            executable === "ash") {
        for (let i = 1; i < commandParts.length - 1; i++) {
            if (safeString(commandParts[i]) === "-c") {
                return isSuspiciousCommand(commandParts[i + 1], depth + 1);
            }
        }
    }

    return false;
}

function isSuspiciousCommand(command, depth) {
    const nesting = depth || 0;
    if (nesting > 4) return false;
    const value = boundedString(command, 32768).trim();
    if (!value) return false;

    const substitutions = shellCommandSubstitutions(value);
    for (let i = 0; i < substitutions.length; i++) {
        if (isSuspiciousCommand(substitutions[i], nesting + 1)) return true;
    }

    const commands = tokenizeShellCommands(value);
    for (let i = 0; i < commands.length; i++) {
        if (isSuspiciousCommandParts(commands[i], nesting, true)) return true;
    }
    return false;
}

function javaCommandParts(value) {
    try {
        if (value && value.$className === "[Ljava.lang.String;") {
            const parts = [];
            for (let i = 0; i < value.length && i < 64; i++) {
                parts.push(boundedString(value[i], 4096));
            }
            return parts;
        }
    } catch (_) {
        // Treat it as a scalar below.
    }
    const scalar = boundedString(value, 32768).trim();
    return scalar ? scalar.split(/\s+/).slice(0, 64) : [];
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
    const IOException = javaUse("java.io.IOException");
    const blockedExecutable = "/system/nonexistent/.apk-analyzer-blocked-" + SELF_PID;

    hookJavaOverloads("java.lang.Runtime", "exec", function (overload) {
        return function () {
            const args = Array.prototype.slice.call(arguments);
            if (args.length > 0 && isSuspiciousCommandParts(javaCommandParts(args[0]), 0)) {
                bypass("runtime-command", "blocked a Java root/environment command probe");
                if (IOException) {
                    throw IOException.$new("Blocked security-environment command probe");
                }
                if (args[0] && args[0].$className === "[Ljava.lang.String;") {
                    args[0] = Java.array("java.lang.String", [blockedExecutable]);
                } else {
                    args[0] = blockedExecutable;
                }
            }
            return overload.apply(this, args);
        };
    });

    const ProcessBuilder = javaUse("java.lang.ProcessBuilder");
    if (!ProcessBuilder) return;
    try {
        const start = ProcessBuilder.start.overload();
        start.implementation = function () {
            let blocked = false;
            try {
                const command = this.command();
                const parts = [];
                for (let i = 0; i < command.size() && i < 64; i++) {
                    parts.push(safeString(command.get(i)));
                }
                blocked = isSuspiciousCommandParts(parts, 0);
                if (blocked && !IOException) {
                    command.clear();
                    command.add(blockedExecutable);
                }
            } catch (error) {
                debug("ProcessBuilder command inspection failed: " + error);
            }
            if (blocked) {
                bypass("process-builder-command", "blocked a ProcessBuilder root/environment probe");
                if (IOException) {
                    throw IOException.$new("Blocked security-environment command probe");
                }
            }
            return start.call(this);
        };
        markJavaHook("ProcessBuilder.start");
    } catch (error) {
        debug("ProcessBuilder.start hook unavailable: " + error);
    }
}

function packageNameFromQuery(value) {
    try {
        if (value && value.$className === "android.content.pm.VersionedPackage" &&
                typeof value.getPackageName === "function") {
            return safeString(value.getPackageName());
        }
    } catch (error) {
        debug("VersionedPackage inspection failed: " + error);
    }
    return safeString(value);
}

function hookPackageManager() {
    const className = "android.app.ApplicationPackageManager";
    const NameNotFoundException = javaUse(
        "android.content.pm.PackageManager$NameNotFoundException"
    );

    ["getPackageInfo", "getApplicationInfo", "getPackageUid", "getPackageGids"].forEach(
        function (methodName) {
            hookJavaOverloads(className, methodName, function (overload) {
                return function () {
                    const args = Array.prototype.slice.call(arguments);
                    const requested = args.length > 0 ? packageNameFromQuery(args[0]) : "";
                    if (NameNotFoundException && isBlockedPackage(requested)) {
                        bypass("package:" + requested,
                            "hid root/emulator package " + requested);
                        throw NameNotFoundException.$new(requested);
                    }
                    return overload.apply(this, args);
                };
            });
        }
    );

    ["getLaunchIntentForPackage", "getLeanbackLaunchIntentForPackage"].forEach(
        function (methodName) {
            hookJavaOverloads(className, methodName, function (overload) {
                return function () {
                    const requested = arguments.length > 0 ?
                        packageNameFromQuery(arguments[0]) : "";
                    if (isBlockedPackage(requested)) {
                        bypass("package-launch:" + requested,
                            "hid root/emulator launch intent for " + requested);
                        return null;
                    }
                    return overload.apply(this, arguments);
                };
            });
        }
    );

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
        "isRooted", "isRootedWithoutBusyBoxCheck", "isRootedWithBusyBoxCheck",
        "detectRootManagementApps", "detectPotentiallyDangerousApps",
        "detectRootCloakingApps", "checkForBinary", "checkForDangerousProps",
        "checkForRWPaths", "detectTestKeys", "checkSuExists", "checkForRootNative",
        "checkForMagiskBinary", "checkForSuBinary", "checkForBusyBoxBinary"
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
    if (!CONFIG.rootDetection && !CONFIG.emulatorDetection) return;
    const Build = javaUse("android.os.Build");
    if (!Build) return;

    const emulatorMarkers = [
        "generic", "unknown", "emulator", "sdk_gphone", "google_sdk", "vbox",
        "genymotion", "goldfish", "ranchu", "nox", "bluestacks", "test-keys",
        "android sdk built for", "emu64", "windows_x86_64", "windows_arm64",
        "microsoft corporation", "sdk_google", "vbox86p", "vbox86", "memu",
        "ldplayer", "droid4x", "ttvm", "noxplayer"
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
            const emulatorValue = CONFIG.emulatorDetection &&
                containsAny(current, emulatorMarkers);
            const lower = current.toLowerCase();
            const rootedValue = CONFIG.rootDetection && (
                (field === "TAGS" && lower.indexOf("test-keys") !== -1) ||
                (field === "TYPE" && (lower === "eng" || lower === "userdebug")) ||
                (field === "FINGERPRINT" &&
                    (lower.indexOf("test-keys") !== -1 ||
                     /(?:^|[:/])(eng|userdebug)(?:[/:.-]|$)/.test(lower)))
            );
            if (emulatorValue || rootedValue) {
                Build[field].value = replacements[field];
                bypass("build:" + field, "spoofed security-sensitive Build." + field);
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
    if (CONFIG.rootDetection || CONFIG.emulatorDetection || CONFIG.debuggerDetection) {
        hookRuntimeCommands();
    }
    hookJavaSystemProperties();
    if (CONFIG.rootDetection) hookRootBeer();
    if (CONFIG.emulatorDetection || CONFIG.debuggerDetection) {
        hookDeveloperSettings();
    }
    if (CONFIG.rootDetection || CONFIG.emulatorDetection) spoofBuildFields();
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

function isBlockedJavaSocketAddress(endpoint) {
    try {
        if (!endpoint || typeof endpoint.getPort !== "function") return false;
        const port = Number(endpoint.getPort());
        if (!BLOCKED_FRIDA_PORTS[port]) return false;

        const address = typeof endpoint.getAddress === "function" ?
            endpoint.getAddress() : null;
        if (address && typeof address.isLoopbackAddress === "function" &&
                address.isLoopbackAddress()) {
            return true;
        }

        const host = boundedString(
            typeof endpoint.getHostString === "function" ?
                endpoint.getHostString() : endpoint,
            256
        ).toLowerCase().replace(/^\[|\]$/g, "");
        return host === "localhost" || host === "ip6-localhost" || host === "::1" ||
            /^127(?:\.\d{1,3}){3}$/.test(host);
    } catch (error) {
        debug("Java socket-address inspection failed: " + error);
        return false;
    }
}

function installJavaFridaHooks() {
    const ConnectException = javaUse("java.net.ConnectException");
    if (!ConnectException) return;

    ["java.net.Socket", "sun.nio.ch.SocketChannelImpl"].forEach(function (className) {
        hookJavaOverloads(className, "connect", function (overload) {
            return function () {
                if (arguments.length > 0 && isBlockedJavaSocketAddress(arguments[0])) {
                    bypass("java-frida-port",
                        "blocked a Java loopback Frida port probe");
                    throw ConnectException.$new("Connection refused");
                }
                return overload.apply(this, arguments);
            };
        });
    });
}

function installJavaHooks() {
    if (typeof Java === "undefined" || !Java.available) {
        STATE.javaState = "unavailable";
        warn("Java hooks skipped; Java bridge is unavailable");
        return;
    }

    STATE.javaState = "pending";
    try {
        Java.perform(function () {
            [
                { name: "TLS", enabled: CONFIG.sslPinning, install: installJavaTlsHooks },
                {
                    name: "environment",
                    enabled: CONFIG.rootDetection || CONFIG.emulatorDetection ||
                        CONFIG.debuggerDetection,
                    install: installJavaEnvironmentHooks
                },
                {
                    name: "debugger",
                    enabled: CONFIG.debuggerDetection,
                    install: installJavaDebuggerHooks
                },
                {
                    name: "termination",
                    enabled: CONFIG.processTermination,
                    install: installJavaTerminationHooks
                },
                {
                    name: "anti-Frida",
                    enabled: CONFIG.fridaDetection,
                    install: installJavaFridaHooks
                }
            ].forEach(function (family) {
                if (!family.enabled) return;
                try {
                    family.install();
                } catch (error) {
                    STATE.javaErrors++;
                    warn("Java " + family.name + " hook installation failed: " +
                        (error.stack || error));
                }
            });
            STATE.javaState = STATE.javaErrors > 0 ? "partial" : "ready";
            info("Java hooks installed: " + STATE.javaHooks +
                " (state=" + STATE.javaState + ")");
        });
    } catch (error) {
        STATE.javaErrors++;
        STATE.javaState = "failed";
        warn("Java hook scheduling failed: " + (error.stack || error));
    }
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

function detachNativeHooksInModule(module) {
    if (!module || !module.base || !module.size) return;
    let end;
    try {
        end = module.base.add(module.size);
    } catch (_) {
        return;
    }

    Object.keys(STATE.listeners).forEach(function (key) {
        const record = STATE.listeners[key];
        let inRange = false;
        try {
            inRange = record.address.compare(module.base) >= 0 &&
                record.address.compare(end) < 0;
        } catch (error) {
            debug("native listener range check failed for " + key + ": " + error);
            return;
        }
        if (!inRange) return;

        try {
            if (record.listener && typeof record.listener.detach === "function") {
                record.listener.detach();
            }
        } catch (error) {
            debug("native listener cleanup failed for " + key + ": " + error);
        }
        delete STATE.listeners[key];
        delete STATE.attached[key];
        STATE.nativeHooks = Math.max(0, STATE.nativeHooks - 1);
    });
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
            if (result.toInt32() === 0) {
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
            },
            onRemoved: function (module) {
                detachNativeHooksInModule(module);
            }
        });
        debug("module observer installed for late-loaded TLS libraries");
        return;
    }

    ["android_dlopen_ext", "dlopen"].forEach(function (name) {
        attachExport(name, {
            onLeave: function (result) {
                if (result.isNull()) return;
                try {
                    Process.enumerateModules().forEach(installNativeTlsHooksForModule);
                } catch (error) {
                    debug("late-loaded TLS module scan failed after " + name + ": " + error);
                }
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
                if (isBlockedPath(path) ||
                        (CONFIG.rootDetection && /(^|\/)su$/.test(normalizePath(path)))) {
                    this.replacementPath = Memory.allocUtf8String(
                        "/system/nonexistent/.apk-analyzer-command"
                    );
                    args[0] = this.replacementPath;
                    bypass("native-exec:" + path, "blocked native root executable " + path);
                }
            }
        }, "libc.so", "root-exec:" + name);
    });
}

function installNativeCommandHooks() {
    replaceAt(
        "root-command:system",
        findExport("system", "libc.so"),
        "int",
        ["pointer"],
        function (original) {
            return function (commandAddress) {
                const command = readCString(commandAddress);
                if (isSuspiciousCommand(command)) {
                    bypass("native-command:" + command,
                        "blocked a native root/environment command probe");
                    return 127 << 8;
                }
                return original(commandAddress);
            };
        }
    );

    replaceAt(
        "root-command:popen",
        findExport("popen", "libc.so"),
        "pointer",
        ["pointer", "pointer"],
        function (original) {
            return function (commandAddress, modeAddress) {
                const command = readCString(commandAddress);
                if (isSuspiciousCommand(command)) {
                    this.errno = 2; // ENOENT
                    bypass("native-command:" + command,
                        "blocked a native root/environment command probe");
                    return NULL_PTR;
                }
                return original(commandAddress, modeAddress);
            };
        }
    );
}

function installNativePropertyHooks() {
    attachExport("__system_property_get", {
        onEnter: function (args) {
            this.name = readCString(args[0], 128);
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

        const name = readCString(nameAddress, 128);
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

const LETHAL_SIGNALS = { 6: true, 9: true, 15: true };

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
const MAX_PROC_SANITIZE_BYTES = 1024 * 1024;

function isSensitiveProcPath(path) {
    const normalized = normalizePath(path);
    if (!/^\/proc\/(self|thread-self|\d+)\//.test(normalized)) return false;
    return /\/(maps|smaps|status|mounts|mountinfo)$/.test(normalized) ||
        /\/task\/\d+\/(maps|smaps|status|stat|comm)$/.test(normalized);
}

function isJavaIoAddress(address) {
    try {
        const module = Process.findModuleByAddress(address);
        if (!module) return false;
        const name = safeString(module.name).toLowerCase();
        return name === "libopenjdk.so" || name === "libjavacore.so";
    } catch (_) {
        return false;
    }
}

function trackProcOpen(name, pathIndex) {
    attachExport(name, {
        onEnter: function (args) {
            this.procPath = readCString(args[pathIndex]);
            this.trackProc = (isApplicationAddress(this.returnAddress) ||
                isJavaIoAddress(this.returnAddress)) &&
                isSensitiveProcPath(this.procPath);
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
        const inspectedLength = Math.min(length, MAX_PROC_SANITIZE_BYTES);
        data = new Uint8Array(buffer.readByteArray(inspectedLength));
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

    if (changed) {
        try {
            buffer.writeByteArray(data);
        } catch (_) {
            return false;
        }
    }
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
            this.fd = args[0].toInt32();
        },
        onLeave: function (result) {
            if (result.toInt32() === 0) delete PROC_FDS[this.fd];
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

    attachExport("fcntl", {
        onEnter: function (args) {
            this.sourceFd = args[0].toInt32();
            const command = args[1].toInt32();
            this.duplicatesFd = command === 0 || command === 1030; // F_DUPFD[_CLOEXEC]
        },
        onLeave: function (result) {
            if (!this.duplicatesFd) return;
            const newFd = result.toInt32();
            if (newFd >= 0 && PROC_FDS[this.sourceFd]) {
                PROC_FDS[newFd] = PROC_FDS[this.sourceFd];
            }
        }
    }, "libc.so", "frida-proc-fcntl-dup");

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
                    containsAny(readCString(args[1], 512), FRIDA_MARKERS);
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
            const line = readCString(this.buffer, Math.min(this.capacity, 4096));
            if (!containsAny(line, FRIDA_MARKERS)) return;
            this.buffer.writeByteArray([0x0a, 0x00]);
            bypass("frida-fgets", "filtered a Frida marker from an app-native text scan");
        }
    }, "libc.so", "frida-fgets");
}

function installReadlinkConcealment() {
    let replacementPath = Process.pointerSize === 8 ?
        "/system/lib64/libc.so" : "/system/lib/libc.so";
    try {
        const libc = Process.findModuleByName("libc.so");
        if (libc && libc.path) replacementPath = libc.path;
    } catch (_) {
        // Keep the architecture-appropriate fallback path.
    }

    [
        { name: "readlink", buffer: 1, size: 2 },
        { name: "readlinkat", buffer: 2, size: 3 }
    ].forEach(function (spec) {
        attachExport(spec.name, {
            onEnter: function (args) {
                this.buffer = args[spec.buffer];
                const capacity = args[spec.size];
                this.capacity = capacity.compare(ptr(replacementPath.length)) >= 0 ?
                    replacementPath.length : Math.max(0, capacity.toInt32());
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

                const bytes = [];
                const count = Math.min(replacementPath.length, this.capacity);
                for (let i = 0; i < count; i++) bytes.push(replacementPath.charCodeAt(i));
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
            const capacity = args[2];
            this.capacity = capacity.compare(ptr(16)) >= 0 ?
                16 : Math.max(0, capacity.toInt32());
            this.appCaller = isApplicationAddress(this.returnAddress);
        },
        onLeave: function (result) {
            if (!this.appCaller || result.toInt32() !== 0 || this.capacity < 2) return;
            const name = readCString(this.buffer, this.capacity);
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
            const name = readCString(this.buffer, 16);
            if (!containsAny(name, FRIDA_MARKERS)) return;
            this.buffer.writeUtf8String(("Binder:" + SELF_PID).slice(0, 15));
            bypass("frida-prctl", "hid Frida thread name from prctl");
        }
    }, "libc.so", "frida-prctl-name");
}

function installFridaPortConcealment() {
    replaceAt(
        "frida-port-probe",
        findExport("connect", "libc.so"),
        "int",
        ["int", "pointer", "uint32"],
        function (original) {
            return function (socketFd, address, length) {
                if (!isApplicationAddress(this.returnAddress) || address.isNull() ||
                        length < 4 || length > 128) {
                    return original(socketFd, address, length);
                }

                let port = 0;
                let loopback = false;
                try {
                    const family = address.readU16();
                    port = (address.add(2).readU8() << 8) | address.add(3).readU8();
                    if (!BLOCKED_FRIDA_PORTS[port]) {
                        return original(socketFd, address, length);
                    }

                    if (family === 2 && length >= 8) { // AF_INET
                        loopback = address.add(4).readU8() === 127;
                    } else if (family === 10 && length >= 24) { // AF_INET6
                        loopback = true;
                        for (let i = 0; i < 15; i++) {
                            if (address.add(8 + i).readU8() !== 0) loopback = false;
                        }
                        if (address.add(23).readU8() !== 1) loopback = false;

                        if (!loopback) {
                            let mapped = true;
                            for (let i = 0; i < 10; i++) {
                                if (address.add(8 + i).readU8() !== 0) mapped = false;
                            }
                            mapped = mapped &&
                                address.add(18).readU8() === 0xff &&
                                address.add(19).readU8() === 0xff &&
                                address.add(20).readU8() === 127;
                            loopback = mapped;
                        }
                    }
                } catch (error) {
                    debug("connect inspection failed: " + error);
                    return original(socketFd, address, length);
                }

                if (!loopback) return original(socketFd, address, length);

                this.errno = 111; // ECONNREFUSED
                bypass("frida-port:" + port, "blocked loopback Frida port probe " + port);
                return -1;
            };
        }
    );
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
        installNativeCommandHooks();
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
        nativeErrors: STATE.nativeErrors,
        javaHooks: STATE.javaHooks,
        bypasses: STATE.bypasses,
        nativeReady: STATE.nativeReady,
        javaState: STATE.javaState,
        javaErrors: STATE.javaErrors,
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
        STATE.nativeReady = true;
        info("native hooks installed: " + STATE.nativeHooks);
    } catch (error) {
        STATE.nativeReady = false;
        warn("native hook installation failed: " + (error.stack || error));
    }
    installJavaHooks();
    info("initialization dispatched; use rpc.exports.status() for readiness and counters");
});
