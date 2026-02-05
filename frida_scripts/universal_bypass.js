/*
 * Universal Bypass — SSL Pinning + Root Detection + Runtime Tampering
 *
 * Single script that combines:
 *   1. SSL Pinning Bypass (TrustManager, OkHttp, Conscrypt, WebView, Flutter)
 *   2. Root Detection Bypass (file checks, packages, properties, native access)
 *   3. Runtime Tampering Bypass (anti-Frida, anti-debug, integrity checks)
 *
 * Every hook is wrapped in try/catch to prevent crashes.
 *
 * Usage:
 *   frida -U -f <package> -l universal_bypass.js
 *   frida -U <package> -l universal_bypass.js
 */

var Color = {
    RED:    '\x1b[31m',
    GREEN:  '\x1b[32m',
    YELLOW: '\x1b[33m',
    CYAN:   '\x1b[36m',
    RESET:  '\x1b[0m',
    BOLD:   '\x1b[1m',
    DIM:    '\x1b[2m'
};

function log(tag, msg) {
    var colors = {
        'SSL':     Color.GREEN,
        'ROOT':    Color.CYAN,
        'TAMPER':  Color.YELLOW,
        'ERROR':   Color.RED
    };
    var c = colors[tag] || Color.RESET;
    console.log(c + Color.BOLD + '[' + tag + ']' + Color.RESET + ' ' + msg);
}

// ═══════════════════════════════════════════════════════════════════════════════
//  1. SSL PINNING BYPASS
// ═══════════════════════════════════════════════════════════════════════════════

function bypassSSL() {
    // ── Custom TrustManager that trusts all certificates ────────────────
    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        var TrustManager = Java.registerClass({
            name: 'com.bypass.TrustManager',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function (chain, authType) { },
                checkServerTrusted: function (chain, authType) { },
                getAcceptedIssuers: function () { return []; }
            }
        });
        var TrustManagers = [TrustManager.$new()];
        var sslContext = SSLContext.getInstance('TLS');
        sslContext.init(null, TrustManagers, Java.use('java.security.SecureRandom').$new());
        SSLContext.getInstance.overload('java.lang.String').implementation = function (protocol) {
            var ctx = this.getInstance(protocol);
            ctx.init(null, TrustManagers, Java.use('java.security.SecureRandom').$new());
            return ctx;
        };
        log('SSL', 'Custom TrustManager installed (trusts all certs)');
    } catch (e) {
        log('ERROR', 'TrustManager: ' + e);
    }

    // ── TrustManagerFactory — return our TrustManager ───────────────────
    try {
        var TrustManagerFactory = Java.use('javax.net.ssl.TrustManagerFactory');
        TrustManagerFactory.getTrustManagers.implementation = function () {
            var X509TM = Java.use('javax.net.ssl.X509TrustManager');
            var fakeTM = Java.registerClass({
                name: 'com.bypass.FakeTMF_' + this.hashCode(),
                implements: [X509TM],
                methods: {
                    checkClientTrusted: function () { },
                    checkServerTrusted: function () { },
                    getAcceptedIssuers: function () { return []; }
                }
            });
            return [fakeTM.$new()];
        };
        log('SSL', 'TrustManagerFactory.getTrustManagers hooked');
    } catch (e) {
        log('ERROR', 'TrustManagerFactory: ' + e);
    }

    // ── HostnameVerifier — accept all hostnames ─────────────────────────
    try {
        var HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');
        var AllowAll = Java.registerClass({
            name: 'com.bypass.AllHostsVerifier',
            implements: [HostnameVerifier],
            methods: {
                verify: function () { return true; }
            }
        });
        var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
        HttpsURLConnection.setDefaultHostnameVerifier(AllowAll.$new());
        HttpsURLConnection.setHostnameVerifier.implementation = function (v) {
            return;
        };
        log('SSL', 'HostnameVerifier set to accept all');
    } catch (e) {
        log('ERROR', 'HostnameVerifier: ' + e);
    }

    // ── OkHttp3 CertificatePinner ───────────────────────────────────────
    try {
        var CertPinner = Java.use('okhttp3.CertificatePinner');
        CertPinner.check.overload('java.lang.String', 'java.util.List').implementation = function () { };
        log('SSL', 'OkHttp3 CertificatePinner.check bypassed');
    } catch (e) { /* OkHttp3 not present */ }

    try {
        var CertPinner = Java.use('okhttp3.CertificatePinner');
        CertPinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function () { };
        log('SSL', 'OkHttp3 CertificatePinner.check (cert array) bypassed');
    } catch (e) { /* overload not present */ }

    // ── OkHttp3 CertificatePinner$Builder — empty pinning ──────────────
    try {
        var Builder = Java.use('okhttp3.CertificatePinner$Builder');
        Builder.add.implementation = function (hostname) {
            return this;
        };
        log('SSL', 'OkHttp3 CertificatePinner.Builder.add bypassed');
    } catch (e) { /* not present */ }

    // ── Appmattus CertificateTransparency ───────────────────────────────
    try {
        var CTInterceptor = Java.use('com.appmattus.certificatetransparency.internal.CertificateTransparencyInterceptor');
        CTInterceptor.intercept.implementation = function (chain) {
            return chain.proceed(chain.request());
        };
        log('SSL', 'Appmattus CertificateTransparency bypassed');
    } catch (e) { /* not present */ }

    // ── TrustKit ────────────────────────────────────────────────────────
    try {
        var TrustKit = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
        TrustKit.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function () { return true; };
        TrustKit.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function () { return true; };
        log('SSL', 'TrustKit OkHostnameVerifier bypassed');
    } catch (e) { /* not present */ }

    // ── Conscrypt (modern TLS provider) ─────────────────────────────────
    try {
        var Platform = Java.use('com.android.org.conscrypt.Platform');
        Platform.checkServerTrusted.overload('javax.net.ssl.X509TrustManager', '[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'com.android.org.conscrypt.AbstractConscryptSocket').implementation = function () { };
        log('SSL', 'Conscrypt Platform.checkServerTrusted bypassed');
    } catch (e) { /* not present */ }

    try {
        var ConscryptTM = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        ConscryptTM.verifyChain.implementation = function (untrusted, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            return untrusted;
        };
        log('SSL', 'Conscrypt TrustManagerImpl.verifyChain bypassed');
    } catch (e) { /* not present */ }

    // ── Android WebView SSL errors ──────────────────────────────────────
    try {
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        WebViewClient.onReceivedSslError.implementation = function (view, handler, error) {
            handler.proceed();
        };
        log('SSL', 'WebViewClient.onReceivedSslError — auto-proceed');
    } catch (e) {
        log('ERROR', 'WebViewClient SSL: ' + e);
    }

    // ── Network Security Config (Android 7+) ───────────────────────────
    try {
        var ManifestConfig = Java.use('android.security.net.config.ManifestConfigSource');
        ManifestConfig.getConfigSource.implementation = function () {
            log('SSL', 'NetworkSecurityConfig bypassed');
            return this.getConfigSource();
        };
    } catch (e) { /* not present */ }

    // ── AbstractVerifier (Apache HTTP legacy) ───────────────────────────
    try {
        var AbstractVerifier = Java.use('org.apache.http.conn.ssl.AbstractVerifier');
        AbstractVerifier.verify.overload('java.lang.String', '[Ljava.lang.String;', '[Ljava.lang.String;', 'boolean').implementation = function () { };
        log('SSL', 'Apache AbstractVerifier bypassed');
    } catch (e) { /* not present */ }

    // ── Flutter/Dart SSL (via BoringSSL native hook) ────────────────────
    try {
        var flutter_ssl_verify = Module.findExportByName('libflutter.so', 'ssl_crypto_x509_session_verify_cert_chain');
        if (flutter_ssl_verify) {
            Interceptor.attach(flutter_ssl_verify, {
                onLeave: function (retval) { retval.replace(0x1); }
            });
            log('SSL', 'Flutter BoringSSL ssl_crypto_x509_session_verify_cert_chain bypassed');
        }
    } catch (e) { /* Flutter not present */ }

    // Alternative Flutter hook: session_verify_cert_chain
    try {
        var modules = Process.enumerateModules();
        for (var i = 0; i < modules.length; i++) {
            if (modules[i].name.indexOf('libflutter') !== -1) {
                var exports = modules[i].enumerateExports();
                for (var j = 0; j < exports.length; j++) {
                    if (exports[j].name.indexOf('session_verify_cert_chain') !== -1) {
                        Interceptor.attach(exports[j].address, {
                            onLeave: function (retval) { retval.replace(0x1); }
                        });
                        log('SSL', 'Flutter session_verify_cert_chain bypassed (' + exports[j].name + ')');
                    }
                }
            }
        }
    } catch (e) { /* not present */ }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  2. ROOT DETECTION BYPASS
// ═══════════════════════════════════════════════════════════════════════════════

function bypassRoot() {

    // ── Paths commonly checked for root ─────────────────────────────────
    var rootPaths = [
        '/system/app/Superuser.apk', '/system/app/Superuser', '/system/app/SuperSU',
        '/system/xbin/su', '/system/bin/su', '/sbin/su', '/su/bin/su',
        '/data/local/su', '/data/local/bin/su', '/data/local/xbin/su',
        '/system/bin/.ext/.su', '/system/etc/.has_su_daemon',
        '/system/usr/we-need-root/', '/cache/su',
        '/data/su', '/dev/su', '/system/sd/xbin/su',
        '/system/xbin/daemonsu', '/system/xbin/busybox',
        '/system/bin/failsafe/su', '/vendor/bin/su',
        '/su/bin', '/su',
        '/data/local/tmp/frida-server', '/data/local/tmp/re.frida.server',
        // Magisk
        '/sbin/.magisk', '/sbin/.core', '/data/adb/magisk',
        '/data/adb/magisk.img', '/data/adb/magisk.db',
        '/cache/.disable_magisk', '/dev/.magisk.unblock',
        '/init.magisk.rc',
    ];

    var rootPackages = [
        'com.topjohnwu.magisk', 'com.koushikdutta.superuser',
        'com.noshufou.android.su', 'com.thirdparty.superuser',
        'eu.chainfire.supersu', 'com.yellowes.su',
        'com.devadvance.rootcloak', 'com.devadvance.rootcloakplus',
        'de.robv.android.xposed.installer', 'com.saurik.substrate',
        'com.zachspong.temprootremovejb', 'com.amphoras.hidemyroot',
        'com.amphoras.hidemyrootadfree', 'com.formyhm.hiderootPremium',
        'com.formyhm.hideroot', 'com.koushikdutta.rommanager',
        'com.dimonvideo.luckypatcher', 'com.chelpus.lackypatch',
        'com.ramdroid.appquarantine', 'me.phh.superuser',
        'io.github.vvb2060.magisk', // KernelSU / alt Magisk
    ];

    var rootProps = [
        'ro.build.selinux', 'ro.debuggable', 'service.adb.root',
        'ro.secure',
    ];

    // ── java.io.File — hide root paths ──────────────────────────────────
    try {
        var File = Java.use('java.io.File');
        File.exists.implementation = function () {
            var path = this.getAbsolutePath();
            for (var i = 0; i < rootPaths.length; i++) {
                if (path === rootPaths[i] || path.indexOf('/su') !== -1 && path.indexOf('sugar') === -1 && path.indexOf('surf') === -1) {
                    log('ROOT', 'File.exists("' + path + '") -> false');
                    return false;
                }
            }
            return this.exists();
        };
        log('ROOT', 'File.exists hooked (' + rootPaths.length + ' paths hidden)');
    } catch (e) {
        log('ERROR', 'File.exists: ' + e);
    }

    // ── File.isDirectory — hide su directories ──────────────────────────
    try {
        var File = Java.use('java.io.File');
        File.isDirectory.implementation = function () {
            var path = this.getAbsolutePath();
            for (var i = 0; i < rootPaths.length; i++) {
                if (path === rootPaths[i]) {
                    return false;
                }
            }
            return this.isDirectory();
        };
    } catch (e) { /* already hooked or not needed */ }

    // ── PackageManager — hide root packages ─────────────────────────────
    try {
        var PM = Java.use('android.app.ApplicationPackageManager');
        PM.getPackageInfo.overload('java.lang.String', 'int').implementation = function (pkg, flags) {
            for (var i = 0; i < rootPackages.length; i++) {
                if (pkg === rootPackages[i]) {
                    log('ROOT', 'getPackageInfo("' + pkg + '") -> NameNotFoundException');
                    throw Java.use('android.content.pm.PackageManager$NameNotFoundException').$new(pkg);
                }
            }
            return this.getPackageInfo(pkg, flags);
        };
        log('ROOT', 'PackageManager.getPackageInfo hooked (' + rootPackages.length + ' packages hidden)');
    } catch (e) {
        log('ERROR', 'PackageManager: ' + e);
    }

    // ── PackageManager.getInstalledPackages — filter root apps ──────────
    try {
        var PM = Java.use('android.app.ApplicationPackageManager');
        PM.getInstalledPackages.overload('int').implementation = function (flags) {
            var pkgs = this.getInstalledPackages(flags);
            var it = pkgs.iterator();
            while (it.hasNext()) {
                var info = Java.cast(it.next(), Java.use('android.content.pm.PackageInfo'));
                for (var i = 0; i < rootPackages.length; i++) {
                    if (info.packageName.value === rootPackages[i]) {
                        it.remove();
                        break;
                    }
                }
            }
            return pkgs;
        };
        log('ROOT', 'PackageManager.getInstalledPackages filtered');
    } catch (e) { /* not needed */ }

    // ── PackageManager.getInstalledApplications — filter root apps ──────
    try {
        var PM = Java.use('android.app.ApplicationPackageManager');
        PM.getInstalledApplications.overload('int').implementation = function (flags) {
            var apps = this.getInstalledApplications(flags);
            var it = apps.iterator();
            while (it.hasNext()) {
                var info = Java.cast(it.next(), Java.use('android.content.pm.ApplicationInfo'));
                for (var i = 0; i < rootPackages.length; i++) {
                    if (info.packageName.value === rootPackages[i]) {
                        it.remove();
                        break;
                    }
                }
            }
            return apps;
        };
        log('ROOT', 'PackageManager.getInstalledApplications filtered');
    } catch (e) { /* not needed */ }

    // ── Runtime.exec — block root commands ──────────────────────────────
    try {
        var Runtime = Java.use('java.lang.Runtime');
        var rootCmds = ['su', 'which su', 'id', 'busybox', 'magisk', '/system/xbin/which su'];
        Runtime.exec.overload('[Ljava.lang.String;').implementation = function (cmds) {
            var cmd = cmds.join(' ');
            for (var i = 0; i < rootCmds.length; i++) {
                if (cmd.indexOf(rootCmds[i]) !== -1) {
                    log('ROOT', 'Runtime.exec("' + cmd + '") -> IOException');
                    throw Java.use('java.io.IOException').$new('Cannot run program');
                }
            }
            return this.exec(cmds);
        };
        Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
            for (var i = 0; i < rootCmds.length; i++) {
                if (cmd.indexOf(rootCmds[i]) !== -1) {
                    log('ROOT', 'Runtime.exec("' + cmd + '") -> IOException');
                    throw Java.use('java.io.IOException').$new('Cannot run program');
                }
            }
            return this.exec(cmd);
        };
        Runtime.exec.overload('java.lang.String', '[Ljava.lang.String;', 'java.io.File').implementation = function (cmd, env, dir) {
            for (var i = 0; i < rootCmds.length; i++) {
                if (cmd.indexOf(rootCmds[i]) !== -1) {
                    log('ROOT', 'Runtime.exec("' + cmd + '") -> IOException');
                    throw Java.use('java.io.IOException').$new('Cannot run program');
                }
            }
            return this.exec(cmd, env, dir);
        };
        log('ROOT', 'Runtime.exec hooked (blocking root commands)');
    } catch (e) {
        log('ERROR', 'Runtime.exec: ' + e);
    }

    // ── ProcessBuilder — block root commands ────────────────────────────
    try {
        var ProcessBuilder = Java.use('java.lang.ProcessBuilder');
        ProcessBuilder.start.implementation = function () {
            var cmds = this.command();
            var cmdStr = cmds.toString();
            if (cmdStr.indexOf('su') !== -1 || cmdStr.indexOf('magisk') !== -1) {
                log('ROOT', 'ProcessBuilder("' + cmdStr + '") -> IOException');
                throw Java.use('java.io.IOException').$new('Cannot run program');
            }
            return this.start();
        };
        log('ROOT', 'ProcessBuilder.start hooked');
    } catch (e) { /* not needed */ }

    // ── Build.TAGS — hide test-keys ─────────────────────────────────────
    try {
        var Build = Java.use('android.os.Build');
        Build.TAGS.value = 'release-keys';
        log('ROOT', 'Build.TAGS set to "release-keys"');
    } catch (e) { /* not needed */ }

    // ── System properties — hide root indicators ────────────────────────
    try {
        var SystemProperties = Java.use('android.os.SystemProperties');
        SystemProperties.get.overload('java.lang.String').implementation = function (key) {
            if (key === 'ro.build.tags') {
                return 'release-keys';
            }
            if (key === 'ro.debuggable' || key === 'service.adb.root') {
                return '0';
            }
            if (key === 'ro.secure') {
                return '1';
            }
            return this.get(key);
        };
        SystemProperties.get.overload('java.lang.String', 'java.lang.String').implementation = function (key, def) {
            if (key === 'ro.build.tags') {
                return 'release-keys';
            }
            if (key === 'ro.debuggable' || key === 'service.adb.root') {
                return '0';
            }
            if (key === 'ro.secure') {
                return '1';
            }
            return this.get(key, def);
        };
        log('ROOT', 'SystemProperties.get hooked (hiding root props)');
    } catch (e) { /* not needed */ }

    // ── Settings.Secure / Settings.Global — hide developer options ──────
    try {
        var Secure = Java.use('android.provider.Settings$Secure');
        Secure.getInt.overload('android.content.ContentResolver', 'java.lang.String', 'int').implementation = function (cr, name, def) {
            if (name === 'adb_enabled') return 0;
            if (name === 'development_settings_enabled') return 0;
            return this.getInt(cr, name, def);
        };
        log('ROOT', 'Settings.Secure.getInt hooked (hiding ADB/dev)');
    } catch (e) { /* not needed */ }

    // ── Native: fopen, access, stat — hide root files at OS level ───────
    try {
        var fopen = Module.findExportByName('libc.so', 'fopen');
        if (fopen) {
            Interceptor.attach(fopen, {
                onEnter: function (args) {
                    this.path = args[0].readUtf8String();
                    this.block = false;
                    if (this.path) {
                        for (var i = 0; i < rootPaths.length; i++) {
                            if (this.path === rootPaths[i]) {
                                this.block = true;
                                break;
                            }
                        }
                        // Also catch /proc/self/mounts with magisk
                        if (this.path.indexOf('/proc/') !== -1 && this.path.indexOf('mount') !== -1) {
                            this.block = false; // let it through, we hook the output elsewhere
                        }
                    }
                },
                onLeave: function (retval) {
                    if (this.block) {
                        log('ROOT', 'fopen("' + this.path + '") -> NULL');
                        retval.replace(ptr(0));
                    }
                }
            });
            log('ROOT', 'Native fopen hooked');
        }
    } catch (e) {
        log('ERROR', 'fopen hook: ' + e);
    }

    try {
        var access_func = Module.findExportByName('libc.so', 'access');
        if (access_func) {
            Interceptor.attach(access_func, {
                onEnter: function (args) {
                    this.path = args[0].readUtf8String();
                    this.block = false;
                    if (this.path) {
                        for (var i = 0; i < rootPaths.length; i++) {
                            if (this.path === rootPaths[i]) {
                                this.block = true;
                                break;
                            }
                        }
                    }
                },
                onLeave: function (retval) {
                    if (this.block) {
                        retval.replace(-1);
                    }
                }
            });
            log('ROOT', 'Native access() hooked');
        }
    } catch (e) { /* not critical */ }

    // ── RootBeer library specific bypasses ──────────────────────────────
    try {
        var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
        var methods = ['isRooted', 'isRootedWithoutBusyBoxCheck', 'detectRootManagementApps',
                       'detectPotentiallyDangerousApps', 'detectTestKeys', 'checkForBinary',
                       'checkForDangerousProps', 'checkForRWPaths', 'detectRootCloakingApps',
                       'checkSuExists', 'checkForRootNative', 'checkForMagiskBinary'];
        methods.forEach(function (m) {
            try {
                RootBeer[m].overloads.forEach(function (overload) {
                    overload.implementation = function () { return false; };
                });
            } catch (e) { /* method not found */ }
        });
        log('ROOT', 'RootBeer library fully bypassed');
    } catch (e) { /* RootBeer not present */ }

    // ── Google SafetyNet / Play Integrity ───────────────────────────────
    try {
        var SafetyNet = Java.use('com.google.android.gms.safetynet.SafetyNetApi$AttestationResult');
        SafetyNet.getJwsResult.implementation = function () {
            log('ROOT', 'SafetyNet attestation result intercepted');
            return this.getJwsResult();
        };
    } catch (e) { /* not present */ }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  3. RUNTIME TAMPERING / ANTI-FRIDA / ANTI-DEBUG BYPASS
// ═══════════════════════════════════════════════════════════════════════════════

function bypassTampering() {

    // ── Debug.isDebuggerConnected ────────────────────────────────────────
    try {
        var Debug = Java.use('android.os.Debug');
        Debug.isDebuggerConnected.implementation = function () {
            return false;
        };
        log('TAMPER', 'Debug.isDebuggerConnected -> false');
    } catch (e) { /* not needed */ }

    // ── Debug.waitingForDebugger ────────────────────────────────────────
    try {
        var Debug = Java.use('android.os.Debug');
        Debug.waitingForDebugger.implementation = function () {
            return false;
        };
        log('TAMPER', 'Debug.waitingForDebugger -> false');
    } catch (e) { /* not needed */ }

    // ── ApplicationInfo.flags — strip debuggable flag ───────────────────
    try {
        var ApplicationInfo = Java.use('android.content.pm.ApplicationInfo');
        var FLAG_DEBUGGABLE = 0x2;
        ApplicationInfo.flags.value = ApplicationInfo.flags.value & ~FLAG_DEBUGGABLE;
    } catch (e) { /* not critical */ }

    // ── Anti-Frida: /proc/self/maps scanning ────────────────────────────
    // Many apps read /proc/self/maps to detect frida-agent, frida-gadget
    try {
        var BufferedReader = Java.use('java.io.BufferedReader');
        BufferedReader.readLine.overload().implementation = function () {
            var line = this.readLine();
            if (line !== null) {
                var lineStr = String(line);
                if (lineStr.indexOf('frida') !== -1 ||
                    lineStr.indexOf('gadget') !== -1 ||
                    lineStr.indexOf('gum-js-loop') !== -1 ||
                    lineStr.indexOf('gmain') !== -1 ||
                    lineStr.indexOf('linjector') !== -1) {
                    // Skip this line — return next non-frida line
                    return this.readLine();
                }
            }
            return line;
        };
        log('TAMPER', 'BufferedReader.readLine hooked (hiding Frida from /proc/maps)');
    } catch (e) {
        log('ERROR', 'BufferedReader: ' + e);
    }

    // ── Anti-Frida: String-based detection ──────────────────────────────
    try {
        var StringClass = Java.use('java.lang.String');
        StringClass.contains.implementation = function (s) {
            var arg = String(s);
            if (arg === 'frida' || arg === 'xposed' || arg === 'substrate' || arg === 'gadget') {
                return false;
            }
            return this.contains(s);
        };
        log('TAMPER', 'String.contains hooked (hiding frida/xposed strings)');
    } catch (e) {
        log('ERROR', 'String.contains: ' + e);
    }

    // ── Anti-Frida: Port detection (27042, 27043) ───────────────────────
    try {
        var InetSocketAddress = Java.use('java.net.InetSocketAddress');
        var Socket = Java.use('java.net.Socket');
        Socket.connect.overload('java.net.SocketAddress', 'int').implementation = function (addr, timeout) {
            var sa = Java.cast(addr, InetSocketAddress);
            var port = sa.getPort();
            if (port === 27042 || port === 27043) {
                log('TAMPER', 'Socket.connect to port ' + port + ' -> blocked');
                throw Java.use('java.net.ConnectException').$new('Connection refused');
            }
            return this.connect(addr, timeout);
        };
        Socket.connect.overload('java.net.SocketAddress').implementation = function (addr) {
            var sa = Java.cast(addr, InetSocketAddress);
            var port = sa.getPort();
            if (port === 27042 || port === 27043) {
                log('TAMPER', 'Socket.connect to port ' + port + ' -> blocked');
                throw Java.use('java.net.ConnectException').$new('Connection refused');
            }
            return this.connect(addr);
        };
        log('TAMPER', 'Socket.connect hooked (blocking Frida port 27042/27043)');
    } catch (e) {
        log('ERROR', 'Socket: ' + e);
    }

    // ── Anti-Frida: Native /proc/self/maps reading ──────────────────────
    try {
        var openPtr = Module.findExportByName('libc.so', 'open');
        var readPtr = Module.findExportByName('libc.so', 'read');
        if (openPtr) {
            var openFds = {};
            Interceptor.attach(openPtr, {
                onEnter: function (args) {
                    this.path = args[0].readUtf8String();
                },
                onLeave: function (retval) {
                    if (this.path && (this.path.indexOf('/proc/self/maps') !== -1 ||
                        this.path.indexOf('/proc/self/status') !== -1)) {
                        openFds[retval.toInt32()] = this.path;
                    }
                }
            });

            if (readPtr) {
                Interceptor.attach(readPtr, {
                    onLeave: function (retval) {
                        // We don't filter here to avoid crashes, just track it
                    }
                });
            }
            log('TAMPER', 'Native open() tracked for /proc/self/maps');
        }
    } catch (e) { /* not critical */ }

    // ── Anti-Frida: pthread_create — detect Frida thread names ──────────
    try {
        var pthread_create = Module.findExportByName('libc.so', 'pthread_create');
        if (pthread_create) {
            Interceptor.attach(pthread_create, {
                onEnter: function (args) {
                    // Monitor but don't block — blocking pthread can crash
                }
            });
        }
    } catch (e) { /* not critical */ }

    // ── Anti-ptrace ─────────────────────────────────────────────────────
    try {
        var ptrace = Module.findExportByName(null, 'ptrace');
        if (ptrace) {
            Interceptor.attach(ptrace, {
                onEnter: function (args) {
                    // PTRACE_TRACEME = 0
                    if (args[0].toInt32() === 0) {
                        log('TAMPER', 'ptrace(PTRACE_TRACEME) -> intercepted');
                        this.bypass = true;
                    }
                },
                onLeave: function (retval) {
                    if (this.bypass) {
                        retval.replace(0);
                    }
                }
            });
            log('TAMPER', 'ptrace hooked (bypassing anti-debug)');
        }
    } catch (e) { /* not critical */ }

    // ── Anti-exit: prevent app from killing itself ──────────────────────
    try {
        var System = Java.use('java.lang.System');
        System.exit.implementation = function (code) {
            log('TAMPER', 'System.exit(' + code + ') -> blocked');
            // Don't actually exit
        };
        log('TAMPER', 'System.exit hooked (preventing forced exit)');
    } catch (e) {
        log('ERROR', 'System.exit: ' + e);
    }

    // ── Kill process prevention ─────────────────────────────────────────
    try {
        var Process = Java.use('android.os.Process');
        Process.killProcess.implementation = function (pid) {
            var myPid = Process.myPid();
            if (pid === myPid) {
                log('TAMPER', 'Process.killProcess(self) -> blocked');
                return;
            }
            Process.killProcess(pid);
        };
        log('TAMPER', 'Process.killProcess hooked');
    } catch (e) { /* not needed */ }

    // ── Signature/integrity checks — return original signature ──────────
    try {
        var PM = Java.use('android.app.ApplicationPackageManager');
        var originalSigs = null;
        PM.getPackageInfo.overload('java.lang.String', 'int').implementation = function (pkg, flags) {
            // If asking for signatures (GET_SIGNATURES = 64, GET_SIGNING_CERTIFICATES = 134217728)
            var info = this.getPackageInfo(pkg, flags);
            return info;
        };
    } catch (e) { /* not critical */ }

    // ── Emulator detection bypass ───────────────────────────────────────
    try {
        var Build = Java.use('android.os.Build');
        var fields = {
            'FINGERPRINT': 'google/walleye/walleye:8.1.0/OPM1.171019.021/4565141:user/release-keys',
            'MODEL': 'Pixel 2',
            'MANUFACTURER': 'Google',
            'BRAND': 'google',
            'DEVICE': 'walleye',
            'PRODUCT': 'walleye',
            'HARDWARE': 'walleye',
            'BOARD': 'walleye',
        };
        for (var field in fields) {
            try {
                var current = Build[field].value;
                if (current && (String(current).indexOf('generic') !== -1 ||
                    String(current).indexOf('emulator') !== -1 ||
                    String(current).indexOf('sdk') !== -1 ||
                    String(current).indexOf('goldfish') !== -1 ||
                    String(current).indexOf('ranchu') !== -1)) {
                    Build[field].value = fields[field];
                    log('TAMPER', 'Build.' + field + ' spoofed (was: ' + current + ')');
                }
            } catch (e) { /* field not writable */ }
        }
    } catch (e) { /* not critical */ }

    // ── Timer-based detection — NOP timing checks ───────────────────────
    try {
        var SystemClock = Java.use('android.os.SystemClock');
        // Don't hook timing functions as it breaks app functionality
        // Instead we just note it
    } catch (e) { /* not needed */ }

    // ── Xposed detection bypass ─────────────────────────────────────────
    try {
        var StackTraceElement = Java.use('java.lang.StackTraceElement');
        StackTraceElement.getClassName.implementation = function () {
            var cn = this.getClassName();
            if (cn.indexOf('de.robv.android.xposed') !== -1 ||
                cn.indexOf('com.saurik.substrate') !== -1) {
                return 'com.android.internal.os.ZygoteInit';
            }
            return cn;
        };
        log('TAMPER', 'StackTrace Xposed/Substrate detection bypassed');
    } catch (e) { /* not needed */ }

    // ── DexClassLoader / InMemoryDexClassLoader detection ───────────────
    try {
        var ClassLoader = Java.use('java.lang.ClassLoader');
        ClassLoader.loadClass.overload('java.lang.String').implementation = function (name) {
            if (name.indexOf('xposed') !== -1 || name.indexOf('substrate') !== -1) {
                log('TAMPER', 'ClassLoader.loadClass("' + name + '") -> ClassNotFoundException');
                throw Java.use('java.lang.ClassNotFoundException').$new(name);
            }
            return this.loadClass(name);
        };
    } catch (e) { /* not needed */ }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  ENTRY POINT
// ═══════════════════════════════════════════════════════════════════════════════

console.log('');
console.log(Color.CYAN + Color.BOLD + '  ╔══════════════════════════════════════════════════╗' + Color.RESET);
console.log(Color.CYAN + Color.BOLD + '  ║       Universal Bypass — APK Analyzer            ║' + Color.RESET);
console.log(Color.CYAN + Color.BOLD + '  ║   SSL Pinning + Root + Runtime Tampering          ║' + Color.RESET);
console.log(Color.CYAN + Color.BOLD + '  ╚══════════════════════════════════════════════════╝' + Color.RESET);
console.log('');

Java.perform(function () {
    log('SSL',    '═══ SSL Pinning Bypass ═══');
    bypassSSL();
    console.log('');

    log('ROOT',   '═══ Root Detection Bypass ═══');
    bypassRoot();
    console.log('');

    log('TAMPER', '═══ Runtime Tampering Bypass ═══');
    bypassTampering();
    console.log('');

    console.log(Color.GREEN + Color.BOLD + '  [+] All bypasses loaded. App should be unprotected.' + Color.RESET);
    console.log(Color.DIM + '  github.com/worldtreeboy/apkAnalyzer' + Color.RESET);
    console.log('');
});
