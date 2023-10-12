/* frida script core function */

/**
 * findClass - 在当前Java虚拟机中查找指定类名称的类。
 *
 * @param {string} className - 要查找的类的名称。
 * @returns {Class|null} - 如果找到类，则返回该类的引用，否则返回null。
 *
 * @example
 * // 使用示例：
 * const className = 'com.example.MyClass';
 * const foundClass = findClass(className);
 * if (foundClass !== null) {
 *     // 对找到的类进行操作
 * } else {
 *     console.log(`无法找到类 ${className}`);
 * }
 *
 * @description
 * 该函数尝试通过使用 Java.use 和 Java.enumerateClassLoadersSync 来查找指定的类。
 * 如果成功找到类，它将返回类的引用。如果未找到类，它将返回null。
 * 注意：该函数可能会更改当前类加载器以确保正确查找类。
 *
 * @created 2023-07-13
 * @last-modified 2023-09-05 10:42
 * @author mahiro
 * @version 1.0.0
 */
function findClass(className)
{
    let clazz = null;
    try {
        clazz = Java.use(className);
    } catch (ignore) {
    }

    if (clazz == null) {
        let classLoaders = Java.enumerateClassLoadersSync();
        if (classLoaders != null) {
            classLoaders.forEach(classLoader => {
                try {
                    if (clazz == null) {
                        // try findClass
                        clazz = classLoader.findClass(className)
                        // replace classloader
                        Java.classFactory.loader = classLoader;
                    }
                }
                catch(ignore) {
                }
            });
        }
    }
    return clazz;
}


/**
 * Android类引用对象
 *
 * @namespace
 * @property {JavaClass} android_os_Process - 对android.os.Process类的引用。
 * @property {JavaClass} java_lang_Thread - 对java.lang.Thread类的引用。
 *
 * @example
 * // 使用示例：
 * const processClass = and.android_os_Process;
 * const threadClass = and.java_lang_Thread;
 *
 * // 获取进程 PID
 * and.android_os_Process.myPid()
 * // 获取进程 UID
 * and.android_os_Process.myUid()
 *
 * @description
 * 该对象包含了对Android中特定类的引用，用于在Java虚拟机中操作和监视这些类。
 * 可以使用这些引用来执行各种与类相关的操作，如方法拦截和字段访问。
 *
 * @created 2023-09-05
 * @last-modified 2023-09-05
 * @author mahiro
 * @version 1.0.0
 */
let and = {
    android_app_ActivityThread : findClass("android.app.ActivityThread"),
    android_os_Process : findClass("android.os.Process"),
    android_util_Log : findClass("android.util.Log"),
    android_view_View : findClass("android.view.View"),
    android_view_ViewGroup : findClass("android.view.ViewGroup"),

    java_lang_reflect_Modifier : findClass("java.lang.reflect.Modifier"),

    java_lang_Thread : findClass("java.lang.Thread"),
    java_util_IdentityHashMap : findClass("java.util.IdentityHashMap"),
}
let classes = {
    common : {
        Runtime : findClass("java.lang.Runtime")
    },

    server : {
        wm: {
            // RootWindowContainer: findClass("com.android.server.wm.RootWindowContainer"),
        },
    }
};

/**
 * ColorLibrary - 颜色库
 *
 *
 * @description
 * 用于修改输出文本的字体颜色和背景色。
 *
 * @created 2023-09-05
 * @last-modified 2023-09-05
 * @author mahiro
 * @version 1.0.0
 */
const ColorLibrary = {
    // 字体前景颜色表
    FontcolorMap: {
        black: '\u001b[30m',
        red: '\u001b[31m',
        green: '\u001b[32m',
        yellow: '\u001b[33m',
        blue: '\u001b[34m',
        magenta: '\u001b[35m',
        cyan: '\u001b[36m',
        white: '\u001b[37m',
        brightBlack: '\u001b[90m',
        brightRed: '\u001b[91m',
        brightGreen: '\u001b[92m',
        brightYellow: '\u001b[93m',
        brightBlue: '\u001b[94m',
        brightMagenta: '\u001b[95m',
        brightCyan: '\u001b[96m',
        brightWhite: '\u001b[97m',
    },

    // 字体背景颜色表
    BgcolorMap: {
        bgBlack: '\u001b[40m',
        bgRed: '\u001b[41m',
        bgGreen: '\u001b[42m',
        bgYellow: '\u001b[43m',
        bgBlue: '\u001b[44m',
        bgMagenta: '\u001b[45m',
        bgCyan: '\u001b[46m',
        bgWhite: '\u001b[47m',
        bgBrightBlack: '\u001b[100m',
        bgBrightRed: '\u001b[101m',
        bgBrightGreen: '\u001b[102m',
        bgBrightYellow: '\u001b[103m',
        bgBrightBlue: '\u001b[104m',
        bgBrightMagenta: '\u001b[105m',
        bgBrightCyan: '\u001b[106m',
        bgBrightWhite: '\u001b[107m'
    },

    /**
     * 修改文本颜色和背景色并返回新的文本。
     *
     * @param {string} text - 要修改颜色的文本。
     * @param {string} color - 字体颜色。默认为 'white'。
     * @param {string} backgroundColor - 背景颜色。默认为 'bgBlack'。
     * @returns {string} - 修改后的文本。
     *
     *
     * @example
     * ColorLibrary.coloredText("我是黑背景白字体");
     * ColorLibrary.coloredText("我是黑绿背景红字体", 'red', 'bgGreen');
     *
     * @description
     * 该对象包含了对Android中特定类的引用，用于在Java虚拟机中操作和监视这些类。
     * 可以使用这些引用来执行各种与类相关的操作，如方法拦截和字段访问。
     *
     * @created 2023-09-05
     * @last-modified 2023-09-05
     * @author mahiro
     * @version 1.0.0
     */
    coloredText: function(text, color = 'white', backgroundColor = 'bgBlack') {
        const resetCode = '\u001b[0m';
        const colorCode = this.FontcolorMap[color] || '';
        const bgColorCode = this.BgcolorMap[backgroundColor] || '';
        return `${bgColorCode}${colorCode}${text}${resetCode}`;
    },
};


/*
   基础功能
* */

function getStackTrace() {
    const currentThread = Java.use('java.lang.Thread').currentThread();
    const stackTrace = currentThread.getStackTrace();
    let stackTraceString = '';

    for (let i = 2; i < stackTrace.length; i++) {
        stackTraceString += '\t' + stackTrace[i].toString() + '\n';
    }

    console.log(ColorLibrary.coloredText('Backtrace: \n' + stackTraceString, 'brightWight'));
    return stackTraceString;
}
function log(text, TAG="10677")
{
    console.log("[*] " + text);
    // send("" + text);
    and.android_util_Log.i(TAG, `${text}`);
}

//////////////////////////////////////////////////////////////////////////////
// 2.0 hook 方式

function sharpHookCommon(className, methodName, overload, beforeCallback, afterCallback) {
    // 获取返回值类型
    const returnType = overload.returnType.className;
    // 获取参数类型
    const argumentTypes = overload.argumentTypes.map(argType => argType.className);
    // 获取参数类型列表
    const argumentTypesList = argumentTypes.join(', ');
    // 获取 pid uid
    const uid = and.android_os_Process.myUid();
    const pid = and.android_os_Process.myPid();

    // 保存彩色日志 返回类型与类名称和函数名称
    // example:[int android.os.Process.myPid]
    let textBody = `${ColorLibrary.coloredText(returnType, 'yellow')} ${ColorLibrary.coloredText(className, 'green')}.${ColorLibrary.coloredText(methodName, 'brightGreen')}`;

    // 保存完整日志信息
    log(ColorLibrary.coloredText('Hooking ', 'brightWight') + textBody
        + '(' + ColorLibrary.coloredText(argumentTypesList, 'brightRed') + ')');

    // 替换目标方法的实现
    overload.implementation = function() {

        // 获取回调参数
        let params = {
            className : className,
            methodName : methodName,

            thisObject : this,
            args : arguments,

            call : true,
            stack : false
        };

        // 获取参数值列表
        const args = [...arguments];
        const argumentValueList = args.map(arg => arg == null ? "null" : arg.toString()).join(', ');

        // 准备函数签名、参数列表
        let info = `${getCurrentTime()} ${uid} ${pid} ${and.java_lang_Thread.currentThread().getId()} ${textBody}(${ColorLibrary.coloredText(argumentValueList, 'brightRed')})`;
        // + '(' + ColorLibrary.coloredText(argumentValueList, 'brightRed') + ') = ';
        log(`${info} | before called`);

        // 在调用前执行前回调函数
        if (typeof beforeCallback === 'function') {
            beforeCallback(params);
        }

        if (params.stack === true) {
            getStackTrace();
        }

        if (params.call === true) {
            // 调用原始方法
            var result = overload.apply(this, arguments);

            // 在调用后执行后回调函数
            if (typeof afterCallback === 'function') {
                params.retval = result;
                afterCallback(params);
                result = params.retval;
            }

            // 打印函数签名、参数列表、返回值
            info += ' = ' + ColorLibrary.coloredText(result, 'brightBlue')
        }
        else {
            info += ' refuse'
        }

        // 输出调用后的日志
        log(`${info} | after called `);

        // 拒绝调用时 返回值做处理
        if (params.call === false) {
            // log("default return value.")
            // 返回默认值
            if (returnType === 'void') {
                return;
            } else if (returnType === 'boolean') {
                return false; // 默认返回 false
            } else if (returnType === 'int') {
                return 0; // 默认返回 0
            } else {
                return null; // 默认返回 null
            }
        }
        return result;
    };
}
// 枚举参数，表示hook的类别
var HookCategory = {
    ALL_MEMBERS: 0,
    SINGLE_FUNCTION: 1,
    CONSTRUCTOR: 2
};
function fastHook(type, name, beforeCallback= null, afterCallback= null) {
    let clazz = null;
    if (type === HookCategory.CONSTRUCTOR) {
        clazz = findClass(name);
        if (clazz == null || clazz == undefined) {
            console.log(`can't find className ${name} return ${clazz}`);
        } else {
            try {
                clazz.$init.overloads.forEach(function (overload) {
                    sharpHookCommon(name, '$init', overload, beforeCallback, afterCallback);
                });
            } catch (e) {
                console.log(e)
            }
        }
        return;
    }
    if (type === HookCategory.ALL_MEMBERS) {
        clazz = findClass(name);
        if (clazz == null) {
            console.log(`can't find className ${name} return ${clazz}`);
        } else {
            clazz.class.getDeclaredMethods().forEach(function (targetMethod) {
                findClass(name)[targetMethod.getName()].overloads.forEach(overload => {
                    sharpHookCommon(name, targetMethod.getName(), overload, beforeCallback, afterCallback);
                });
            });
        }
        return;
    }
    if (type === HookCategory.SINGLE_FUNCTION) {
        // 获取类路径
        let findClassByString = function(text) {
            return text.substring(0, text.lastIndexOf('.'))
        }
        // 获取函数名称
        let findMethodByString = function(text) {
            return text.substring(text.lastIndexOf('.') + 1)
        }
        // 获取类路径
        const className = findClassByString(name);
        // 获取函数名称
        const methodName = findMethodByString(name);
        
        // 获取 java 类
        clazz = findClass(className);
        if (clazz == null) {
            console.log(`can't find className ${className} return ${clazz}`);
            return;
        }
        
        clazz[methodName].overloads.forEach(overload => {
            sharpHookCommon(className, methodName, overload, beforeCallback, afterCallback);
        });
    }
}

//////////////////////////////////////////////////////////////////////////////
function resolveIntent(intent)
{
    if (intent != null) {
        log("=============    resolveIntent start    =============")
        try
        {
            intent = Java.cast(intent, findClass("android.content.Intent"));
            log(JSON.stringify(intent))

            log("intent.getType() = " + intent.getType());
            log("intent.getAction() = " + intent.getAction());
            log("intent.getPackage() = " + intent.getPackage());
            log("intent.getComponent() =  " + intent.getComponent());
            log("intent.getData() =  " + intent.getData());
            log("intent.getFlags() =  " + intent.getFlags());
            log("intent.getClipData() =  " + intent.getClipData());
            if (intent.getData()) {
                log("intent.getScheme() =  " + intent.getScheme());
            }

            let bundle = intent.getExtras();
            if (bundle != null) {
                bundle.keySet().toArray().forEach(function(key){
                    log("string key:  " + key + "  value:  " + bundle.get(key));
                });
            }
        } catch (e){
            log(e);
        }
        log("=============    resolveIntent  end     =============")
    }
}

function resolveBundle(bundle)
{
    log("=============    resolveBundle start    =============")
    try
    {
        bundle.keySet().toArray().forEach(function(key){
            log("string key:  " + key + "  value:  " + bundle.get(key));
        });
    } catch (e){

    }
    log("=============    resolveBundle  end     =============")
}

function findClassesWithKeyword(filter) {

    Java.perform(function() {
        Java.enumerateLoadedClasses({
            onMatch: function(className, classHandle) {
                // console.log(className)
                if (filter === "" || className.indexOf(filter) !== -1) {
                    console.log("Class Name:", ColorLibrary.coloredText(className, 'red'));
                }
                // 处理每个匹配到的类
            },
            onComplete: function() {
                console.log("Class enumeration completed.");
                // 枚举完成后的逻辑
            }
        });
    });
}

function baseTrace() {
    fastHook(HookCategory.ALL_MEMBERS, "android.app.IActivityManager$Stub$Proxy");
    fastHook(HookCategory.ALL_MEMBERS, "android.app.IActivityTaskManager$Stub$Proxy");
    fastHook(HookCategory.ALL_MEMBERS, "android.app.IActivityClientController$Stub$Proxy");
    fastHook(HookCategory.ALL_MEMBERS, "android.content.pm.IPackageManager$Stub$Proxy");
    fastHook(HookCategory.ALL_MEMBERS, "android.view.IWindowSession$Stub$Proxy");
    fastHook(HookCategory.ALL_MEMBERS, "android.net.IConnectivityManager$Stub$Proxy");
    fastHook(HookCategory.ALL_MEMBERS, "com.android.internal.telephony.ITelephony$Stub$Proxy");
    fastHook(HookCategory.ALL_MEMBERS, "android.accounts.IAccountManager$Stub$Proxy");
    // fastHook(HookCategory.ALL_MEMBERS, "android.content.ContentProvider");
    fastHook(HookCategory.ALL_MEMBERS, "android.app.admin.IDevicePolicyManager$Stub$Proxy");
    fastHook(HookCategory.ALL_MEMBERS, "android.app.INotificationManager$Stub$Proxy");
    fastHook(HookCategory.ALL_MEMBERS, "android.app.job.IJobScheduler$Stub$Proxy");
    fastHook(HookCategory.ALL_MEMBERS, "android.media.IAudioService$Stub$Proxy");
    fastHook(HookCategory.ALL_MEMBERS, "com.android.internal.telephony.ISub$Stub$Proxy");
    fastHook(HookCategory.ALL_MEMBERS, "android.content.ContentProviderProxy");
    fastHook(HookCategory.ALL_MEMBERS, "android.content.ContentProvider$Transport");
    fastHook(HookCategory.ALL_MEMBERS, "com.android.internal.view.IInputMethodManager$Stub$Proxy");
    fastHook(HookCategory.ALL_MEMBERS, "android.view.accessibility.IAccessibilityManager$Stub$Proxy");
    // fastHook(HookCategory.ALL_MEMBERS, "android.content.ContentResolver");
    fastHook(HookCategory.ALL_MEMBERS, "android.os.storage.IStorageManager$Stub$Proxy");
    fastHook(HookCategory.ALL_MEMBERS, "com.android.providers.media.MediaProvider");
    // fastHook(HookCategory.ALL_MEMBERS, "com.google.android.apps.photos.localmedia.ui.LocalPhotosActivity");
    fastHook(HookCategory.ALL_MEMBERS, "android.hardware.display.IDisplayManager$Stub$Proxy");
    // fastHook(HookCategory.ALL_MEMBERS, "android.app.Instrumentation")
    fastHook(HookCategory.ALL_MEMBERS, "com.android.server.content.SyncManager");
    fastHook(HookCategory.ALL_MEMBERS, "android.os.IUserManager$Stub$Proxy");
    fastHook(HookCategory.ALL_MEMBERS, "android.content.IContentService$Stub$Proxy");
    // fastHook(HookCategory.ALL_MEMBERS, "android.app.ActivityThread");
    // fastHook(HookCategory.ALL_MEMBERS, "android.app.Activity");


    // fastHook(HookCategory.ALL_MEMBERS, "android.net.Uri");
    // fastHook(HookCategory.CONSTRUCTOR, ("android.net.Uri");
    // fastHook(HookCategory.ALL_MEMBERS, "java.net.URL");
    // fastHook(HookCategory.CONSTRUCTOR, ("java.net.URL");

    // fastHook(HookCategory.SINGLE_FUNCTION, "android.app.SharedPreferencesImpl.getBoolean");
    // fastHook(HookCategory.SINGLE_FUNCTION, "android.app.SharedPreferencesImpl.getInt");
    // fastHook(HookCategory.SINGLE_FUNCTION, "android.app.SharedPreferencesImpl.getLong");
    // fastHook(HookCategory.SINGLE_FUNCTION, "android.app.SharedPreferencesImpl.getFloat");
    // fastHook(HookCategory.SINGLE_FUNCTION, "android.app.SharedPreferencesImpl.getString");
    // fastHook(HookCategory.SINGLE_FUNCTION, "android.app.SharedPreferencesImpl.getStringSet");
    // fastHook(HookCategory.SINGLE_FUNCTION, "android.app.SharedPreferencesImpl$EditorImpl.putBoolean");
    // fastHook(HookCategory.SINGLE_FUNCTION, "android.app.SharedPreferencesImpl$EditorImpl.putInt");
    // fastHook(HookCategory.SINGLE_FUNCTION, "android.app.SharedPreferencesImpl$EditorImpl.putLong");
    // fastHook(HookCategory.SINGLE_FUNCTION, "android.app.SharedPreferencesImpl$EditorImpl.putFloat");
    // fastHook(HookCategory.SINGLE_FUNCTION, "android.app.SharedPreferencesImpl$EditorImpl.putString");
    // fastHook(HookCategory.SINGLE_FUNCTION, "android.app.SharedPreferencesImpl$EditorImpl.putStringSet");
}

function getCurrentTime() {
    const now = new Date();
    const month = String(now.getMonth() + 1).padStart(2, '0');
    const day = String(now.getDate()).padStart(2, '0');
    const hours = String(now.getHours()).padStart(2, '0');
    const minutes = String(now.getMinutes()).padStart(2, '0');
    const seconds = String(now.getSeconds()).padStart(2, '0');
    const milliseconds = String(now.getMilliseconds()).padStart(3, '0');

    return `${month}-${day} ${hours}:${minutes}:${seconds}.${milliseconds}`;
}

function hookSoAddress(libName, exportName, beforeCallback, afterCallback) {
    let module = null;
    try {
        module = Process.getModuleByName(libName);
    } catch (e) {
        log(e);
        return;
    }

    const targetAddr = module.findExportByName(exportName);
    log(`module.name: ${module.name} module.base: ${module.base} targetAddr: ${targetAddr}`);

    let params = {};
    Interceptor.attach(targetAddr, {
        onEnter: function (args) {
            params = {
                args: args,
                stack: false,
                module: module,
                thisObject: this,
                call: this.shouldContinue
            }


            try {
                if (typeof beforeCallback === 'function') {
                    Java.perform(() => {
                        beforeCallback(params);
                    })
                }
            } catch (e) {
                log(e);
            }

            this.shouldContinue = params.call;
        },
        onLeave: function (retval) {
            try {
                if (typeof afterCallback === 'function') {
                    Java.perform(() => {
                        afterCallback(params);
                    })
                }
            } catch (e) {
                log(e);
            }
        }
    });
}

function catObject(obj, type, callback=null) {
    try {
        if (obj == null) {
            log("Unable cat object null");
            return;
        }

        let clazz;
        if (type == null) {
            clazz = obj.getClass();
        } else {
            clazz = findClass(type).class;
        }


        log(``);
        log(`============ ${clazz.getName()} ============ `);
        clazz.getDeclaredFields().forEach(field => {
            field.setAccessible(true);

            let fieldClass = field.getClass();
            let fieldName = field.getName();
            let fieldObject = field.get(obj);

            let modifiers = field.getModifiers();
            let isFinal = and.java_lang_reflect_Modifier.isFinal(modifiers);
            let isStatic = and.java_lang_reflect_Modifier.isStatic(modifiers);

            // if (isFinal && isStatic) {
            //
            // }
            // else
            {
                if (callback == null) {
                    log(`${fieldName} = ${fieldObject} ${JSON.stringify(fieldObject)}`);
                } else {
                    callback(fieldClass, fieldName, fieldObject);
                }
            }

        });
        log(`============ ${clazz.getName()} ============ `);
        log(``);
    } catch (e) {
        log(e);
    }
}

function enumerateModules(callback) {
    console.log("========== B enumerateModules B ==========")
    Java.perform(() => {
        Process.enumerateModules().forEach(module => {
            let params = {
                name : module.name,
                base : module.base,
                size : module.size,
                path : module.path,
                imports : module.enumerateImports()
            }
            callback(params);
        })
    })
    console.log("========== E enumerateModules E ==========")
}


function VoiceChanger() {
    // fastHook(HookCategory.SINGLE_FUNCTION, "com.tencent.av.VideoController.q5", p =>
    // {
    //     // [*] Backtrace:
    //     // com.tencent.av.ui.bc.d(Native Method)
    //     // com.tencent.av.ui.bc.e(P:4)
    //     // com.tencent.av.ui.effect.toolbar.newversion.VoiceChangeToolbar$a.b(P:15)
    //     // com.tencent.av.ui.effect.adapter.MaterialAdapter.d0(P:3)
    //     // com.tencent.av.ui.effect.adapter.MaterialAdapter.S(P:5)
    //     // com.tencent.av.ui.effect.adapter.MaterialAdapter$b.a(P:8)
    //     // com.tencent.av.ui.QavListItemBase.onClick(P:4)
    //     // android.view.View.performClick(View.java:7455)
    //     // android.view.View.performClickInternal(View.java:7432)
    //     // android.view.View.access$3700(View.java:835)
    //     // android.view.View$PerformClick.run(View.java:28810)
    //     // android.os.Handler.handleCallback(Handler.java:938)
    //     // android.os.Handler.dispatchMessage(Handler.java:99)
    //     // android.os.Looper.loopOnce(Looper.java:201)
    //     // android.os.Looper.loop(Looper.java:288)
    //     // android.app.ActivityThread.main(ActivityThread.java:7870)
    //     // java.lang.reflect.Method.invoke(Native Method)
    //     // com.android.internal.os.RuntimeInit$MethodAndArgsCaller.run(RuntimeInit.java:548)
    //     // com.android.internal.os.ZygoteInit.main(ZygoteInit.java:1003)
    //     p.stack=true
    // });
    // fastHook(HookCategory.CONSTRUCTOR, "com.tencent.avcore.jni.dav.DavEngineJni", p => {
    //     for (let i = 0; i < 4; i++) {
    //         console.log(`arg${i} = ${JSON.stringify(args[i])}`)
    //     }
    // })

    // Java.choose("com.tencent.avcore.jni.dav.DavEngineJni", {
    //     onMatch: function (instance) {
    //         console.log(instance)
    //         catObject(instance)
    //     },
    //     onComplete: function () {
    //
    //     }
    // })

    // let base = Module.findBaseAddress("libqav_rtc_sdk.so");
    // log(`base:${base}`)
    //
    // let addr = base.add(0x407B3C);
    // Interceptor.attach(addr, {
    //     onEnter: function(args) {
    //         console.log(`${addr} onEnter`)
    //         for (let i = 0; i < 3; i++) {
    //             console.log(`${addr} arg${i} = ${args[i]}`)
    //         }
    //
    //         // console.log(Thread.backtrace(this.context, Backtracer.FUZZY)
    //         //     .map(DebugSymbol.fromAddress).join("\n"))
    //     },
    //     onLeave: retval => {
    //         console.log(`${addr} onLeave`);
    //     }
    // });


    // fastHook(HookCategory.ALL_MEMBERS, "com.tencent.avcore.util.AVCoreLog")
    // // fastHook(HookCategory.SINGLE_FUNCTION, "com.tencent.avcore.util.AVCoreLog.printAllUserLog")
    // fastHook(HookCategory.SINGLE_FUNCTION, "com.tencent.av.VideoController.I0", p => {
    //     log(p.thisObject._c.value);
    // })
    //
    // fastHook(HookCategory.SINGLE_FUNCTION, "com.tencent.avcore.jni.dav.DavEngineProxy.setVoiceType", p => {
    //     catObject(p.thisObject, "com.tencent.avcore.jni.dav.DavEngineProxy")
    //     // console.log(`${JSON.stringify(p.thisObject.mJniImpl.value)}`);
    // });


    // fastHook(HookCategory.SINGLE_FUNCTION, "com.tencent.av.core.VcControllerImpl.enableLoopback");
    // fastHook(HookCategory.ALL_MEMBERS, "com.tencent.av.core.VcControllerImpl");

    //
    // fastHook(HookCategory.SINGLE_FUNCTION, "android.view.View.performClick")
    // fastHook(HookCategory.SINGLE_FUNCTION, "com.tencent.av.ui.effect.toolbar.oldversion.VoiceChangeToolbar$a.b")


    // Interceptor.attach(Module.findExportByName("libc.so", "dlopen"), {
    //     onEnter: function(args) {
    //         for (let i = 0; i < 3; i++) {
    //             console.log(`libaudioclient.so read arg${i} = ${args[i]}`)
    //         }
    //         console.log("" + ptr(args[0]).readCString())
    //         // console.log(Thread.backtrace(this.context, Backtracer.FUZZY)
    //         //     .map(DebugSymbol.fromAddress).join("\n"))
    //     },
    //     onLeave: retval => {
    //         console.log("libaudioclient.so read retval：" + retval);
    //     }
    // });

    // fastHook(HookCategory.ALL_MEMBERS, "android.media.internal.exo.audio.DtsUtil")
    // fastHook(HookCategory.ALL_MEMBERS, "android.media.internal.exo.audio.WavUtil")
    // fastHook(HookCategory.ALL_MEMBERS, "com.tencent.mobileqq.qqaudio.audioplayer.AudioPlayerBase")
    // fastHook(HookCategory.ALL_MEMBERS, "com.tencent.mobileqq.utils.AudioUtil")
    // fastHook(HookCategory.ALL_MEMBERS, "com.tencent.mobileqq.utils.QQAudioHelper")
    // fastHook(HookCategory.ALL_MEMBERS, "com.tencent.qqlive.module.videoreport.dtreport.audio.data.AudioDataManager")
    // fastHook(HookCategory.ALL_MEMBERS, "com.tencent.mobileqq.qqaudio.QQAudioUtils")
    // fastHook(HookCategory.ALL_MEMBERS, "com.tencent.qqnt.audio.play.player.AudioPlayer")

    // com.tencent.av.ui.effect.view.QavVoiceChangeMaterialItemView

    // findClassesWithKeyword("Audio")


    // fastHook(HookCategory.ALL_MEMBERS, "android.media.AudioRecord")
    // fastHook(HookCategory.ALL_MEMBERS, "android.media.AudioTrack")
    // Interceptor.attach(Module.findExportByName("libaudioclient.so", "start"), {
    //     onEnter: function(args) {
    //         console.log(Thread.backtrace(this.context, Backtracer.FUZZY)
    //             .map(DebugSymbol.fromAddress).join("\n"))
    //     },
    //     onLeave: retval => {
    //         console.log("libaudioclient.so read retval：" + retval);
    //     }
    // });
    // Interceptor.attach(Module.findExportByName("libaudioclient.so", "read"), {
    //     onEnter: function(args) {
    //         for (let i = 0; i < 3; i++) {
    //             console.log(`libaudioclient.so read arg${i} = ${args[i]}`)
    //         }
    //         console.log(Thread.backtrace(this.context, Backtracer.FUZZY)
    //             .map(DebugSymbol.fromAddress).join("\n"))
    //     },
    //     onLeave: retval => {
    //         console.log("libaudioclient.so read retval：" + retval);
    //     }
    // });

    // let base = Module.findBaseAddress("libGVoice.so");
    // let addr;
    // // addr = base.add(0x119038);
    //
    // addr = Module.findExportByName("libaudioclient.so", "read");
    // Interceptor.attach(addr, {
    //     onEnter: function(args) {
    //         for (let i = 0; i < 3; i++) {
    //             console.log(`libaudioclient.so read arg${i} = ${args[i]}`)
    //         }
    //         console.log(Thread.backtrace(this.context, Backtracer.FUZZY)
    //             .map(DebugSymbol.fromAddress).join("\n"))
    //     },
    //     onLeave: retval => {
    //         console.log("libaudioclient.so read retval：" + retval);
    //     }
    // });
    // Process.enumerateModules().forEach(m => {
    //     console.log(`${m.name} => ${m.path}`)
    // });
}

Java.perform(function () {
    console.log("uid: " + and.android_os_Process.myUid());
    console.log("pid: " + and.android_os_Process.myPid());

    let cx = Java.use("com.google.android.apps.gsa.staticplugins.opa.errorui.ad");
    cx["$init"].implementation = function (bmVar) {
        console.log(`cx.$init is called: bmVar=${bmVar}`);
        getStackTrace();
        this["$init"](bmVar);
    };

    // fastHook(HookCategory.ALL_MEMBERS, "android.app.IActivityManager$Stub$Proxy");
    // fastHook(HookCategory.ALL_MEMBERS, "android.app.IActivityTaskManager$Stub$Proxy");
    // fastHook(HookCategory.SINGLE_FUNCTION, "android.app.Activity.getIntent", p => p.stack=true)

    // fastHook(HookCategory.SINGLE_FUNCTION, "android.app.FragmentTransaction.add");
    // fastHook(HookCategory.SINGLE_FUNCTION, "android.app.FragmentTransaction.commit", p => p.stack=true);
    // fastHook(HookCategory.SINGLE_FUNCTION, "androidx.fragment.app.FragmentTransaction.add");
    // fastHook(HookCategory.SINGLE_FUNCTION, "androidx.fragment.app.FragmentTransaction.commit", p => p.stack=true);
    // fastHook(HookCategory.SINGLE_FUNCTION, "com.google.android.gms.common.ac.c");
    // fastHook(HookCategory.ALL_MEMBERS, "android.a.a.d");
    // fastHook(HookCategory.SINGLE_FUNCTION, "android.app.IActivityManager$Stub$Proxy.finishActivity")
    // fastHook(HookCategory.ALL_MEMBERS, "com.google.android.apps.gsa.staticplugins.opa.OpaActivity")
    // fastHook(HookCategory.ALL_MEMBERS, "android.app.Instrumentation")
    // fastHook(HookCategory.SINGLE_FUNCTION, "com.google.android.apps.gsa.staticplugins.opa.lv.a", p => {
    //     p.stack=true
    //     p.call=false
    // })
    // fastHook(HookCategory.SINGLE_FUNCTION, "android.a.a.d.b")
    return;
    // fastHook(HookCategory.SINGLE_FUNCTION, "android.net.Uri.parse")
    // fastHook(HookCategory.SINGLE_FUNCTION, "com.google.android.apps.gsa.staticplugins.deeplink.activity.DeeplinkActivity.onCreate", p => {
    //     let intent = p.thisObject.getIntent();
    //     // console.log("" + intent);
    //
    //     let uri = intent.getData();
    //     console.log("uri：" + uri);
    //
    //     console.log("getScheme:" + uri.getScheme());
    //     console.log("getHost:" + uri.getHost());
    //     console.log("getPath：" + uri.getPath());
    // });
    // fastHook(HookCategory.SINGLE_FUNCTION, "android.content.ContextWrapper.startActivityForResult");
    // fastHook(HookCategory.SINGLE_FUNCTION, "android.content.pm.IPackageManager$Stub$Proxy.resolveIntent");
    // fastHook(HookCategory.SINGLE_FUNCTION, "android.content.pm.ShortcutManager.setDynamicShortcuts");
    // fastHook(HookCategory.ALL_MEMBERS, "com.google.android.apps.googleassistant.AssistantActivity");

    return;
    console.log(`libunity:${Module.findBaseAddress("libunity.so")}`);
    console.log(`libil2cpp:${Module.findBaseAddress("libil2cpp.so")}`);
    console.log(`libc:${Module.findBaseAddress("libc.so")}`);
    // enumerateModules(m => {
    //     if (m.name.includes("libil2cpp")) {
    //         console.log(`${m.name}`);
    //         console.log(`${m.base}`);
    //         console.log(`${m.size}`);
    //         console.log(`${m.path}`);
    //     }
    //
    //     // m.imports.forEach(item => {
    //     //     if (item.name.includes("libil2cpp"))
    //     //     {
    //     //         console.log(`${item.type}`);
    //     //         console.log(`${item.name}`);
    //     //         console.log(`${item.module}`);
    //     //         console.log(`${item.address}`);
    //     //         // getStackTrace();
    //     //     }
    //     // });
    // })
    reIO();
    // fastHook(HookCategory.SINGLE_FUNCTION, "atvv.i");
    // fastHook(HookCategory.CONSTRUCTOR, "atwn");
    // fastHook(HookCategory.ALL_MEMBERS, "atwl");

    // fastHook(HookCategory.SINGLE_FUNCTION, "kya.a", p => {
    //     console.log("this b:" + p.thisObject.b.value);
    //     console.log("boolean z:" + p.args[0].g());
    //     console.log("lvv e:" + p.args[0].e());
    //
    //     // let e = Java.cast(p.args[0].e(), findClass("lvv"));
    //     // console.log("e():" + e);
    //     // if (e != null) {
    //     //     console.log(`e.f:[${e._f.value}]`);
    //     // }
    //     // p.stack=true;
    // })
    return;
    /**
     * 监控服务调度 android.app.IApplicationThread$Stub$Proxy.scheduleTransaction
     * */

    if (and.android_os_Process.myUid() === 1000) {
        fastHook(HookCategory.SINGLE_FUNCTION, "android.app.IApplicationThread$Stub$Proxy.scheduleTransaction", p => {
            p.stack=true;
        });

        fastHook(HookCategory.SINGLE_FUNCTION, "com.android.server.wm.ActivityTaskSupervisor.startSpecificActivity");

        /**
         * Backtrace:
         *         com.android.server.wm.ActivityTaskSupervisor.scheduleIdleTimeout(Native Method)
         *         com.android.server.wm.ActivityRecord.completeResumeLocked(ActivityRecord.java:5681)
         *         com.android.server.wm.Task.minimalResumeActivityLocked(Task.java:4784)
         *         com.android.server.wm.ActivityTaskSupervisor.realStartActivityLocked(ActivityTaskSupervisor.java:931)
         *         com.android.server.wm.ActivityTaskSupervisor.startSpecificActivity(ActivityTaskSupervisor.java:998)
         *         com.android.server.wm.TaskFragment.resumeTopActivity(TaskFragment.java:1351)
         *         com.android.server.wm.Task.resumeTopActivityInnerLocked(Task.java:5035)
         *         com.android.server.wm.Task.resumeTopActivityUncheckedLocked(Task.java:4970)
         *         com.android.server.wm.RootWindowContainer.resumeFocusedTasksTopActivities(RootWindowContainer.java:2361)
         *         com.android.server.wm.RootWindowContainer.resumeFocusedTasksTopActivities(RootWindowContainer.java:2347)
         *         com.android.server.wm.TaskFragment.completePause(TaskFragment.java:1602)
         *         com.android.server.wm.ActivityRecord.activityPaused(ActivityRecord.java:5714)
         *         com.android.server.wm.ActivityClientController.activityPaused(ActivityClientController.java:175)
         *         android.app.IActivityClientController$Stub.onTransact(IActivityClientController.java:548)
         *         com.android.server.wm.ActivityClientController.onTransact(ActivityClientController.java:121)
         *         android.os.Binder.execTransactInternal(Binder.java:1184)
         *         android.os.Binder.execTransact(Binder.java:1143)
         * */
        fastHook(HookCategory.SINGLE_FUNCTION, "com.android.server.wm.ActivityTaskManagerService.startActivity", p => {
            // p.stack=true;
        });
        return;
    }


});

function shell() {

    fastHook(HookCategory.SINGLE_FUNCTION, "android.app.ActivityThread.handleLaunchActivity")
    fastHook(HookCategory.SINGLE_FUNCTION, "android.app.LoadedApk.makeApplication", p => {
        p.stack=true
    });
    fastHook(HookCategory.SINGLE_FUNCTION, "com.gsnslxs.gdx.bylaasy.MyApplication.attachBaseContext", p => {
        let activityThread = findClass("android.app.ActivityThread");
        let s = activityThread.currentActivityThread();
        let field = activityThread.class.getDeclaredField("mInitialApplication");
        field.setAccessible(true);
        console.log("attachBaseContext app2:" + field.get(s));
        p.stack=true;

        // console.log(p.thisObject.getClassLoader());
        fastHook(HookCategory.SINGLE_FUNCTION, "a.auu.a.c");
        fastHook(HookCategory.SINGLE_FUNCTION, "com.gsnslxs.gdx.bylaasy.multidex.MultiDex.install");
    });
    fastHook(HookCategory.SINGLE_FUNCTION, "android.app.ConfigurationController.handleConfigurationChanged", p => {
        let mActivityThread = p.thisObject.mActivityThread.value;
        let activityThread = findClass("android.app.ActivityThread");
        let s = activityThread.currentActivityThread();
        let field = activityThread.class.getDeclaredField("mInitialApplication");
        field.setAccessible(true);
        console.log("app:" + mActivityThread.getApplication());
        console.log("app2:" + field.get(s));
    });
}
function reIO() {

    // fastHook(HookCategory.ALL_MEMBERS, "com.mihoyoos.sdk.platform.SdkActivity")
    // TracePid pass
    // var ByPassTracerPid = function () {
    //     var fgetsPtr = Module.findExportByName("libc.so", "fgets");
    //     var fgets = new NativeFunction(fgetsPtr, 'pointer', ['pointer', 'int', 'pointer']);
    //     Interceptor.replace(fgetsPtr, new NativeCallback(function (buffer, size, fp) {
    //         var retval = fgets(buffer, size, fp);
    //         var bufstr = Memory.readUtf8String(buffer);
    //         if (bufstr.indexOf("TracerPid:") > -1) {
    //             Memory.writeUtf8String(buffer, "TracerPid:\t0");
    //             console.log("tracerpid replaced: " + Memory.readUtf8String(buffer));
    //             console.log('pthread_create called from:\n'
    //                 + Thread.backtrace(this.context, Backtracer.ACCURATE)
    //                     .map(DebugSymbol.fromAddress)
    //                     .join('\n')
    //                 + '\n');
    //         }
    //         return retval;
    //     }, 'pointer', ['pointer', 'int', 'pointer']));
    // };
    // ByPassTracerPid();

    // function hook_libc_func(exportName) {
    //     var pthread_creat_addr = Module.findExportByName("libc.so", exportName)
    //     Interceptor.attach(pthread_creat_addr,{
    //         onEnter(args){
    //             console.log("call pthread_create...")
    //             let func_addr = args[2]
    //             console.log("The thread function address is " + func_addr)
    //             console.log('pthread_create called from:\n'
    //                 + Thread.backtrace(this.context, Backtracer.ACCURATE)
    //                     .map(DebugSymbol.fromAddress)
    //                     .join('\n')
    //                 + '\n');
    //         }
    //     })
    // }
    // hook_libc_func("pthread_create");

    Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"), {
        onEnter: function (args) {
            const addr = args[0];
            if (addr !== undefined && addr !== null) {

                var path = ptr(addr).readCString();
                console.log("dlopen load " + path);
            }
        }
    });

    // Interceptor.attach(Module.findExportByName(null, "__system_property_get"), {
    //     onEnter: args => {
    //         let name = args[0];
    //
    //         let ignore = [
    //             "vendor.debug.egl.swapinterval",
    //             "cache_key.display_info",
    //             "cache_key.package_info",
    //             "debug.force_rtl",
    //             "cache_key.telephony.get_default_sub_id",
    //             "gsm.operator.alpha",
    //         ]
    //
    //         let result = ignore.find(item => item == name);
    //         if (result != undefined && result != null) {
    //             console.log("__system_property_get:" + ptr(name).readCString());
    //         }
    //     }, onLeave: retval => {
    //
    //     }
    // })
return;
    let path;
    let relink;
    Interceptor.attach(Module.findExportByName(null, "readlink"), {
        onEnter: function (args) {
            path = args[0];
            relink = args[1];
        },
        onLeave: retval => {
            let pathname = ptr(path).readCString();
            let relinkPath = ptr(relink).readCString();
            // relinkPath = relinkPath.replaceAll(
            //     "/storage/emulated/0/Android/data/com.gbox.android/_root/sdcard",
            //     "/storage/emulated/0");
            //
            // relinkPath = relinkPath.replaceAll(
            //     "/data/user/0/com.gbox.android/_root/data/internal_app",
            //     "/data/app");
            //
            // relinkPath = relinkPath.replaceAll(
            //     "/data/user/0/com.gbox.android/_root/data/user/0",
            //     "/data/user/0");
            //
            // relinkPath = relinkPath.replaceAll(
            //     "/data/internal_app",
            //     "/data/app");
            //
            console.log(`relink ${pathname} to ${relinkPath}`);
            ptr(relink).writeUtf8String(relinkPath)
        }
    });
    // Interceptor.attach(Module.findExportByName(null, "open"), {
    //     onEnter: function (args) {
    //         var pathptr = args[0];
    //         if (pathptr !== undefined && pathptr != null) {
    //             let path = ptr(pathptr).readCString();
    //             // console.log("open file:" + path);
    //             let ignore = [
    //                 "/data/user/0/com.gbox.android/_root/data",
    //                 "/storage/emulated/0/Android/data",
    //                 "/data/internal_app",
    //                 "/data/data/com.garena.game.codm",
    //                 "/storage/emulated/0/com.garena.game.codm",
    //                 "/dev/urandom",
    //                 "/apex/",
    //                 "/data/misc",
    //                 "/system",
    //                 "[",
    //                 "/dev",
    //                 "/data/resource-cache",
    //                 "/product",
    //                 "/vendor",
    //                 "/dmabuf:",
    //                 "/memfd",
    //             ];
    //
    //             let find = false;
    //             for (let i = 0; i < ignore.length; i++) {
    //                 if (path.includes(ignore[i])) {
    //                     find = true;
    //                 }
    //             }
    //
    //
    //             if (!find) {
    //                 console.log(" open:" + path);
    //             }
    //
    //             Java.perform(() => {
    //
    //                 // if (path.includes('/maps')) {
    //                 //     log(printSoBacktrace(this.context));
    //                 // }
    //             })
    //             // console.log(' called from:\n' + printSoBacktrace());
    //         }
    //     }
    //     , onLeave: retval => {
    //         // console.log("count:" + count + " open fd:" + retval);
    //     }
    // });
    return;
    Interceptor.attach(Module.findExportByName(null, "openat"), {
        onEnter: function (args) {
            let fd = args[0];
            let path = args[1];
            let flags = args[2];

            if (path != null && path != undefined) {
                console.log("openat path: " + ptr(path).readCString());
            }
        }

    });
    Interceptor.attach(Module.findExportByName(null, "read"), {
        onEnter: function (args) {
            Java.perform(() => {
                let fd = args[0];
                let buf = args[1];
                let bytes = args[2];

                // 读取字符串
                let stringValue = ptr(buf).readCString();
                stringValue = stringValue.replaceAll("/data/user/0/com.gbox.android/_root/data/internal_app", "/data/app")
                stringValue = stringValue.replaceAll("/data/user/0/com.gbox.android/_root/data/user/0", "/data/user/0")
                stringValue = stringValue.replaceAll("/data/media/0/Android/data/com.gbox.android/_root", "")
                ptr(buf).writeUtf8String(stringValue)

                // console.log(`fd(${fd})=${stringValue}`);

                // var regex = /^[\x20-\x7E]+$/;
                // if (regex.test(stringValue)) {
                //     console.log(`fd(${fd})=${stringValue}`);
                //     log(printSoBacktrace(this.context));
                // //     console.log(`read(${bytes})=${hexdump(ptr(buf))}`);
                // }
            })
        }
    });

    Interceptor.attach(Module.findExportByName(null, "kill"), {
        onEnter: function(args) {
            console.log("kill:\n");
            console.log(Thread.backtrace(this.context, Backtracer.FUZZY)
                        .map(DebugSymbol.fromAddress).join("\n"))
        }
    });

    // let libunity_addr = Process.getModuleByName("libunity.so");
    // if (libunity_addr) {
    //
    //     log("libunity_addr: " + libunity_addr.base);
    //     Interceptor.attach(ptr(libunity_addr.base).add(0x6D41F8), {
    //         onEnter: args => {
    //             console.log(hexdump(args[0]));
    //             console.log("libunity_addr enter:" + `${args[0]} ${args[1]} ${args[2]} ${args[3]}`);
    //         },
    //         onLeave: retval => {
    //             console.log("libunity_addr leave:" + retval);
    //             retval.replace(0);
    //         }
    //
    //     });
    //     // Interceptor.replace(ptr(libunity_addr.base).add(0x6D41F8),
    //     //     new NativeCallback((a0, a1, a2, a3, a4, a5, a6, a7) => {
    //     //         console.log("refuse fault.");
    //     //         return 0;
    //     // }, 'int', ['int','int','int','int','int','int','int','int']));
    //
    //     // Interceptor.attach(ptr(libunity_addr.base).add(0x70EB10), {
    //     //     onEnter: args => {
    //     //         var output = "";
    //     //
    //     //         // 遍历通用寄存器x0到x30
    //     //         for (var i = 0; i <= 30; i++) {
    //     //             var regValue = args[i].toString(16).padStart(16, '0'); // 转换为16进制，并补0到16位
    //     //             output += 'x' + i + '   ' + regValue + '  ';
    //     //             if (i % 4 === 3) {
    //     //                 output += '\n'; // 每4个寄存器换行
    //     //             }
    //     //         }
    //     //         console.log(output);
    //     //     }
    //     // });
    // }

    // Interceptor.attach(Module.findExportByName(null, "pthread_setname_np"), {
    //     onEnter: args => {
    //         console.log("pthread_setname_np:" + `${ptr(args[1]).readCString()}`);
    //     },
    //     onLeave: retval => {
    //
    //     }
    // });
}

function Messager() {
    // 有一个界面拉起来后， onStart 声明周期会存储键值对，但是它在调用 onStart 之前被 kill 了

    fastHook(HookCategory.ALL_MEMBERS, "com.facebook.bloks.messenger.activity.MSGBloksActivity");
    fastHook(HookCategory.SINGLE_FUNCTION, "android.app.IActivityClientController$Stub$Proxy.activityDestroyed", p => p.stack=true);
    return;
    /**
     * Backtrace:
     *         X.EAq.<init>(Native Method)
     *         X.DFd.A03(Unknown Source:8)
     *         X.JXJ.ANZ(Unknown Source:767)
     *         X.JXI.ANZ(Unknown Source:14)
     *         X.E1y.ANZ(Unknown Source:34)
     *         X.E1z.ANZ(Unknown Source:22)
     *         X.E20.ANZ(Unknown Source:10765)
     *         X.E1x.ANZ(Unknown Source:15)
     *         X.DJP.A0F(Unknown Source:367)
     *         X.DJP.A0F(Unknown Source:1477)
     *         X.D2j.A00(Unknown Source:142)
     *         X.DDh.A00(Unknown Source:24)
     *         X.DId.A01(Unknown Source:14)
     *         X.DId.A04(Unknown Source:10)
     *         X.DUa.onTouch(Unknown Source:100)
     *         android.view.View.dispatchTouchEvent(View.java:14595)
     *         android.view.ViewGroup.dispatchTransformedTouchEvent(ViewGroup.java:3114)
     *         android.view.ViewGroup.dispatchTouchEvent(ViewGroup.java:2787)
     *         android.view.ViewGroup.dispatchTransformedTouchEvent(ViewGroup.java:3142)
     *         android.view.ViewGroup.dispatchTouchEvent(ViewGroup.java:2801)
     *         android.view.ViewGroup.dispatchTransformedTouchEvent(ViewGroup.java:3120)
     *         android.view.ViewGroup.dispatchTouchEvent(ViewGroup.java:2801)
     *         android.view.ViewGroup.dispatchTransformedTouchEvent(ViewGroup.java:3120)
     *         android.view.ViewGroup.dispatchTouchEvent(ViewGroup.java:2801)
     *         android.view.ViewGroup.dispatchTransformedTouchEvent(ViewGroup.java:3120)
     *         android.view.ViewGroup.dispatchTouchEvent(ViewGroup.java:2801)
     *         android.view.ViewGroup.dispatchTransformedTouchEvent(ViewGroup.java:3120)
     *         android.view.ViewGroup.dispatchTouchEvent(ViewGroup.java:2801)
     *         android.view.ViewGroup.dispatchTransformedTouchEvent(ViewGroup.java:3120)
     *         android.view.ViewGroup.dispatchTouchEvent(ViewGroup.java:2801)
     *         android.view.ViewGroup.dispatchTransformedTouchEvent(ViewGroup.java:3120)
     *         android.view.ViewGroup.dispatchTouchEvent(ViewGroup.java:2801)
     *         android.view.ViewGroup.dispatchTransformedTouchEvent(ViewGroup.java:3120)
     *         android.view.ViewGroup.dispatchTouchEvent(ViewGroup.java:2801)
     *         android.view.ViewGroup.dispatchTransformedTouchEvent(ViewGroup.java:3120)
     *         android.view.ViewGroup.dispatchTouchEvent(ViewGroup.java:2801)
     *         android.view.ViewGroup.dispatchTransformedTouchEvent(ViewGroup.java:3120)
     *         android.view.ViewGroup.dispatchTouchEvent(ViewGroup.java:2801)
     *         android.view.ViewGroup.dispatchTransformedTouchEvent(ViewGroup.java:3120)
     *         android.view.ViewGroup.dispatchTouchEvent(ViewGroup.java:2801)
     *         com.android.internal.policy.DecorView.superDispatchTouchEvent(DecorView.java:498)
     *         com.android.internal.policy.PhoneWindow.superDispatchTouchEvent(PhoneWindow.java:1890)
     *         android.app.Activity.dispatchTouchEvent(Activity.java:4202)
     *         com.facebook.base.activity.FbFragmentActivity.dispatchTouchEvent(:100)
     *         com.android.internal.policy.DecorView.dispatchTouchEvent(DecorView.java:456)
     *         android.view.View.dispatchPointerEvent(View.java:14858)
     *         android.view.ViewRootImpl$ViewPostImeInputStage.processPointerEvent(ViewRootImpl.java:6452)
     *         android.view.ViewRootImpl$ViewPostImeInputStage.onProcess(ViewRootImpl.java:6253)
     *         android.view.ViewRootImpl$InputStage.deliver(ViewRootImpl.java:5731)
     *         android.view.ViewRootImpl$InputStage.onDeliverToNext(ViewRootImpl.java:5788)
     *         android.view.ViewRootImpl$InputStage.forward(ViewRootImpl.java:5754)
     *         android.view.ViewRootImpl$AsyncInputStage.forward(ViewRootImpl.java:5919)
     *         android.view.ViewRootImpl$InputStage.apply(ViewRootImpl.java:5762)
     *         android.view.ViewRootImpl$AsyncInputStage.apply(ViewRootImpl.java:5976)
     *         android.view.ViewRootImpl$InputStage.deliver(ViewRootImpl.java:5735)
     *         android.view.ViewRootImpl$InputStage.onDeliverToNext(ViewRootImpl.java:5788)
     *         android.view.ViewRootImpl$InputStage.forward(ViewRootImpl.java:5754)
     *         android.view.ViewRootImpl$InputStage.apply(ViewRootImpl.java:5762)
     *         android.view.ViewRootImpl$InputStage.deliver(ViewRootImpl.java:5735)
     *         android.view.ViewRootImpl.deliverInputEvent(ViewRootImpl.java:8702)
     *         android.view.ViewRootImpl.doProcessInputEvents(ViewRootImpl.java:8653)
     *         android.view.ViewRootImpl.enqueueInputEvent(ViewRootImpl.java:8622)
     *         android.view.ViewRootImpl$WindowInputEventReceiver.onInputEvent(ViewRootImpl.java:8825)
     *         android.view.InputEventReceiver.dispatchInputEvent(InputEventReceiver.java:259)
     *         android.os.MessageQueue.nativePollOnce(Native Method)
     *         android.os.MessageQueue.next(MessageQueue.java:335)
     *         android.os.Looper.loopOnce(Looper.java:161)
     *         android.os.Looper.loop(Looper.java:288)
     *         android.app.ActivityThread.main(ActivityThread.java:7870)
     *         java.lang.reflect.Method.invoke(Native Method)
     *         com.android.internal.os.RuntimeInit$MethodAndArgsCaller.run(RuntimeInit.java:548)
     *         com.android.internal.os.ZygoteInit.main(ZygoteInit.java:1003)
     * */
    // fastHook(HookCategory.CONSTRUCTOR, "X.EAq", p => p.stack=true);


    /**
     * Backtrace:
     *         X.E0m.<init>(Native Method)
     *         X.E0m.A01(Unknown Source:2)
     *         X.EAq.run(Unknown Source:13)
     *         android.os.Handler.handleCallback(Handler.java:938)
     *         android.os.Handler.dispatchMessage(Handler.java:99)
     *         android.os.Looper.loopOnce(Looper.java:201)
     *         android.os.Looper.loop(Looper.java:288)
     *         android.os.HandlerThread.run(HandlerThread.java:67)
     *         X.18v.run(Unknown Source:0)
     * */
    // fastHook(HookCategory.CONSTRUCTOR, "X.E0m", p => p.stack=true);

    /**
     * Backtrace:
     *         X.JX3.<init>(Native Method)
     *         com.facebook.messaging.caa.plugins.login.implementations.sessioninitialization.MSGBloksCaaHandleLoginResponseImplementation.A01(Unknown Source:541)
     *         X.JXJ.ANZ(Unknown Source:9040)
     *         X.JXI.ANZ(Unknown Source:14)
     *         X.E1y.ANZ(Unknown Source:34)
     *         X.E1z.ANZ(Unknown Source:22)
     *         X.E20.ANZ(Unknown Source:10765)
     *         X.E1x.ANZ(Unknown Source:15)
     *         X.DJP.A0F(Unknown Source:367)
     *         X.D2j.A00(Unknown Source:142)
     *         X.DDh.A00(Unknown Source:24)
     *         X.DId.A06(Unknown Source:40)
     *         X.DXD.C4M(Unknown Source:8)
     *         X.E0m.onSuccess(Unknown Source:3733)
     *         X.1Ap.run(Unknown Source:8)
     *         android.os.Handler.handleCallback(Handler.java:938)
     *         android.os.Handler.dispatchMessage(Handler.java:99)
     *         android.os.Looper.loopOnce(Looper.java:201)
     *         android.os.Looper.loop(Looper.java:288)
     *         android.app.ActivityThread.main(ActivityThread.java:7870)
     *         java.lang.reflect.Method.invoke(Native Method)
     *         com.android.internal.os.RuntimeInit$MethodAndArgsCaller.run(RuntimeInit.java:548)
     *         com.android.internal.os.ZygoteInit.main(ZygoteInit.java:1003)
     * */
    // fastHook(HookCategory.CONSTRUCTOR, "X.JX3", p => p.stack=true);

    /**
     * Backtrace:
     *         X.Gtj.<init>(Native Method)
     *         X.Fky.A00(Unknown Source:104)
     *         com.facebook.messaging.caa.plugins.login.implementations.sessioninitialization.MSGBloksCaaHandleLoginResponseImplementation.A00(Unknown Source:117)
     *         X.JX3.onSuccess(Unknown Source:19)
     *         X.1Ap.run(Unknown Source:8)
     *         android.os.Handler.handleCallback(Handler.java:938)
     *         android.os.Handler.dispatchMessage(Handler.java:99)
     *         android.os.Looper.loopOnce(Looper.java:201)
     *         android.os.Looper.loop(Looper.java:288)
     *         android.app.ActivityThread.main(ActivityThread.java:7870)
     *         java.lang.reflect.Method.invoke(Native Method)
     *         com.android.internal.os.RuntimeInit$MethodAndArgsCaller.run(RuntimeInit.java:548)
     *         com.android.internal.os.ZygoteInit.main(ZygoteInit.java:1003)
     * */
    // fastHook(HookCategory.CONSTRUCTOR, "X.Gtj", p => {
    //     p.stack=true;
    // })

    // fastHook(HookCategory.CONSTRUCTOR, "X.FEq", p => {
    //     p.stack=true;
    // })

    /**
     * [*] 09-27 14:44:38.181 10679 18739 2 int android.app.IActivityTaskManager$Stub$Proxy.startActivity([object Object], com.facebook.orca, null, Intent { cmp=com.facebook.orca/com.facebook.messaging.neue.nux.NeueNuxActivity (has extras) }, null, [object Object], null, -1, 0, null, null) | before called
     * Backtrace:
     *         android.app.IActivityTaskManager$Stub$Proxy.startActivity(Native Method)
     *         android.app.Instrumentation.execStartActivity(Instrumentation.java:1758)
     *         android.app.Activity.startActivityForResult(Activity.java:5410)
     *         android.app.Activity.startActivityForResult(Activity.java:5368)
     *         com.facebook.base.activity.FbFragmentActivity.startActivityForResult(:6)
     *         com.facebook.base.activity.DelegatingFbFragmentFrameworkActivity.A0F(Unknown Source:0)
     *         X.1fk.startActivityForResult(Unknown Source:2)
     *         X.07L.A0W(:2)
     *         X.08M.startActivityForResult(:2)
     *         com.facebook.base.activity.DelegatingFbFragmentFrameworkActivity.startActivityForResult(Unknown Source:2)
     *         android.app.Activity.startActivity(Activity.java:5754)
     *         android.app.Activity.startActivity(Activity.java:5707)
     *         com.facebook.base.activity.DelegatingFbFragmentFrameworkActivity.A0E(Unknown Source:0)
     *         X.1fk.CaH(Unknown Source:2)
     *         X.07L.A0V(:2)
     *         X.08M.CaH(:2)
     *         com.facebook.base.activity.DelegatingFbFragmentFrameworkActivity.startActivity(Unknown Source:2)
     *         X.0Fq.A0A(:35)
     *         X.1fv.By1(Unknown Source:773)
     *         X.1fu.A0E(Unknown Source:48)
     *         com.facebook.base.activity.FbFragmentActivity.onResume(:110)
     *         com.facebook.base.activity.DelegatingFbFragmentFrameworkActivity.A0O(Unknown Source:0)
     *         X.1fk.onResume(Unknown Source:2)
     *         X.07L.A0w(:2)
     *         X.1fm.A0w(Unknown Source:113)
     *         X.08M.onResume(:2)
     *         com.facebook.base.activity.DelegatingFbFragmentFrameworkActivity.onResume(Unknown Source:9)
     *         android.app.Instrumentation.callActivityOnResume(Instrumentation.java:1488)
     *         android.app.Activity.performResume(Activity.java:8197)
     *         android.app.ActivityThread.performResumeActivity(ActivityThread.java:4814)
     *         android.app.ActivityThread.handleResumeActivity(ActivityThread.java:4857)
     *         android.app.servertransaction.ResumeActivityItem.execute(ResumeActivityItem.java:54)
     *         android.app.servertransaction.ActivityTransactionItem.execute(ActivityTransactionItem.java:45)
     *         android.app.servertransaction.TransactionExecutor.executeLifecycleState(TransactionExecutor.java:176)
     *         android.app.servertransaction.TransactionExecutor.execute(TransactionExecutor.java:97)
     *         android.app.ActivityThread$H.handleMessage(ActivityThread.java:2253)
     *         android.os.Handler.dispatchMessage(Handler.java:106)
     *         android.os.Looper.loopOnce(Looper.java:201)
     *         android.os.Looper.loop(Looper.java:288)
     *         android.app.ActivityThread.main(ActivityThread.java:7870)
     *         java.lang.reflect.Method.invoke(Native Method)
     *         com.android.internal.os.RuntimeInit$MethodAndArgsCaller.run(RuntimeInit.java:548)
     *         com.android.internal.os.ZygoteInit.main(ZygoteInit.java:1003)
     * */
    // com.android.server.am.ActivityManagerService.startActivity
    // com.android.server.wm.ActivityTaskManagerService.startActivityAsUser
    // android.app.IActivityTaskManager$Stub$Proxy.startActivity
    fastHook(HookCategory.SINGLE_FUNCTION, "android.app.IActivityTaskManager$Stub$Proxy.startActivity", p => {
        p.stack=true;
    });
    fastHook(HookCategory.SINGLE_FUNCTION, "android.app.IActivityManager$Stub$Proxy.startActivity", p => {
        p.stack=true;
    });


    fastHook(HookCategory.ALL_MEMBERS, "android.app.Instrumentation")

    /**
     * Backtrace:
     *         android.app.Instrumentation.execStartActivity(Native Method)
     *         android.app.Activity.startActivityForResult(Activity.java:5410)
     *         android.app.Activity.startActivityForResult(Activity.java:5368)
     *         com.facebook.base.activity.FbFragmentActivity.startActivityForResult(:6)
     *         com.facebook.base.activity.DelegatingFbFragmentFrameworkActivity.A0F(Unknown Source:0)
     *         X.1fk.startActivityForResult(Unknown Source:2)
     *         X.07L.A0W(:2)
     *         X.08M.startActivityForResult(:2)
     *         com.facebook.base.activity.DelegatingFbFragmentFrameworkActivity.startActivityForResult(Unknown Source:2)
     *         android.app.Activity.startActivity(Activity.java:5754)
     *         android.app.Activity.startActivity(Activity.java:5707)
     *         com.facebook.base.activity.DelegatingFbFragmentFrameworkActivity.A0E(Unknown Source:0)
     *         X.1fk.CaH(Unknown Source:2)
     *         X.07L.A0V(:2)
     *         X.08M.CaH(:2)
     *         com.facebook.base.activity.DelegatingFbFragmentFrameworkActivity.startActivity(Unknown Source:2)
     *         X.0Fq.A0A(:35)
     *         X.1fv.By1(Unknown Source:773)
     *         X.1fu.A0E(Unknown Source:48)
     *         com.facebook.base.activity.FbFragmentActivity.onResume(:110)
     *       * com.facebook.base.activity.DelegatingFbFragmentFrameworkActivity.A0O(Unknown Source:0)
     *         X.1fk.onResume(Unknown Source:2)
     *         X.07L.A0w(:2)
     *         X.1fm.A0w(Unknown Source:113)
     *         X.08M.onResume(:2)
     *         com.facebook.base.activity.DelegatingFbFragmentFrameworkActivity.onResume(Unknown Source:9)
     *         android.app.Instrumentation.callActivityOnResume(Instrumentation.java:1488)
     *         android.app.Instrumentation.callActivityOnResume(Native Method)
     *         android.app.Activity.performResume(Activity.java:8197)
     *         android.app.ActivityThread.performResumeActivity(ActivityThread.java:4814)
     *         android.app.ActivityThread.handleResumeActivity(ActivityThread.java:4857)
     *         android.app.servertransaction.ResumeActivityItem.execute(ResumeActivityItem.java:54)
     *         android.app.servertransaction.ActivityTransactionItem.execute(ActivityTransactionItem.java:45)
     *         android.app.servertransaction.TransactionExecutor.executeLifecycleState(TransactionExecutor.java:176)
     *         android.app.servertransaction.TransactionExecutor.execute(TransactionExecutor.java:97)
     *         android.app.ActivityThread$H.handleMessage(ActivityThread.java:2253)
     *         android.os.Handler.dispatchMessage(Handler.java:106)
     *         android.os.Looper.loopOnce(Looper.java:201)
     *         android.os.Looper.loop(Looper.java:288)
     *         android.app.ActivityThread.main(ActivityThread.java:7870)
     *         java.lang.reflect.Method.invoke(Native Method)
     *         com.android.internal.os.RuntimeInit$MethodAndArgsCaller.run(RuntimeInit.java:548)
     *         com.android.internal.os.ZygoteInit.main(ZygoteInit.java:1003)
     * */
        // fastHook(HookCategory.SINGLE_FUNCTION, "android.app.Instrumentation.execStartActivity", p => p.stack=true)

    let first = 0;
    fastHook(HookCategory.SINGLE_FUNCTION, "com.facebook.common.zapp_component_factory.m4a.M4aAppComponentFactory.instantiateActivity", p => {
        let intent = p.args[2];
        let component = intent.getComponent();

        console.log("component:" + component);
        if (component.getClassName().indexOf("MSGBloksActivity")) {
            if (first == 0) {
                first = 1;
                component.mClass.value = "com.facebook.messenger.neue.MainActivity";
                intent.setComponent(component);
                p.args[2] = intent;
                console.log(intent);
            }
        }
        // "com.facebook.bloks.messenger.activity.MSGBloksActivity"
        // "com.facebook.messenger.neue.MainActivity"
        p.stack=true;
    });
    /**
     * Backtrace:
     *         com.facebook.messaging.neue.nux.NeueNuxActivity.<init>(Native Method)
     *         java.lang.Class.newInstance(Native Method)
     *         android.app.AppComponentFactory.instantiateActivity(AppComponentFactory.java:95)
     *         com.facebook.common.zapp_component_factory.m4a.M4aAppComponentFactory.instantiateActivity(:310)
     *         android.app.Instrumentation.newActivity(Instrumentation.java:1285)
     *         android.app.ActivityThread.performLaunchActivity(ActivityThread.java:3600)
     *         android.app.ActivityThread.handleLaunchActivity(ActivityThread.java:3864)
     *         android.app.servertransaction.LaunchActivityItem.execute(LaunchActivityItem.java:103)
     *         android.app.servertransaction.TransactionExecutor.executeCallbacks(TransactionExecutor.java:135)
     *         android.app.servertransaction.TransactionExecutor.execute(TransactionExecutor.java:95)
     *         android.app.ActivityThread$H.handleMessage(ActivityThread.java:2253)
     *         android.os.Handler.dispatchMessage(Handler.java:106)
     *         android.os.Looper.loopOnce(Looper.java:201)
     *         android.os.Looper.loop(Looper.java:288)
     *         android.app.ActivityThread.main(ActivityThread.java:7870)
     *         java.lang.reflect.Method.invoke(Native Method)
     *         com.android.internal.os.RuntimeInit$MethodAndArgsCaller.run(RuntimeInit.java:548)
     *         com.android.internal.os.ZygoteInit.main(ZygoteInit.java:1003)
     * */
    fastHook(HookCategory.CONSTRUCTOR, "com.facebook.messaging.neue.nux.NeueNuxActivity", p => {
        p.stack=true;
    });


    /**
     * Backtrace:
     *         com.facebook.messaging.neue.nux.NeueNuxActivity.onStart(Native Method)
     *         android.app.Instrumentation.callActivityOnStart(Instrumentation.java:1467)
     *         android.app.Instrumentation.callActivityOnStart(Native Method)
     *         android.app.Activity.performStart(Activity.java:8082)
     *         android.app.ActivityThread.handleStartActivity(ActivityThread.java:3732)
     *         android.app.servertransaction.TransactionExecutor.performLifecycleSequence(TransactionExecutor.java:221)
     *         android.app.servertransaction.TransactionExecutor.cycleToPath(TransactionExecutor.java:201)
     *         android.app.servertransaction.TransactionExecutor.executeLifecycleState(TransactionExecutor.java:173)
     *         android.app.servertransaction.TransactionExecutor.execute(TransactionExecutor.java:97)
     *         android.app.ActivityThread$H.handleMessage(ActivityThread.java:2253)
     *         android.os.Handler.dispatchMessage(Handler.java:106)
     *         android.os.Looper.loopOnce(Looper.java:201)
     *         android.os.Looper.loop(Looper.java:288)
     *         android.app.ActivityThread.main(ActivityThread.java:7870)
     *         java.lang.reflect.Method.invoke(Native Method)
     *         com.android.internal.os.RuntimeInit$MethodAndArgsCaller.run(RuntimeInit.java:548)
     *         com.android.internal.os.ZygoteInit.main(ZygoteInit.java:1003)
     * */
    fastHook(HookCategory.SINGLE_FUNCTION, "com.facebook.messaging.neue.nux.NeueNuxActivity.onStart", p => {
        p.stack=true;
    });

    /**
     * Backtrace:
     *         com.facebook.base.fragment.AbstractNavigableFragment.<init>(Native Method)
     *         com.facebook.messaging.neue.nux.NuxFragment.<init>(Unknown Source:0)
     *         com.facebook.messaging.neue.nux.messenger.NeueNuxCaaLoginSaveCredentialsFragment.<init>(Unknown Source:0)
     *         java.lang.reflect.Constructor.newInstance0(Native Method)
     *         java.lang.reflect.Constructor.newInstance(Constructor.java:343)
     *         androidx.fragment.app.Fragment.instantiate(:268435475)
     *         X.Edv.A02(Unknown Source:109)
     *         X.Edv.A1V(Unknown Source:16)
     *         com.facebook.messaging.neue.nux.NeueNuxActivity.onStart(Unknown Source:56)
     *         android.app.Instrumentation.callActivityOnStart(Instrumentation.java:1467)
     *         android.app.Activity.performStart(Activity.java:8082)
     *         android.app.ActivityThread.handleStartActivity(ActivityThread.java:3732)
     *         android.app.servertransaction.TransactionExecutor.performLifecycleSequence(TransactionExecutor.java:221)
     *         android.app.servertransaction.TransactionExecutor.cycleToPath(TransactionExecutor.java:201)
     *         android.app.servertransaction.TransactionExecutor.executeLifecycleState(TransactionExecutor.java:173)
     *         android.app.servertransaction.TransactionExecutor.execute(TransactionExecutor.java:97)
     *         android.app.ActivityThread$H.handleMessage(ActivityThread.java:2253)
     *         android.os.Handler.dispatchMessage(Handler.java:106)
     *         android.os.Looper.loopOnce(Looper.java:201)
     *         android.os.Looper.loop(Looper.java:288)
     *         android.app.ActivityThread.main(ActivityThread.java:7870)
     *         java.lang.reflect.Method.invoke(Native Method)
     *         com.android.internal.os.RuntimeInit$MethodAndArgsCaller.run(RuntimeInit.java:548)
     *         com.android.internal.os.ZygoteInit.main(ZygoteInit.java:1003)
     * */
    // fastHook(HookCategory.CONSTRUCTOR, "com.facebook.base.fragment.AbstractNavigableFragment", p => {
    //     p.stack=true;
    // });
    // fastHook(HookCategory.SINGLE_FUNCTION, "com.facebook.base.fragment.AbstractNavigableFragment.A1V", p => {
    //     p.stack=true;
    // });



    /**
     * Backtrace:
     *         com.facebook.messaging.neue.nux.messenger.NeueNuxContactImportFragment.<init>(Native Method)
     *         java.lang.reflect.Constructor.newInstance0(Native Method)
     *         java.lang.reflect.Constructor.newInstance(Constructor.java:343)
     *         androidx.fragment.app.Fragment.instantiate(:268435475)
     *         X.Edv.A02(Unknown Source:109)
     *         X.GJl.BiR(Unknown Source:2)
     *         com.facebook.base.fragment.AbstractNavigableFragment.A01(Unknown Source:87)
     *         com.facebook.base.fragment.AbstractNavigableFragment.A1W(Unknown Source:6)
     *         com.facebook.messaging.neue.nux.NuxFragment.A1b(Unknown Source:59)
     *         com.facebook.messaging.neue.nux.NuxFragment.A1c(Unknown Source:1)
     *         com.facebook.messaging.neue.nux.messenger.NeueNuxCaaLoginSaveCredentialsFragment.A1V(Unknown Source:1)
     *         com.facebook.base.fragment.AbstractNavigableFragment.onResume(Unknown Source:24)
     *         androidx.fragment.app.Fragment.performResume(:17)
     *         X.1jA.performResume(Unknown Source:3)
     *         X.0A0.A07(:77)
     *         X.07y.A0B(:30)
     *         X.07w.A08(:25)
     *         X.07w.A0E(:33)
     *         X.07w.A0h(:11)
     *         androidx.fragment.app.Fragment.performResume(:42)
     *         X.1jA.performResume(Unknown Source:3)
     *         X.0A0.A07(:77)
     *         X.07y.A0B(:30)
     *         X.07w.A08(:25)
     *         X.07w.A0E(:33)
     *         X.07w.A0h(:11)
     *         androidx.fragment.app.FragmentActivity.A10(:13)
     *         com.facebook.base.activity.FbFragmentActivity.A10(:4)
     *         androidx.fragment.app.FragmentActivity.onPostResume(:3)
     *         com.facebook.base.activity.FbFragmentActivity.onPostResume(:0)
     *         android.app.Activity.performResume(Activity.java:8222)
     *         android.app.ActivityThread.performResumeActivity(ActivityThread.java:4814)
     *         android.app.ActivityThread.handleResumeActivity(ActivityThread.java:4857)
     *         android.app.servertransaction.ResumeActivityItem.execute(ResumeActivityItem.java:54)
     *         android.app.servertransaction.ActivityTransactionItem.execute(ActivityTransactionItem.java:45)
     *         android.app.servertransaction.TransactionExecutor.executeLifecycleState(TransactionExecutor.java:176)
     *         android.app.servertransaction.TransactionExecutor.execute(TransactionExecutor.java:97)
     *         android.app.ActivityThread$H.handleMessage(ActivityThread.java:2253)
     *         android.os.Handler.dispatchMessage(Handler.java:106)
     *         android.os.Looper.loopOnce(Looper.java:201)
     *         android.os.Looper.loop(Looper.java:288)
     *         android.app.ActivityThread.main(ActivityThread.java:7870)
     *         java.lang.reflect.Method.invoke(Native Method)
     *         com.android.internal.os.RuntimeInit$MethodAndArgsCaller.run(RuntimeInit.java:548)
     *         com.android.internal.os.ZygoteInit.main(ZygoteInit.java:1003)
     * */
    // fastHook(HookCategory.CONSTRUCTOR, "com.facebook.messaging.neue.nux.messenger.NeueNuxContactImportFragment", p => {
    //     p.stack=true;
    // });



    /**
     * Backtrace:
     *         com.facebook.messaging.neue.nux.messenger.NeueNuxContactImportFragment.onCreateView(Native Method)
     *         androidx.fragment.app.Fragment.performCreateView(:19)
     *         X.1jA.performCreateView(Unknown Source:3)
     *         X.0A0.A07(:297)
     *         X.07w.A0H(:252)
     *         X.07w.A0G(:80)
     *         X.07w.A1I(:62)
     *         X.07w.A0E(:62)
     *         X.07w.A0h(:11)
     *         androidx.fragment.app.Fragment.performResume(:42)
     *         X.1jA.performResume(Unknown Source:3)
     *         X.0A0.A07(:77)
     *         X.07y.A0B(:30)
     *         X.07w.A08(:25)
     *         X.07w.A0E(:33)
     *         X.07w.A0h(:11)
     *         androidx.fragment.app.FragmentActivity.A10(:13)
     *         com.facebook.base.activity.FbFragmentActivity.A10(:4)
     *         androidx.fragment.app.FragmentActivity.onPostResume(:3)
     *         com.facebook.base.activity.FbFragmentActivity.onPostResume(:0)
     *         android.app.Activity.performResume(Activity.java:8222)
     *         android.app.ActivityThread.performResumeActivity(ActivityThread.java:4814)
     *         android.app.ActivityThread.handleResumeActivity(ActivityThread.java:4857)
     *         android.app.servertransaction.ResumeActivityItem.execute(ResumeActivityItem.java:54)
     *         android.app.servertransaction.ActivityTransactionItem.execute(ActivityTransactionItem.java:45)
     *         android.app.servertransaction.TransactionExecutor.executeLifecycleState(TransactionExecutor.java:176)
     *         android.app.servertransaction.TransactionExecutor.execute(TransactionExecutor.java:97)
     *         android.app.ActivityThread$H.handleMessage(ActivityThread.java:2253)
     *         android.os.Handler.dispatchMessage(Handler.java:106)
     *         android.os.Looper.loopOnce(Looper.java:201)
     *         android.os.Looper.loop(Looper.java:288)
     *         android.app.ActivityThread.main(ActivityThread.java:7870)
     *         java.lang.reflect.Method.invoke(Native Method)
     *         com.android.internal.os.RuntimeInit$MethodAndArgsCaller.run(RuntimeInit.java:548)
     *         com.android.internal.os.ZygoteInit.main(ZygoteInit.java:1003)
     * */
    // fastHook(HookCategory.SINGLE_FUNCTION, "com.facebook.messaging.neue.nux.messenger.NeueNuxContactImportFragment.onCreateView", p => {
    //     p.stack=true;
    // });



    /**
     * [*] 09-26 20:10:04.650 10679 22700 2 void X.14m.A02([object Object], [object Object], true) | before called
     * [*] /config/neue/nux_ver_completed=10
     * [*] /config/neue/should_show_end_of_nux_survey=true
     * [*] /config/neue/nux_completed_timestamp=1695730204650
     * Backtrace:
     *         X.14m.A02(Native Method)
     *         X.1ov.A01(Unknown Source:122)
     *         X.1ov.commitImmediately(Unknown Source:1)
     *         X.GJn.BiR(Unknown Source:165)
     *         X.Edv.A02(Unknown Source:307)
     *         X.GJl.BiR(Unknown Source:2)
     *         com.facebook.base.fragment.AbstractNavigableFragment.A01(Unknown Source:87)
     *         com.facebook.base.fragment.AbstractNavigableFragment.A1W(Unknown Source:6)
     *         com.facebook.messaging.neue.nux.NuxFragment.A1b(Unknown Source:59)
     *         com.facebook.messaging.neue.nux.NuxFragment.A1c(Unknown Source:1)
     *         com.facebook.messaging.neue.nux.messenger.NeueNuxContactImportFragment.A03(Unknown Source:150)
     *         X.G72.onClick(Unknown Source:1153)
     *         X.EQd.handleMessage(Unknown Source:34)
     *         android.os.Handler.dispatchMessage(Handler.java:106)
     *         android.os.Looper.loopOnce(Looper.java:201)
     *         android.os.Looper.loop(Looper.java:288)
     *         android.app.ActivityThread.main(ActivityThread.java:7870)
     *         java.lang.reflect.Method.invoke(Native Method)
     *         com.android.internal.os.RuntimeInit$MethodAndArgsCaller.run(RuntimeInit.java:548)
     *         com.android.internal.os.ZygoteInit.main(ZygoteInit.java:1003)
     * */
    // fastHook(HookCategory.SINGLE_FUNCTION, "X.4bG.run", p => {
    //     let A00 = p.thisObject.A00.value;
    //     let map = Java.cast(A00.A02.value, findClass("java.util.HashMap"));
    //     let entrySet = map.entrySet();
    //     let iterator = entrySet.iterator();
    //     while (iterator.hasNext()) {
    //         let next = iterator.next();
    //         log(next)
    //     }
    //     p.stack=true;
    // });
    // fastHook(HookCategory.SINGLE_FUNCTION, "X.14m.A02", p => {
    //     let map = Java.cast(p.args[1], findClass("java.util.HashMap"));
    //     let entrySet = map.entrySet();
    //     let iterator = entrySet.iterator();
    //     while (iterator.hasNext()) {
    //         let next = iterator.next();
    //         log(next)
    //     }
    //     p.stack=true
    // });



    /**
     * [Pixel 4 XL::Messenger ]-> [*] 09-26 19:54:43.368 10679 21498 334 void X.14n.Cis([object Object], [object Object], false) | before called
     * [*] /settings/sms_integration/defaultapp/sms_device_status_reported=true
     * [*] /contacts_upload/continuous_import_upsell_decline_ms/__prefs_data_migrated__=true
     * [*] /contacts_upload/continuous_import_upsell_decline_count/__prefs_data_migrated__=true
     * [*] /contacts_upload/continuous_import_upsell_decline_count=1
     * [*] /contacts_upload/continuous_import_upsell_decline_ms=1695729283362
     * [*] /config/neue/nux_ver_completed=10
     * [*] /config/neue/should_show_end_of_nux_survey=true
     * [*] /config/neue/nux_completed_timestamp=1695729283367
     * Backtrace:
     *         X.14n.Cis(Native Method)
     *         X.4bG.run(Unknown Source:70)
     *         java.util.concurrent.Executors$RunnableAdapter.call(Executors.java:463)
     *         java.util.concurrent.FutureTask.run(FutureTask.java:264)
     *         X.19x.run(Unknown Source:47)
     *         java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1137)
     *         java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:637)
     *         X.1A0.run(Unknown Source:3)
     *         X.1A1.run(Unknown Source:14)
     *         java.lang.Thread.run(Thread.java:1012)
     * */
    // fastHook(HookCategory.SINGLE_FUNCTION, "X.14n.Cis", p => {
    //     p.stack=true;
    //     let map = Java.cast(p.args[1], findClass("java.util.HashMap"));
    //     let entrySet = map.entrySet();
    //     let iterator = entrySet.iterator();
    //     while (iterator.hasNext()) {
    //         let next = iterator.next();
    //         log(next)
    //     }
    // });



    /**
     * [*] 09-26 19:49:27.298 10679 11319 242 void android.content.ContentValues.put(key, /config/neue/nux_ver_completed) | before called
     * Backtrace:
     *         android.content.ContentValues.put(Native Method)
     *         X.14n.Cis(Unknown Source:436)
     *         X.4bG.run(Unknown Source:70)
     *         java.util.concurrent.Executors$RunnableAdapter.call(Executors.java:463)
     *         java.util.concurrent.FutureTask.run(FutureTask.java:264)
     *         X.19x.run(Unknown Source:47)
     *         java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1137)
     *         java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:637)
     *         X.1A0.run(Unknown Source:3)
     *         X.1A1.run(Unknown Source:14)
     *         java.lang.Thread.run(Thread.java:1012)
     * */
    // fastHook(HookCategory.SINGLE_FUNCTION, "android.content.ContentValues.put", p => {
    //     if (p.args[0] == "key" && p.args[1] == "/config/neue/nux_ver_completed") {
    //         p.stack = true;
    //     }
    // });
}
// Message登录协议
/**
 * X.FET
 * [*]
 * [*] ============ com.google.android.gms.auth.api.credentials.Credential ============
 * [*] A00 = https://scontent.xx.fbcdn.net/v/t39.30808-1/350535535_1272526747035769_5930723042686398757_n.jpg?_nc_cat=108&ccb=1-7&_nc_sid=fe8171&_nc_ohc=DqqwaHZDpzwAX-hfcOM&_nc_ad=z-m&_nc_cid=0&_nc_ht=scontent.xx&oh=00_AfC0JQV9HtZOQ5V4zRnEaB2mppfDjhta7Fi-6bWWhTKanw&oe=651276A4
 * [*] A01 = fzhangxiaoyu@gmail.com
 * [*] A02 = Zxy Fish
 * [*] A03 = ainixy1314
 * [*] A04 = null
 * [*] A05 = null
 * [*] A06 = null
 * [*] A07 = []
 * [*] ============ com.google.android.gms.auth.api.credentials.Credential ============
 * [*]
* */