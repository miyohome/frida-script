# frida-script
A frida script to quickly hook android apps

# How do I use the scripting feature
## 1. hook class construction

    Java.perform(function () {
        console.log("uid: " + and.android_os_Process.myUid());
        console.log("pid: " + and.android_os_Process.myPid());


        // do something
        hookConstruction("android.view.View");
    })

## 2. hook class method

    Java.perform(function () {
        console.log("uid: " + and.android_os_Process.myUid());
        console.log("pid: " + and.android_os_Process.myPid());


        // do something
        hookMethod("android.view.View.performClick");
    })

## 3. hook class all methods

    Java.perform(function () {
        console.log("uid: " + and.android_os_Process.myUid());
        console.log("pid: " + and.android_os_Process.myPid());


        // do something
        hookClass("android.view.View");
    })

# How do we use the callback function
## 1. Print java function call tracebacks

    // java
    package com.android.test;
    Class Math {
        private static int add(int a1, int a2) {
            return a1 + a2;
        }
    }

    // frida script
    Java.perform(function () {
        console.log("uid: " + and.android_os_Process.myUid());
        console.log("pid: " + and.android_os_Process.myPid());


        // do something
        hookMethod("com.android.test.Math.add", params => {
            params.stack=true; // 此命令生效打印堆栈
        });
    })

## 2. Get and modify the java function parameters

    // java
    package com.android.test;
    Class Math {
        private static int add(int a1, int a2) {
            return a1 + a2;
        }
    }

    // frida script
    Java.perform(function () {
        console.log("uid: " + and.android_os_Process.myUid());
        console.log("pid: " + and.android_os_Process.myPid());


        // do something
        hookMethod("com.android.test.Math.add", params => {
            // 以下两行打印参数一 和 参数二
            console.log("params[0]: " + params.args[0]);
            console.log("params[1]: " + params.args[1]);
            
            // 修改参数一为 100
            params[0] = 100;
            // 修改参数二为 200
            params[1] = 200;
        });
    })

## 3. Get and modify the java function return value

    // java
    package com.android.test;
    Class Math {
        private static int add(int a1, int a2) {
            return a1 + a2;
        }
    }

    // frida script
    Java.perform(function () {
        console.log("uid: " + and.android_os_Process.myUid());
        console.log("pid: " + and.android_os_Process.myPid());


        // do something
        hookMethod("com.android.test.Math.add", null, params => {
            console.log("old retval: " + params.retval);  // 打印旧返回值
            params.retval=100; // 此命令修改返回值为 100
            console.log("new retval: " + params.retval);  // 打印新返回值
        });
    })

## 4. Force cancellation of program call

    // java
    package com.android.test;
    Class Math {
        private static int add(int a1, int a2) {
            return a1 + a2;
        }
    }

    // frida script
    Java.perform(function () {
        console.log("uid: " + and.android_os_Process.myUid());
        console.log("pid: " + and.android_os_Process.myPid());


        // do something
        hookMethod("com.android.test.Math.add", params => {
            params.call=false; // 此命令生效取消调用函数
        });
    })
