if (Java.available) {
    Java.performNow(function () {
        MessageDigest();
    });
}


function MessageDigest() {
    let ByteString = Java.use("com.android.okhttp.okio.ByteString");
    function toBase64(tag, data) {
        console.log(tag + " Base64: ", ByteString.of(data).base64());
    }
    function toHex(tag, data) {
        console.log(tag + " Hex: ", ByteString.of(data).hex());
    }
    function toUtf8(tag, data) {
        console.log(tag + " Utf8: ", ByteString.of(data).utf8());
    }
    function toUtf82(tag, data,offset,len) {
        console.log(tag + " Utf8: ", ByteString.of(data,offset,len).utf8());
    }


    let MessageDigest = Java.use("java.security.MessageDigest");
    // 信息摘要自吐
    MessageDigest["update"].overload('byte').implementation = function (input) {
        console.log(`Algorithm： ${this.getAlgorithm()} MessageDigest.update('byte') is called!`)
        return this["update"](input);
    }
    MessageDigest["update"].overload('[B').implementation = function (input) {
        console.log(`Algorithm： ${this.getAlgorithm()} MessageDigest.update('byte[]') is called!`)
        return this["update"](input);
    }
    MessageDigest["update"].overload('[B','int','int').implementation = function (input,offset,len) {
        console.log(`Algorithm： ${this.getAlgorithm()} MessageDigest.update('[B','int','int') is called!`)
        return this["update"](input,offset,len);
    }
    MessageDigest["update"].overload('java.nio.ByteBuffer').implementation = function (byteBuffer) {
        console.log(`Algorithm： ${this.getAlgorithm()} MessageDigest.update('java.nio.ByteBuffer') is called!`)
        return this["update"](byteBuffer);
    }
    MessageDigest["digest"].overload('[B').implementation = function (input) {
        let algorithm = this.getAlgorithm();
        console.log(`Algorithm： ${algorithm} MessageDigest.digest('byte[]') before!`);
        toUtf8(algorithm + " input: ", input)
        let result = this["digest"](input);
        toHex(algorithm + " output: ", result)
        console.log(`Algorithm： ${algorithm} MessageDigest.digest('byte[]') after!`);
        return result;
    }
    MessageDigest["digest"].overload('[B','int','int').implementation = function (input,offset,len) {
        let algorithm = this.getAlgorithm();
        console.log(`Algorithm： ${algorithm} MessageDigest.digest('[B','int','int') before!`)
        toUtf82(algorithm + " input: ", input,offset,len);
        let result = this["digest"](input,offset,len);
        toHex(algorithm + " output: ", input);
        console.log(`Algorithm： ${algorithm} MessageDigest.digest('[B','int','int') after!`)
        return result;
    }

    let JUB_Encoder = Java.use("java.util.Base64$Encoder");
    JUB_Encoder["encodeToString"].overload('[B').implementation = function (src) {
        console.log(`java.util.Base64$Encoder.encodeToString('[B') before!`)
        toUtf8("Encoder", src);
        let result = this["encodeToString"](src);
        console.log(result)
        console.log(`java.util.Base64$Encoder.encodeToString('[B') after!`)
        return result;
    }

    let AUB_Base64 = Java.use("android.util.Base64");
    AUB_Base64["encodeToString"].overload('[B','int').implementation = function (input,flags) {
        console.log(`android.util.Base64.encodeToString('[B') before!`)
        toUtf8("Encoder", input);
        let result = this["encodeToString"](input, flags);
        console.log(result)
        console.log(`android.util.Base64.encodeToString('[B') after!`)
        return result;
    }
}
