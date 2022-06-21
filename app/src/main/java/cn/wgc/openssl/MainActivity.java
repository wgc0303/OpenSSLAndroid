package cn.wgc.openssl;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.widget.TextView;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import cn.wgc.openssl.gmhelper.BCECUtil;
import cn.wgc.openssl.gmhelper.SM2Util;
import cn.wgc.openssl.gmhelper.SM3Util;
import cn.wgc.openssl.gmhelper.SM4Util;

public class MainActivity extends AppCompatActivity {

  static {
    System.loadLibrary("crypto_lib");
  }

  //sm2 公钥x hex串
  private final String xHex = "86AE5F84C28C2F23767FEF3D06C000D3A78F456619D6DAB82231CDD9733894AE";
  //sm2 公钥y hex串
  private final String yHex = "93D4AB932C160539E089218797F9C76249818800665EEA2093AD34967CF8D55F";
  //sm2 私钥hex串
  private final String priHex = "70698BA3576D3061C106E82568D75FD866E01F3DAD2C7F71BBC950BB6A03564D";

  private final String RSA_PUBLIC_KEY = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCq7pL6rR9L+l0WTuwEiiKn8cAvihWoIZCuU5yiH8GgXoJlsrmJyi736l0fQnv69MLsKwImalp/F0u+o9hw9HiY+72qkpjGZpwZYDYU509V4dv4IpyITWecAx1ELZHscV+BZ5HEZ73v4DESvJjzZ5rY7pN6cs4rbOPbnnaPpFFZzwIDAQAB";
  private final String RSA_PRIVATE_KEY = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAKrukvqtH0v6XRZO7ASKIqfxwC+KFaghkK5TnKIfwaBegmWyuYnKLvfqXR9Ce" +
      "/r0wuwrAiZqWn8XS76j2HD0eJj7vaqSmMZmnBlgNhTnT1Xh2/ginIhNZ5wDHUQtkexxX4FnkcRnve/gMRK8mPNnmtjuk3pyzits49uedo+kUVnPAgMBAAECgYBP9x+MpVwcW8qbqp1QvFzdK8RImTVrfBRm8Ze34tpfD4e6UwPouc0CT0J0YtKEg2gDO1WcqimfBkN5ssYJhd06lEBqNYxhbJ0esj2g5PFrS399lvnDRE/OBoH0ZhPGZBcmH+Jotf5U6vJtWobHY5V3Ja1nuv1xBtdtg2GNKpiY+QJBAOLaGS/NPV2R53/qOlsFmNofdTt6RCL0tdPSTL9TigoI5eJDBPTJJx5oXpSqJL8NDLLtfmfJX4jThBxHlqVqsqcCQQDA5RVvDDAW4AJYoW3wC10TROqvzAPlnvqfVI+q7az7F2oivPsWkMeYEd7NiGomLF/0wRBKyNhL2QeqVkdgxUyZAkB5Fn23PFBzL7xoVPiNOXGbjIshEmRoXELqLCj3P3pBXPqIScnNd8m/u2ow5Jj0udx7bbW5ZI3wFSdBiRzqcwelAkEAh8Y4Cgw4JUHUJPKr4ZT+FLwjvU4LSCtZGaF55sSZR7w5du4yhrWt6Dpb66wjm28Ms8jZYOpyZSEEpj9IyrLVsQJBALSmIa7fFTsMManISpWMHlsVe1FeizoF6wJ6zf7Kx3xyVLjVmrEQe7u9KcsGMcOH2cWS6PquD8us4Og80LJgOv4=";
  private final String KV = "1234567812345678";
  private final String SM2_SIGN_ID = "123";
  //    private String content = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWABCDEFGHIJKLMNOPQRSTUVWXYZA";
  private String content = "斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。斗破三大遗憾:药岩和云芝；海波东和蝶；你和法犸。";
//    private String content = "abcdabcdabcdabcd5";

  private TextView tv;

  private ExecutorService singleService = Executors.newSingleThreadExecutor();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        tv = findViewById(R.id.sample_text);
        //演示打印SM2密钥信息
            printSM2KeyData();
    // 演示RSA密钥对打印 N D  E
    //printRSAKeyData();
    findViewById(R.id.btnCrypt).setOnClickListener(v ->
        singleService.submit(() -> {
          jniEncAndJavaDec();
          javaEncAndJniDec();
          jniSignAndJavaVerify();
          javaSignAndJniVerify();
          compareJniAndJavaSM3Digest();
          sm4JavaEncAndJniDec();
          sm4JniEncAndJavaDec();
          rsaJniEncAndJavaDec();
          rsaJavaEncAndJniDec();
          rsaJniSignAndJavaVerify();
          rsaJavaSignAndJniVerify();
        }));

    findViewById(R.id.generateSm2KeyPair).setOnClickListener(v -> jniGenerateSm2KeyPair());

  }

  public synchronized native void jniGenerateSm2KeyPair();

  public synchronized native String jniSm2Encrypt2ASN1HexString(byte[] content);

  public synchronized native String jniSm2DecryptASN12HexString(byte[] asnData);

  public synchronized native String jniSm2Sign2HexString(byte[] content);

  public synchronized native boolean jniSm2VerifyASN1SignData(byte[] content, byte[] signASN1Data);

  public synchronized native String jniSM3Digest(byte[] content);

  public synchronized native byte[] jniSM4CBCEncrypt(byte[] content);

  public synchronized native byte[] jniSM4CBCDecrypt(byte[] cipherText);

  public synchronized native String jniRsaEncrypt(byte[] content);

  public synchronized native String jniRsaDecrypt(byte[] cipherText);

  public synchronized native String jniRsaSign(byte[] content);

  public synchronized native boolean jniRsaVerify(byte[] content, byte[] sign);


  public void javaEncAndJniDec() {
    try {

      ECPublicKeyParameters pubKey = BCECUtil.createECPublicKeyParameters(xHex, yHex, SM2Util.CURVE, SM2Util.DOMAIN_PARAMS);

      long l0 = System.currentTimeMillis();
      byte[] encryptedData = SM2Util.encrypt(SM2Engine.Mode.C1C2C3, pubKey, content.getBytes());
      Log.d("wgc", "java sm2 加密耗时" + (System.currentTimeMillis() - l0));
      byte[] encASN1Data = SM2Util.c1c2c3Convert2c1c3c2Der(encryptedData);
      long l = System.currentTimeMillis();
      String decryptContentHex = jniSm2DecryptASN12HexString(encASN1Data);
      Log.d("wgc", "jni sm2 解密耗时" + (System.currentTimeMillis() - l));
      String decryptContent = new String(ByteUtils.fromHexString(decryptContentHex));
      Log.d("wgc", "解密前后数据是否一致：     " + (decryptContent.equals(content)));

    } catch (Exception e) {
      e.printStackTrace();
    }
  }


  public void jniEncAndJavaDec() {
    try {
      long l0 = System.currentTimeMillis();
      String jniEecASN1HexString = jniSm2Encrypt2ASN1HexString(content.getBytes());
      Log.d("wgc", "jni sm2 加密耗时" + (System.currentTimeMillis() - l0));
      byte[] encASN1HexBytes = ByteUtils.fromHexString(jniEecASN1HexString);

      byte[] encData = SM2Util.c1c3c2DerConvert2c1c2c3(encASN1HexBytes);

      ECPrivateKeyParameters priKey = new ECPrivateKeyParameters(
          new BigInteger(ByteUtils.fromHexString(priHex)), SM2Util.DOMAIN_PARAMS);

      long l1 = System.currentTimeMillis();
      byte[] decryptData = SM2Util.decrypt(SM2Engine.Mode.C1C2C3, priKey, encData);
      Log.d("wgc", "java sm2 解密耗时" + (System.currentTimeMillis() - l1));
      String result = new String(decryptData);
      Log.d("wgc", "解密前后数据是否一致：     " + (result.equals(content)));

    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  public void jniSignAndJavaVerify() {

    String signHex = jniSm2Sign2HexString(content.getBytes());
    Log.d("wgc", "jniSign      " + signHex);
    ECPublicKeyParameters pubKey = BCECUtil.createECPublicKeyParameters(xHex, yHex, SM2Util.CURVE, SM2Util.DOMAIN_PARAMS);

    byte[] signDerBytes = ByteUtils.fromHexString(signHex);
    boolean verify = SM2Util.verify(pubKey, SM2_SIGN_ID.getBytes(), content.getBytes(), signDerBytes);
    Log.d("wgc", "javaVerify   " + verify);
  }

  public void javaSignAndJniVerify() {
    try {

      ECPrivateKeyParameters priKey = new ECPrivateKeyParameters(
          new BigInteger(ByteUtils.fromHexString(priHex)), SM2Util.DOMAIN_PARAMS);

      byte[] sign = SM2Util.sign(priKey, SM2_SIGN_ID.getBytes(), content.getBytes());
      Log.d("wgc", "javaSign      " + ByteUtils.toHexString(sign));
      boolean verify = jniSm2VerifyASN1SignData(content.getBytes(), sign);
      Log.d("wgc", "jniVerify   " + verify);
    } catch (Exception e) {
      e.printStackTrace();
    }
  }


  public void compareJniAndJavaSM3Digest() {
    byte[] hash = SM3Util.hash(content.getBytes());
    String javaDigest = ByteUtils.toHexString(hash).toUpperCase();
    String jniDigest = jniSM3Digest(content.getBytes()).toUpperCase();
    Log.d("wgc", "javaSM3摘要与JniSM3摘要对比是否一致   ：" + (javaDigest.equals(jniDigest)));
  }


  public void sm4JavaEncAndJniDec() {
    try {
      byte[] kv = KV.getBytes();
      byte[] cipherArray = SM4Util.encrypt_CBC_Padding(kv, kv, content.getBytes());
      byte[] contentArray = jniSM4CBCDecrypt(cipherArray);
      Log.d("wgc", "sm4 java加密与jni解密结果验证为：" + (new String(contentArray).equals(content)));
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  public void sm4JniEncAndJavaDec() {
    try {
      byte[] cipherArray = jniSM4CBCEncrypt(content.getBytes());
      byte[] kv = KV.getBytes();
      byte[] contentArray = SM4Util.decrypt_CBC_Padding(kv, kv, cipherArray);
      Log.d("wgc", "sm4 jni加密与java解密结果验证为：" + (new String(contentArray).equals(content)));
    } catch (Exception e) {
      e.printStackTrace();
    }
  }


  public void rsaJniEncAndJavaDec() {
    try {
      String hex = jniRsaEncrypt(content.getBytes());
      byte[] bytes = ByteUtils.fromHexString(hex);
      String s = Base64.encodeToString(bytes, Base64.NO_WRAP);
      String decrypt = RSAUtil.decrypt(s, RSA_PRIVATE_KEY);
      Log.d("wgc", "rsa jni加密与java解密结果验证为：" + (decrypt.equals(content)));
    } catch (Exception e) {
      e.printStackTrace();
    }
  }


  public void rsaJavaEncAndJniDec() {
    try {
      String cipher = RSAUtil.encrypt(RSA_PUBLIC_KEY, Base64.encodeToString(content.getBytes(), Base64.NO_WRAP));
      byte[] bytes = Base64.decode(cipher, Base64.NO_WRAP);
      String contentHex = jniRsaDecrypt(bytes);
      Log.d("wgc", "rsa java加密与jni解密结果验证为：" + (new String(ByteUtils.fromHexString(contentHex)).equals(content)));
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  public void rsaJniSignAndJavaVerify() {
    try {
      String signHex = jniRsaSign(content.getBytes());
      byte sign[] = ByteUtils.fromHexString(signHex);
      boolean verifySign = RSAUtil.verifySign(RSA_PUBLIC_KEY, content, Base64.encodeToString(sign, Base64.NO_WRAP));
      Log.d("wgc", "rsa jni签名与java验签结果为：" + verifySign);
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  public void rsaJavaSignAndJniVerify() {
    try {
      String sign = RSAUtil.sign(RSA_PRIVATE_KEY, content);
      byte[] signBytes = Base64.decode(sign, Base64.NO_WRAP);
      boolean verify = jniRsaVerify(content.getBytes(), signBytes);
      Log.d("wgc", "rsa java签名与jni验签结果为：" + verify);
    } catch (Exception e) {
      e.printStackTrace();
    }
  }


  private void printRSAKeyData() {

    try {

      byte[] privateKeys = Base64.decode(RSA_PRIVATE_KEY, Base64.NO_WRAP);
      RSAPrivateKey priKey = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(privateKeys));
      BigInteger privateD = priKey.getPrivateExponent();
      BigInteger n = priKey.getModulus();
      Log.d("wgc", "RSA  D:    " + ByteUtils.toHexString(privateD.toByteArray()));
      TestUtil.printHexString2Array(ByteUtils.toHexString(privateD.toByteArray()));
      Log.d("wgc", "RSA  N:    " + ByteUtils.toHexString(n.toByteArray()));
      TestUtil.printHexString2Array(ByteUtils.toHexString(n.toByteArray()));

      byte[] pKeys = Base64.decode(RSA_PUBLIC_KEY, Base64.NO_WRAP);
      RSAPublicKey pubKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(pKeys));
      BigInteger e = pubKey.getPublicExponent();
      Log.d("wgc", "RSA  E:    " + ByteUtils.toHexString(e.toByteArray()));
      TestUtil.printHexString2Array(ByteUtils.toHexString(e.toByteArray()));


    } catch (Exception e) {
      e.printStackTrace();
    }

  }


  private void printSM2KeyData() {
    try {
      AsymmetricCipherKeyPair keyPair = SM2Util.generateKeyPairParameter();
      ECPrivateKeyParameters priKey = (ECPrivateKeyParameters) keyPair.getPrivate();
      ECPublicKeyParameters pubKey = (ECPublicKeyParameters) keyPair.getPublic();

      System.out.println("Pri Hex:" + ByteUtils.toHexString(priKey.getD().toByteArray()).toUpperCase());
      TestUtil.printHexString2Array(ByteUtils.toHexString(priKey.getD().toByteArray()).toUpperCase());

      System.out.println("Pub X Hex:" + ByteUtils.toHexString(pubKey.getQ().getAffineXCoord().getEncoded()).toUpperCase());
      TestUtil.printHexString2Array(ByteUtils.toHexString(pubKey.getQ().getAffineXCoord().getEncoded()).toUpperCase());

      System.out.println("Pub Y Hex:" + ByteUtils.toHexString(pubKey.getQ().getAffineYCoord().getEncoded()).toUpperCase());
      TestUtil.printHexString2Array(ByteUtils.toHexString(pubKey.getQ().getAffineYCoord().getEncoded()).toUpperCase());

      System.out.println("Pub Point Hex:" + ByteUtils.toHexString(pubKey.getQ().getEncoded(false)).toUpperCase());
      TestUtil.printHexString2Array(ByteUtils.toHexString(pubKey.getQ().getEncoded(false)).toUpperCase());

    } catch (Exception e) {
      e.printStackTrace();
    }

    String pemSm2Pub = "-----BEGIN PUBLIC KEY-----\n" +
        "MFowFAYIKoEcz1UBgi0GCCqBHM9VAYItA0IABIauX4TCjC8jdn/vPQbAANOnj0Vm\n" +
        "GdbauCIxzdlzOJSuk9SrkywWBTngiSGHl/nHYkmBiABmXuogk600lnz41V8=\n" +
        "-----END PUBLIC KEY-----";
    try {
      byte[] keyPEMToPKCS8 = BCECUtil.convertECPublicKeyPEMToX509(pemSm2Pub);
      TestUtil.printHexString2Array(ByteUtils.toHexString(keyPEMToPKCS8));
    } catch (IOException e) {
      e.printStackTrace();
    }
//        String pemSm2Pub = "MFowFAYIKoEcz1UBgi0GCCqBHM9VAYItA0IABIauX4TCjC8jdn/vPQbAANOnj0VmGdbauCIxzdlzOJSuk9SrkywWBTngiSGHl/nHYkmBiABmXuogk600lnz41V8=";
//        byte[] sm2Pub = Base64.decode(pemSm2Pub, Base64.NO_WRAP);
//        TestUtil.printHexString2Array(ByteUtils.toHexString(sm2Pub));
  }


}