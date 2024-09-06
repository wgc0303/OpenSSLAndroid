package cn.wgc.openssl;

import java.math.BigInteger;

/**
 * <pre>
 *
 *     author : wgc
 *     time   : 2021/12/17
 *     desc   :
 *     version: 1.0
 *
 * </pre>
 */
public class SM2ASN1Parse {

  public static final int MARKER_0X00 = 0x00;
  public static final int MARKER_0X81 = 0x81;
  public static final int MARKER_0X82 = 0x82;


  public static final int INTEGER = 0x02;
  public static final int OCTET_STRING = 0x04;
  public static final int SEQUENCE_STRING = 0x30;


  public static final int SM3_DIGEST_LENGTH = 32;
  //标准SM2曲线长度计算出为32
  public static final int SM2_CURVE_LENGTH = 32;

  /**
   长度域表达方式有两种：
   1、短格式byte<=127的长度域直接以16进制表示，例：32就为0x20; 2、长格式  127<byte<=255为 例：158就为819e   255<byte<=65535为 例：1500就为8205DC
   说明可以参考 https://blog.csdn.net/mao834099514/article/details/109078662
   sm2加密数据ASN.1编码格式由四部分组成 c1x+c1y+c3+c2, c1x+c1y称为c1
   c1x和c1y的ASN.1编码规格相同，数据为{0x02,长度域(0x20或0x21)，数据（32位或者33位）}，当c1x和c1y是大正数是前面需要加0 所以大负数是32位，大正数是33位
   c3为签名数据，其ASN.1的编码格式为{0x04,0x20(长度域固定32位)，32位数据}
   c2为加密数据，其长度跟明文长度一致， C2的ASN1编码的数据为{0x04,长度域，数据}
   sm2整体的ASN.1编码数据为(0x30,长度域（计算出c1ASN.1+c3ASN.1+c2ASN.1的总byte长度域表达式）,密文数据}
   */

  /**
   * 将c1c2c3原始拼接的数据编码成der数据
   *
   * @param cipher c1c2c3原始数据
   * @return der数据
   */
  public static byte[] c1c2c3Convert2c1c3c2Der(byte[] cipher) {

    byte[] c1x = new byte[SM2_CURVE_LENGTH];
    byte[] c1y = new byte[SM2_CURVE_LENGTH];
    byte[] c2 = new byte[cipher.length - c1x.length - c1y.length - 1 - SM3_DIGEST_LENGTH];
    byte[] c3 = new byte[SM3_DIGEST_LENGTH];

    int startPos = 1;
    System.arraycopy(cipher, startPos, c1x, 0, c1x.length);
    startPos += c1x.length;
    System.arraycopy(cipher, startPos, c1y, 0, c1y.length);
    startPos += c1y.length;
    System.arraycopy(cipher, startPos, c2, 0, c2.length);
    startPos += c2.length;
    System.arraycopy(cipher, startPos, c3, 0, c3.length);

    byte[] c1xDer = bigInteger2Der(c1x);
    byte[] c1yDer = bigInteger2Der(c1y);
    byte[] c2Der = octetString2der(c2);
    byte[] c3Der = octetString2der(c3);

    byte[] c1c3c2Der = merge2c1c3c2Der(c1xDer, c1yDer, c2Der, c3Der);
    resetArray2null(c1x, c1y, c2, c3, c1xDer, c1yDer, c2Der, c3Der);

    return c1c3c2Der;

  }

  /**
   * 将 c1,c2,c3合并成 序列（SEQUENCE）der
   *
   * @param c1xDer c1x ASN.1编码的数据
   * @param c1yDer c1y ASN.1编码的数据
   * @param c2Der c2 ASN.1编码的数据
   * @param c3Der c3 ASN.1编码的数据
   * @return 序列排序的Der
   */
  private static byte[] merge2c1c3c2Der(byte[] c1xDer, byte[] c1yDer, byte[] c2Der, byte[] c3Der) {
    int totalLen = c1xDer.length + c1yDer.length + c3Der.length + c2Der.length;
    int marker = calculateMarker(totalLen);
    int derLen = 0;
    String lenHex = "";
    switch (marker) {
      case MARKER_0X00:
        derLen = totalLen + 2;
        lenHex = String.format("%02x", totalLen);
        break;
      case MARKER_0X81:
        derLen = totalLen + 3;
        lenHex = String.format("%02x", totalLen);
        break;
      case MARKER_0X82:
        derLen = totalLen + 4;
        lenHex = String.format("%04x", totalLen);
        break;
    }

    byte[] c1c3c2Der = new byte[derLen];
    c1c3c2Der[0] = (byte) SEQUENCE_STRING;
    byte[] lenBytes = hexStringToBytes(lenHex);
    if (marker == MARKER_0X00) {
      System.arraycopy(lenBytes, 0, c1c3c2Der, 1, lenBytes.length);
      System.arraycopy(c1xDer, 0, c1c3c2Der, 1 + lenBytes.length, c1xDer.length);
      System.arraycopy(c1yDer, 0, c1c3c2Der, 1 + lenBytes.length + c1xDer.length, c1yDer.length);
      System.arraycopy(c3Der, 0, c1c3c2Der, 1 + lenBytes.length + c1xDer.length + c1yDer.length, c3Der.length);
      System.arraycopy(c2Der, 0, c1c3c2Der, 1 + lenBytes.length + c1xDer.length + c1yDer.length + c3Der.length, c2Der.length);

    } else {
      c1c3c2Der[1] = (byte) marker;
      System.arraycopy(lenBytes, 0, c1c3c2Der, 2, lenBytes.length);
      System.arraycopy(c1xDer, 0, c1c3c2Der, 2 + lenBytes.length, c1xDer.length);
      System.arraycopy(c1yDer, 0, c1c3c2Der, 2 + lenBytes.length + c1xDer.length, c1yDer.length);
      System.arraycopy(c3Der, 0, c1c3c2Der, 2 + lenBytes.length + c1xDer.length + c1yDer.length, c3Der.length);
      System.arraycopy(c2Der, 0, c1c3c2Der, 2 + lenBytes.length + c1xDer.length + c1yDer.length + c3Der.length, c2Der.length);
    }

    return c1c3c2Der;
  }

  /**
   * 字节串(字节数组)编码成 der
   *
   * @param content 字节数组
   * @return der octet
   */
  private static byte[] octetString2der(byte[] content) {
    int marker = calculateMarker(content.length);
    int derLen = 0;
    String lenHex = "";
    switch (marker) {
      case MARKER_0X00:
        derLen = content.length + 2;
        lenHex = String.format("%02x", content.length);
        break;
      case MARKER_0X81:
        derLen = content.length + 3;
        lenHex = String.format("%02x", content.length);
        break;
      case MARKER_0X82:
        derLen = content.length + 4;
        lenHex = String.format("%04x", content.length);
        break;
    }

    byte[] cipherDer = new byte[derLen];
    cipherDer[0] = (byte) OCTET_STRING;
    byte[] lenBytes = hexStringToBytes(lenHex);
    if (marker == MARKER_0X00) {
      System.arraycopy(lenBytes, 0, cipherDer, 1, lenBytes.length);
      System.arraycopy(content, 0, cipherDer, 1 + lenBytes.length, content.length);
    } else {
      cipherDer[1] = (byte) marker;
      System.arraycopy(lenBytes, 0, cipherDer, 2, lenBytes.length);
      System.arraycopy(content, 0, cipherDer, 2 + lenBytes.length, content.length);
    }
    return cipherDer;
  }

  /**
   * 大整形数据编码成 der
   *
   * @param bigBytes 大整形byte数据
   * @return der
   */
  private static byte[] bigInteger2Der(byte[] bigBytes) {
    byte[] bigIntegerBytes = new BigInteger(1, bigBytes).toByteArray();
    int marker = calculateMarker(bigIntegerBytes.length);
    int derLen = 0;
    String lenHex = "";
    switch (marker) {
      case MARKER_0X00:
        derLen = bigIntegerBytes.length + 2;
        lenHex = String.format("%02x", bigIntegerBytes.length);
        break;
      case MARKER_0X81:
        derLen = bigIntegerBytes.length + 3;
        lenHex = String.format("%02x", bigIntegerBytes.length);
        break;
      case MARKER_0X82:
        derLen = bigIntegerBytes.length + 4;
        lenHex = String.format("%04x", bigIntegerBytes.length);
        break;
    }

    byte[] bigIntegerDer = new byte[derLen];
    bigIntegerDer[0] = (byte) INTEGER;
    byte[] lenBytes = hexStringToBytes(lenHex);
    if (marker == MARKER_0X00) {
      System.arraycopy(lenBytes, 0, bigIntegerDer, 1, lenBytes.length);
      System.arraycopy(bigIntegerBytes, 0, bigIntegerDer, 1 + lenBytes.length, bigIntegerBytes.length);
    } else {
      bigIntegerDer[1] = (byte) marker;
      System.arraycopy(lenBytes, 0, bigIntegerDer, 2, lenBytes.length);
      System.arraycopy(bigIntegerBytes, 0, bigIntegerDer, 2 + lenBytes.length, bigIntegerBytes.length);
    }
    return bigIntegerDer;
  }

  public static byte[] c1c3c2DerConvert2c1c2c3(byte[] der) {
    return c1c3c2DerConvert2c1c2c3(der, true);
  }

  /**
   * c1c3c2 ASN.1编码数据还原成 c1c2c3原始数据
   *
   * @param der c1c3c2 ASN.1编码数据
   * @param needCompress 是否需要添加04压缩标志符
   * @return c1c2c3原始数据
   */
  public static byte[] c1c3c2DerConvert2c1c2c3(byte[] der, boolean needCompress) {
    try {
      byte[] totalDer = restoreDer2Data(der);
      byte[] c1xDer = cutDstDerInConcatDer(0, totalDer);
      byte[] c1yDer = cutDstDerInConcatDer(c1xDer.length, totalDer);
      byte[] c3Der = cutDstDerInConcatDer(c1xDer.length + c1yDer.length, totalDer);
      byte[] c2Der = cutDstDerInConcatDer(c1xDer.length + c1yDer.length + c3Der.length, totalDer);

      byte[] c1x = fixToCurveLengthBytes(restoreDer2Data(c1xDer));
      byte[] c1y = fixToCurveLengthBytes(restoreDer2Data(c1yDer));
      byte[] c3 = restoreDer2Data(c3Der);
      byte[] c2 = restoreDer2Data(c2Der);

      int totalLen = c1x.length + c1y.length + c3.length + c2.length;

      int startPosition;
      byte[] c1c2c3;
      if (needCompress) {
        startPosition = 1;
        c1c2c3 = new byte[totalLen + 1];
        c1c2c3[0] = (byte) 0x04;
      } else {
        startPosition = 0;
        c1c2c3 = new byte[totalLen];
      }

      System.arraycopy(c1x, 0, c1c2c3, startPosition, c1x.length);
      System.arraycopy(c1y, 0, c1c2c3, startPosition + c1x.length, c1y.length);
      System.arraycopy(c2, 0, c1c2c3, startPosition + c1x.length + c1y.length, c2.length);
      System.arraycopy(c3, 0, c1c2c3, startPosition + c1x.length + c1y.length + c2.length, c3.length);

      resetArray2null(totalDer, c1xDer, c1yDer, c3Der, c2Der, c1x, c1y, c3, c2);

      return c1c2c3;
    } catch (Exception e) {
      return null;
    }
  }


  public static byte[] hexStringToBytes(String hexString) {
    if (hexString == null || hexString.equals("")) {
      return null;
    }
    hexString = hexString.toUpperCase();
    int length = hexString.length() / 2;
    char[] hexChars = hexString.toCharArray();
    byte[] d = new byte[length];
    for (int i = 0; i < length; i++) {
      int pos = i * 2;
      d[i] = (byte) (charToByte(hexChars[pos]) << 4 | charToByte(hexChars[pos + 1]));
    }
    return d;
  }

  public static String byte2HexSting(byte[] data) {
    StringBuilder stringBuffer = new StringBuilder();
    for (int aR_data : data) {
      stringBuffer.append(String.format("%02X", aR_data & 0x00ff));
    }
    return stringBuffer.toString();
  }


  private static byte charToByte(char c) {
    return (byte) "0123456789ABCDEFabcdef".indexOf(c);
  }


  private static int calculateMarker(int len) {
    int marker;
    if (len <= 127) {
      marker = MARKER_0X00;
    } else if (len <= 255) {
      marker = MARKER_0X81;
    } else {
      marker = MARKER_0X82;
    }
    return marker;
  }

  /**
   * 还原der数据
   *
   * @param der der数据
   * @return 原始数据
   */
  public static byte[] restoreDer2Data(byte[] der) {

    byte derMarker = der[0];

    switch (derMarker) {
      case (byte) SEQUENCE_STRING:
      case (byte) INTEGER:
      case (byte) OCTET_STRING:
        break;
      default:
        return null;
    }

    byte lenMarker = der[1];
    byte[] lenBytes;
    int totalMarkerLen;
    switch (lenMarker) {

      case (byte) MARKER_0X81:
        lenBytes = new byte[1];
        System.arraycopy(der, 2, lenBytes, 0, lenBytes.length);
        totalMarkerLen = 1 + 2;
        break;

      case (byte) MARKER_0X82:
        lenBytes = new byte[2];
        System.arraycopy(der, 2, lenBytes, 0, lenBytes.length);
        totalMarkerLen = 1 + 3;
        break;
      default:
        lenBytes = new byte[1];
        System.arraycopy(der, 1, lenBytes, 0, lenBytes.length);
        totalMarkerLen = 1 + 1;
        break;
    }
    String hexLen = byte2HexSting(lenBytes);

    long len = Long.parseLong(hexLen, 16);
    if (der.length - totalMarkerLen != len) {
      System.out.println("数据局长度不符");
      return null;
    }

    byte[] dstData = new byte[(int) len];
    System.arraycopy(der, totalMarkerLen, dstData, 0, dstData.length);
    return dstData;
  }

  /**
   * 从一串拼接的der中截取目标der
   *
   * @param startIndex der数据的开始位置
   * @param der 拼接的der数据
   * @return der数据
   */
  private static byte[] cutDstDerInConcatDer(int startIndex, byte[] der) {

    byte derMarker = der[startIndex];
    switch (derMarker) {
      case (byte) SEQUENCE_STRING:
      case (byte) INTEGER:
      case (byte) OCTET_STRING:
        break;
      default:
        return null;
    }

    byte lenMarker = der[startIndex + 1];
    byte[] lenBytes;
    int totalMarkerLen;
    switch (lenMarker) {

      case (byte) MARKER_0X81:
        lenBytes = new byte[1];
        System.arraycopy(der, startIndex + 2, lenBytes, 0, lenBytes.length);
        totalMarkerLen = 1 + 2;
        break;

      case (byte) MARKER_0X82:
        lenBytes = new byte[2];
        System.arraycopy(der, startIndex + 2, lenBytes, 0, lenBytes.length);
        totalMarkerLen = 1 + 3;
        break;
      default:
        lenBytes = new byte[1];
        System.arraycopy(der, startIndex + 1, lenBytes, 0, lenBytes.length);
        totalMarkerLen = 1 + 1;
        break;
    }
    String hexLen = byte2HexSting(lenBytes);

    long len = Long.parseLong(hexLen, 16);
    int derLen = (int) (len + totalMarkerLen);
    if (der.length < derLen) {
      System.out.println("数据局长度过短");
      return null;
    }
    byte[] dstData = new byte[derLen];
    System.arraycopy(der, startIndex, dstData, 0, dstData.length);
    return dstData;
  }


  /**
   * 还原sm2 C1x和C1y 大整形数据
   *
   * @return 大整形原始数据
   */
  public static byte[] fixToCurveLengthBytes(byte[] src) {
    if (src.length == SM2_CURVE_LENGTH) {
      return src;
    }

    byte[] result = new byte[SM2_CURVE_LENGTH];
    if (src.length > SM2_CURVE_LENGTH) {
      System.arraycopy(src, src.length - result.length, result, 0, result.length);
    } else {
      System.arraycopy(src, 0, result, result.length - src.length, src.length);
    }
    return result;
  }


  private static void resetArray2null(byte[]... bytes) {

    for (byte[] b : bytes) {
      b = null;
    }
  }


}
