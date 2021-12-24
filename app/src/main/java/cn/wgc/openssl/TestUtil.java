package cn.wgc.openssl;

import android.util.Log;

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
public class TestUtil {

    public static void printHexString2Array(String hex) {
        int len = hex.length();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < len; i += 2) {
            sb.append("0x").append(hex.substring(i, i + 2)).append(",");
            if ((i + 2) % 16 == 0 && i > 0) {
                sb.append("\n");
            }
        }
        String data = sb.toString().trim();
        Log.d("wgc", " 字节数组  ：    \n{" + data.substring(0, data.length() - 1).toLowerCase() + "}");
    }
}
