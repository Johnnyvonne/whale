package nature.wildcode.auth.util;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Random;

/**
 * 加密工具
 * md5,sha256,sha512,salted sha512
 */
public class EncryptUtil {

    private static char[] hex = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

    /**
     * 返回16个数字，每个数字是2位的16进制字符串
     * 如果单个数字小于16，则在前面补0
     *
     * @param src
     * @return
     */
    private static String bytesToHexString(byte[] src) {
        StringBuilder sb = new StringBuilder();
        if (src == null || src.length <= 0) {
            return null;
        }
        for (int i = 0; i < src.length; i++) {
            int v = src[i] & 0xFF;
            String hv = Integer.toHexString(v);
            if (hv.length() < 2) {
                sb.append(0);
            }
            sb.append(hv);
        }
        return sb.toString();
    }

    /**
     * 解析
     *
     * @param hexString
     * @return
     */
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

    /**
     * 将指定byte数组以16进制的形式打印到控制台
     *
     * @param b
     */
    public static void printHexString(byte[] b) {
        for (int i = 0; i < b.length; i++) {
            String hex = Integer.toHexString(b[i] & 0xFF);
            if (hex.length() == 1) {
                hex = '0' + hex;
            }
            System.out.print(hex.toUpperCase());
        }

    }

    /**
     * Convert char to byte
     *
     * @param c char
     * @return byte
     */
    private static byte charToByte(char c) {
        return (byte) "0123456789abcdef".indexOf(c);
    }

    /**
     * 加密
     *
     * @param str
     * @return
     */
    public static String MD5(String str) {
        String strDigest = "";
        try {
            // 此 MessageDigest 类为应用程序提供信息摘要算法的功能，必须用try,catch捕获
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            byte[] data = md5.digest(str.getBytes("utf-8"));// 转换为MD5码
            strDigest = bytesToHexString(data);
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
        return strDigest;
    }

    /**
     * 传入文本内容，返回 SHA-256 串
     *
     * @param strText
     * @return
     */
    public static String SHA256(final String strText) {
        return SHA(strText, "SHA-256");
    }

    /**
     * 传入文本内容，返回 SHA-512 串
     *
     * @param strText
     * @return
     */
    public static String SHA512(final String strText) {
        return SHA(strText, "SHA-512");
    }

    /**
     * 字符串 SHA 加密
     *
     * @param strText
     * @return
     */
    private static String SHA(final String strText, final String strType) {
        // 返回值
        String strResult = null;
        // 是否是有效字符串
        if (strText != null && strText.length() > 0) {
            try {
                // SHA 加密开始
                // 创建加密对象 并傳入加密類型
                MessageDigest messageDigest = MessageDigest.getInstance(strType);
                // 传入要加密的字符串
                messageDigest.update(strText.getBytes("utf-8"));
                // 得到 byte 類型结果
                byte[] byteBuffer = messageDigest.digest();
                strResult = bytesToHexString(byteBuffer);
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            } catch (UnsupportedEncodingException e) {
                throw new RuntimeException(e);
            }
        }
        return strResult;
    }

    public static String mixedSaltedSHA512(String source) {
        String sha512 = SHA512(source);
        int length = 64;
        String salt = salt(length);
        String saltedSha512 = SHA512(sha512 + salt);
        List<Character> cs = new ArrayList<>();
        for (int i = 0, j = 0; i / 3 * 2 + 1 <= 128; i += 3, j++) {
            cs.add(saltedSha512.charAt(i / 3 * 2));
            cs.add(salt.charAt(i / 3)); //输出带盐，存储盐到hash值中;每两个hash字符中间插入一个盐字符
            cs.add(saltedSha512.charAt(i / 3 * 2 + 1));
        }
        char[] mixed = new char[cs.size()];
        for (int i = 0; i < cs.size(); i++) {
            mixed[i] = cs.get(i);
        }
        return new String(mixed);
    }

    public static boolean matchMixedSaltedSHA512(String source, String mixedHash) {
        String sha512 = SHA512(source);
        String salt = getSaltFromHash(mixedHash);
        String saltedSHA512 = SHA512(sha512 + salt);
        List<Character> cs = new ArrayList<>();
        for (int i = 0, j = 0; i / 3 * 2 + 1 <= 128; i += 3, j++) {
            cs.add(saltedSHA512.charAt(i / 3 * 2));
            cs.add(salt.charAt(i / 3)); //输出带盐，存储盐到hash值中;每两个hash字符中间插入一个盐字符
            cs.add(saltedSHA512.charAt(i / 3 * 2 + 1));
        }
        char[] ca = new char[cs.size()];
        for (int i = 0; i < cs.size(); i++) {
            ca[i] = cs.get(i);
        }
        return Objects.equals(new String(ca), mixedHash);
    }

    private static String salt(int length) {
        Random random = new Random();
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < sb.capacity(); i++) {
            sb.append(hex[random.nextInt(hex.length)]);
        }
        return sb.toString();
    }

    private static String getSaltFromHash(String hash) {
        StringBuilder sb = new StringBuilder();
        char[] h = hash.toCharArray();
        for (int i = 0; i < hash.length(); i += 3) {
            sb.append(h[i + 1]);
        }
        return sb.toString();
    }

    public static void main(String[] args) {
        //注册
        String saltedSHA512 = EncryptUtil.mixedSaltedSHA512("AFs123456");
        String saltedSHA51211 = EncryptUtil.mixedSaltedSHA512("112233");

        System.out.println(saltedSHA512);
        System.out.println(saltedSHA51211);
//        System.out.println("==================");
//        //登录
//        System.out.println("get salt:" + EncryptUtil.getSaltFromHash(saltedSHA512));
        System.out.println(EncryptUtil.matchMixedSaltedSHA512("AFs123456", saltedSHA512));
    }
}
