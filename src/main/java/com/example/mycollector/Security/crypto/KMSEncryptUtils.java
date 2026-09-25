package com.example.mycollector.Security.crypto;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class KMSEncryptUtils {

    protected static final int IV_BYTE_SIZE = 16;
    protected static final int GENERATE_KEY_BLOCK_SIZE = 16;
    protected static final String DEFAULT_SHA_ALGORITHM = "SHA-256";
    protected static final String SALT = "HSCK";
    protected static final int ADDITIONAL_KEK_BYTE_SIZE = 16;

    private final String masterKeyPath;
    private final String randomKeyPath;
    private final String dekPath;

    private final String hash;

    public KMSEncryptUtils(String masterKeyPath, String randomKeyPath, String dekPath)
            throws IOException, NoSuchAlgorithmException {
        this.masterKeyPath = masterKeyPath;
        this.randomKeyPath = randomKeyPath;
        this.dekPath = dekPath;

        String masterKey = this.readMasterKey();
        String randomKey = this.readRandomKey();
        String originKek = this.getSaltedData(masterKey, randomKey);
        this.hash = this.toHash(originKek);
    }

    protected byte[] getKEKFromHash() {
        String KEK = this.hash.substring(0, 16) + this.hash.substring(this.hash.length() - 16) + toHexString(new byte[16]);
        return concat(hexStringToByteArray(KEK), new byte[16]);
    }

    protected byte[] encrypt(byte[] kek, byte[] dek)
            throws InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchAlgorithmException,
                   InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = this.getCipher(kek, Cipher.ENCRYPT_MODE);
        return cipher.doFinal(dek);
    }

    protected byte[] decrypt(byte[] key, byte[] dek)
            throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException,
                   IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        Cipher cipher = this.getCipher(key, Cipher.DECRYPT_MODE);
        return cipher.doFinal(dek);
    }

    protected byte[] getDEK()
            throws IOException, InvalidAlgorithmParameterException, NoSuchPaddingException,
                   IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        byte[] kek = this.getKEKFromHash();
        byte[] dek = this.decrypt(kek, hexStringToByteArray(toHexString(this.readFileString(this.dekPath))));
        Arrays.fill(kek, (byte) 0);
        return dek;
    }


    public String decrypt(String data)
            throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException,
                   IOException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        Cipher cipher = this.getCipher(this.getDEK(), Cipher.DECRYPT_MODE);
        byte[] decoded = Base64.getDecoder().decode(data.getBytes(StandardCharsets.UTF_8));
        return new String(cipher.doFinal(decoded), StandardCharsets.UTF_8);
    }


    public String encrypt(String data)
            throws InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchAlgorithmException,
                   InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {
        byte[] dek = this.getDEK();
        Cipher cipher = this.getCipher(dek, Cipher.ENCRYPT_MODE);
        String cipherText = Base64.getEncoder().encodeToString(cipher.doFinal(data.getBytes(StandardCharsets.UTF_8)));
        Arrays.fill(dek, (byte) 0);
        return cipherText;
    }

    private String extractMasterKey(String masterKey) {
        String regex = "\\%patrow\\$\\%(.{32})\\$";
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(masterKey);
        matcher.find();
        String key = matcher.group();
        String realKey = key.substring(9, key.length() - 1);
        return toHexString(realKey);
    }

    private String readFileString(String filePath) throws IOException {
        try (FileInputStream stream = new FileInputStream(filePath)) {
            StringBuilder builder = new StringBuilder();
            int read;
            while ((read = stream.read()) != -1) {
                builder.append((char) read);
            }
            return builder.toString();
        }
    }

    public static String toHexString(byte[] bites) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bites) {
            sb.append(String.format("%02X", b & 255));
        }
        return sb.toString();
    }

    protected static String toHexString(String message) {
        return toHexString(message.getBytes(StandardCharsets.ISO_8859_1));
    }

    protected static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }


    protected static byte[] concat(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }

    protected IvParameterSpec getIv() {
        byte[] ivArr = new byte[16];
        Arrays.fill(ivArr, (byte) 0);
        return new IvParameterSpec(ivArr);
    }

    protected Cipher getCipher(byte[] key, int mode)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        String algorithm = "AES/CBC/PKCS5Padding";
        Cipher cipher = Cipher.getInstance(algorithm);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        cipher.init(mode, keySpec, this.getIv());
        return cipher;
    }

    protected String toHash(String message) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(DEFAULT_SHA_ALGORITHM);
        byte[] bytData = hexStringToByteArray(message);
        md.update(bytData);
        byte[] digest = md.digest();
        return toHexString(digest);
    }

    protected String readMasterKey() throws IOException {
        return this.extractMasterKey(this.readFileString(this.masterKeyPath));
    }

    protected String readRandomKey() throws IOException {
        return toHexString(this.readFileString(this.randomKeyPath));
    }

    protected String getSaltedData(String masterKey, String randomKey) {
        return toHexString(SALT) + masterKey + randomKey;
    }

    public String getDEKString()
            throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException,
                   IOException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        return toHexString(this.getDEK());
    }
}
