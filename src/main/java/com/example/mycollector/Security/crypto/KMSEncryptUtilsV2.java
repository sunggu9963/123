package com.example.mycollector.Security.crypto;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;


public class KMSEncryptUtilsV2 extends KMSEncryptUtils {

    private static final int BYTE_PER_STRING = 8;

    private final String[] hashData;

    public KMSEncryptUtilsV2(String masterKeyPath, String randomKeyPath, String dekPath)
            throws IOException, NoSuchAlgorithmException {
        super(masterKeyPath, randomKeyPath, dekPath);

        // 주의: 이 시점에 상위(KMSEncryptUtils)의 생성자가 먼저 실행되면서
        // 오버라이드된 getSaltedData()가 한 번 더 호출됩니다 (자바의 생성자-가상호출 특성).
        // 원본 클래스도 동일하게 동작하던 구조라 그대로 유지했습니다.
        String masterKey = this.readMasterKey();
        String randomKey = this.readRandomKey();

        String[] combinedData = new String[masterKey.length() / BYTE_PER_STRING];
        for (int i = 0; i < combinedData.length; i++) {
            String saltedData = this.getSaltedData(
                    masterKey.substring(i * BYTE_PER_STRING, (i + 1) * BYTE_PER_STRING),
                    randomKey.substring(i * BYTE_PER_STRING, (i + 1) * BYTE_PER_STRING));
            combinedData[i] = this.toHash(saltedData);
        }
        this.hashData = combinedData;
    }

    @Override
    protected byte[] getKEKFromHash() {
        int initIndex = 0;
        byte[] initBytes = hexStringToByteArray(
                this.getStart(this.hashData[initIndex], 16) + this.getEnd(this.hashData[initIndex], 16));
        return concat(this.recursiveXOR(initBytes, initIndex + 1), this.generateByteArray(16, (byte) 0));
    }

    private byte[] recursiveXOR(byte[] previousBytes, int index) {
        if (this.hashData.length == index) {
            return previousBytes;
        }
        byte[] thisBytes = hexStringToByteArray(
                this.getStart(this.hashData[index], 16) + this.getEnd(this.hashData[index], 16));
        byte[] result = this.doXor(previousBytes, thisBytes);
        return this.recursiveXOR(result, index + 1);
    }

    private String getStart(String data, int size) {
        return data.substring(0, size);
    }

    private String getEnd(String data, int size) {
        int start = data.length() - size;
        return data.substring(start);
    }

    private byte[] doXor(byte[] bytes1, byte[] bytes2) {
        byte[] result = new byte[bytes1.length];
        for (int i = 0; i < bytes1.length; i++) {
            result[i] = (byte) (bytes1[i] ^ bytes2[i]);
        }
        return result;
    }

    @Override
    protected String getSaltedData(String masterKey, String randomKey) {
        return toHexString(SALT) + toHexString(this.generateByteArray(4, (byte) 0)) + masterKey + randomKey;
    }

    private byte[] generateByteArray(int size, byte value) {
        byte[] result = new byte[size];
        Arrays.fill(result, value);
        return result;
    }
}
