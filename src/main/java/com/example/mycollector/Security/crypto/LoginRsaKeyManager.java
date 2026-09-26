package com.example.mycollector.Security.crypto;

import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

/**
 * 원본 hsck 프로젝트의 CryptoUtils.decryptRsa()에 대응.
 *
 * 원본은 서버 어딘가에 이미 만들어진 RSA 키쌍(파일 등)을 읽어 쓰는 방식이었을 것으로
 * 추정되는데, 여기서는 앱 기동 시 메모리에서 2048비트 키쌍을 새로 생성해서 쓴다.
 * (재기동하면 키가 바뀌지만, 로그인 페이지는 매번 새로 공개키를 받아가므로 문제 없음)
 *
 * 개인키는 이 객체 밖으로 절대 나가지 않고, decrypt()를 통해서만 사용된다.
 */
@Component
public class LoginRsaKeyManager {

    private static final String RSA_ALGORITHM = "RSA";
    private static final String CIPHER_TRANSFORMATION = "RSA/ECB/PKCS1Padding";
    private static final int KEY_SIZE = 2048;

    private final KeyPair keyPair;

    public LoginRsaKeyManager() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(RSA_ALGORITHM);
        generator.initialize(KEY_SIZE);
        this.keyPair = generator.generateKeyPair();
    }

    /**
     * 로그인 페이지(JS)에 내려줄 공개키. PEM 형식(BEGIN/END PUBLIC KEY)으로 반환.
     * 브라우저의 JSEncrypt 같은 라이브러리가 바로 읽을 수 있는 표준 형식이다.
     */
    public String getPublicKeyPem() {
        PublicKey publicKey = keyPair.getPublic();
        String base64 = Base64.getEncoder().encodeToString(publicKey.getEncoded());

        StringBuilder pem = new StringBuilder();
        pem.append("-----BEGIN PUBLIC KEY-----\n");
        for (int i = 0; i < base64.length(); i += 64) {
            pem.append(base64, i, Math.min(i + 64, base64.length())).append("\n");
        }
        pem.append("-----END PUBLIC KEY-----\n");
        return pem.toString();
    }

    /** 클라이언트가 공개키로 암호화해서 보낸 Base64 문자열을 개인키로 복호화 */
    public String decrypt(String base64CipherText) throws Exception {
        PrivateKey privateKey = keyPair.getPrivate();
        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        byte[] cipherBytes = Base64.getDecoder().decode(base64CipherText);
        byte[] plainBytes = cipher.doFinal(cipherBytes);
        return new String(plainBytes, StandardCharsets.UTF_8);
    }
}
