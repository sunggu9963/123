package com.example.mycollector.Security;

import com.example.mycollector.Security.crypto.KMSEncryptUtilsV2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;


@Component
public class DbConnectionProvider {

    private final KMSEncryptUtilsV2 kmsEncryptUtils;

    @Value("${db.driver:org.postgresql.Driver}")
    private String driverClassName;

    @Value("${db.url}")
    private String dbUrl;

    /** jdbc.properties의 db.Username과 동일하게, 암호화된 값 그대로 */
    @Value("${db.username}")
    private String encryptedUsername;

    /** jdbc.properties의 db.Password와 동일하게, 암호화된 값 그대로 */
    @Value("${db.password}")
    private String encryptedPassword;

    public DbConnectionProvider(KMSEncryptUtilsV2 kmsEncryptUtils) {
        this.kmsEncryptUtils = kmsEncryptUtils;
    }

    public Connection getConnection() throws SQLException {
        try {
            Class.forName(driverClassName);

            // KMS 유틸로 암호화된 계정/비밀번호를 복호화 (기존 SecureBasicDataSource와 동일한 방식)
            String username = kmsEncryptUtils.decrypt(encryptedUsername);
            String password = kmsEncryptUtils.decrypt(encryptedPassword);

            return DriverManager.getConnection(dbUrl, username, password);
        } catch (ClassNotFoundException e) {
            throw new SQLException("JDBC 드라이버를 찾을 수 없습니다: " + driverClassName, e);
        } catch (SQLException e) {
            throw e;
        } catch (Exception e) {
            // KMS 복호화 실패(키 파일 경로 오류, 암호문 손상 등)
            throw new SQLException("DB 계정 정보 복호화 중 오류가 발생했습니다.", e);
        }
    }
}
