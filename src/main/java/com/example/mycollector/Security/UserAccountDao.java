package com.example.mycollector.Security;

import com.example.mycollector.Security.crypto.KMSEncryptUtilsV2;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Repository;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;


@Repository
public class UserAccountDao {

    private static final Logger log = LoggerFactory.getLogger(UserAccountDao.class);

    private static final String SQL_FIND_BY_ADMID =
            "select admcd, admid, passwd, admnm, rolecd " +
            "  from tbl_admmgr " +
            " where admid = ?";

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

    public UserAccountDao(KMSEncryptUtilsV2 kmsEncryptUtils) {
        this.kmsEncryptUtils = kmsEncryptUtils;
    }

    /** 아이디로 사용자 조회. 없으면 null 리턴 */
    public UserAccount findByUserId(String userId) {
        try (Connection conn = getConnection();
             PreparedStatement ps = conn.prepareStatement(SQL_FIND_BY_ADMID)) {

            ps.setString(1, userId);

            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) {
                    return null; // 해당 아이디 없음
                }
                UserAccount account = new UserAccount();
                account.setUserSeq(rs.getLong("admcd"));
                account.setUserId(rs.getString("admid"));
                account.setPasswordHash(rs.getString("passwd"));
                account.setUserName(rs.getString("admnm"));
                account.setUserRole(rs.getString("rolecd"));
                return account;
            }
        } catch (SQLException e) {
            log.error("DB 조회 중 오류 (userId={}): {}", userId, e.getMessage(), e);
            throw new RuntimeException("사용자 조회 중 DB 오류가 발생했습니다.", e);
        }
    }

    private Connection getConnection() throws SQLException {
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
