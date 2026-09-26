package com.example.mycollector.Security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Repository;

import java.sql.Connection;
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

    private final DbConnectionProvider connectionProvider;

    public UserAccountDao(DbConnectionProvider connectionProvider) {
        this.connectionProvider = connectionProvider;
    }

    /** 아이디로 사용자 조회. 없으면 null 리턴 */
    public UserAccount findByUserId(String userId) {
        try (Connection conn = connectionProvider.getConnection();
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
}
