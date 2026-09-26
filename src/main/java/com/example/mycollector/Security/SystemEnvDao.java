package com.example.mycollector.Security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Repository;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;


@Repository
public class SystemEnvDao {

    private static final Logger log = LoggerFactory.getLogger(SystemEnvDao.class);

    private static final String SYSTEM_ID = "I001";

    private static final String SQL_GET_TAG_VALUE =
            "select tag_value from tbl_system_env where tag like ? and system_id = ?";

    private final DbConnectionProvider connectionProvider;

    public SystemEnvDao(DbConnectionProvider connectionProvider) {
        this.connectionProvider = connectionProvider;
    }

    /**
     * 태그에 해당하는 설정값을 조회. 값이 없거나 조회 중 오류가 나면 null을 리턴한다
     * (호출부에서 null이면 기본값을 쓰도록 처리 - 원본이 list.size()==0일 때
     *  기본값을 유지하던 것과 동일한 방식).
     */
    public String getTagValue(String tag) {
        try (Connection conn = connectionProvider.getConnection();
             PreparedStatement ps = conn.prepareStatement(SQL_GET_TAG_VALUE)) {

            ps.setString(1, tag);
            ps.setString(2, SYSTEM_ID);

            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) {
                    return null;
                }
                return rs.getString("tag_value");
            }
        } catch (SQLException e) {
            log.error("systemEnv 조회 중 오류 (tag={}): {}", tag, e.getMessage(), e);
            return null;
        }
    }
}
