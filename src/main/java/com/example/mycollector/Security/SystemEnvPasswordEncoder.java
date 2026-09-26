package com.example.mycollector.Security;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * 원본 hsck.hrx.web.module.HrxPasswordEncoderDecider 대응.
 *
 * systemEnv 설정값(tbl_system_env, tag=MAINPWDCRYPTTYPE, system_id=I001)에 따라
 * 실제 사용할 PasswordEncoder를 매번(encode/matches 호출마다) 새로 결정한다.
 * → 원본처럼 값이 바뀌면 앱 재시작 없이 바로 반영된다.
 *
 * 현재는 BCRYPT만 지원한다. 원본은 SHA256 등 다른 옵션도 있었을 수 있는데,
 * 이미 확인한 대로 tbl_admmgr.passwd가 실제로 BCrypt로 저장돼 있어서 요청하신
 * 범위에서는 BCRYPT 분기만 구현했다. 다른 알고리즘 값이 실제로 쓰인다면 알려주면
 * 분기를 추가하면 된다.
 */
@Component
public class SystemEnvPasswordEncoder implements PasswordEncoder {

    private static final String TAG_MAIN_PWD_CRYPT_TYPE = "MAINPWDCRYPTTYPE";
    private static final String TYPE_BCRYPT = "BCRYPT";
    private static final String DEFAULT_TYPE = TYPE_BCRYPT;

    // 원본 주석에 있던 것과 동일하게 strength=10
    private static final BCryptPasswordEncoder BCRYPT_ENCODER = new BCryptPasswordEncoder(10);

    private final SystemEnvDao systemEnvDao;

    public SystemEnvPasswordEncoder(SystemEnvDao systemEnvDao) {
        this.systemEnvDao = systemEnvDao;
    }

    @Override
    public String encode(CharSequence rawPassword) {
        return resolveEncoder().encode(rawPassword);
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        return resolveEncoder().matches(rawPassword, encodedPassword);
    }

    private PasswordEncoder resolveEncoder() {
        String type = systemEnvDao.getTagValue(TAG_MAIN_PWD_CRYPT_TYPE);
        if (type == null || type.trim().isEmpty()) {
            type = DEFAULT_TYPE;
        }

        if (TYPE_BCRYPT.equalsIgnoreCase(type.trim())) {
            return BCRYPT_ENCODER;
        }

        // TODO: SHA256 등 다른 MAINPWDCRYPTTYPE 값이 실제로 쓰인다면 여기 분기 추가
        throw new IllegalStateException(
                "지원하지 않는 MAINPWDCRYPTTYPE 설정값입니다: " + type + " (현재 BCRYPT만 지원)");
    }
}
