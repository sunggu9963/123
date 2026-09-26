package com.example.mycollector.Security;

import com.example.mycollector.Security.crypto.LoginRsaKeyManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;

/**
 * 원본 hsck.hrx.web.module.CustomUsernamePasswordAuthenticationFilter 대응.
 *
 * 원본은 필터에서는 복호화하지 않고 암호화된 채로 넘긴 뒤, HrxAuthenticationProvider의
 * additionalAuthenticationChecks() 안 콜백에서 뒤늦게 복호화했었다 (지난 대화에서 확인한
 * access$001 / Runnable 트릭). 여기서는 그 우회 없이, Spring Security의 정상적인 확장
 * 지점인 obtainUsername()/obtainPassword()에서 곧바로 복호화한다 - 결과는 동일하지만
 * 더 단순하고 표준적인 방식이다.
 *
 * 주의: 일부러 @Component를 안 붙였다. UsernamePasswordAuthenticationFilter는
 * javax.servlet.Filter 구현체라, 이걸 스프링 빈으로 등록하면 Spring Boot가
 * SecurityConfig의 addFilterBefore()와는 별개로 톰캣 전역 필터로 또 자동 등록해버려서
 * 요청마다 두 번 실행되는(=복호화가 두 번 일어나는) 문제가 생긴다. 그래서 SecurityConfig
 * 안에서 new로 직접 생성해서 addFilterBefore()에만 등록한다.
 */
public class RsaLoginAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final LoginRsaKeyManager rsaKeyManager;

    public RsaLoginAuthenticationFilter(LoginRsaKeyManager rsaKeyManager) {
        this.rsaKeyManager = rsaKeyManager;
    }

    @Override
    protected String obtainUsername(HttpServletRequest request) {
        return decrypt(super.obtainUsername(request));
    }

    @Override
    protected String obtainPassword(HttpServletRequest request) {
        return decrypt(super.obtainPassword(request));
    }

    private String decrypt(String encryptedValue) {
        if (encryptedValue == null || encryptedValue.isEmpty()) {
            return encryptedValue;
        }
        try {
            return rsaKeyManager.decrypt(encryptedValue);
        } catch (Exception e) {
            // 복호화 실패(값 위변조, 키 불일치, 만료된 공개키로 암호화됨 등) → 인증 실패로 처리
            throw new AuthenticationServiceException("로그인 정보를 복호화할 수 없습니다.", e);
        }
    }
}
