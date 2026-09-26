package com.example.mycollector.Security;

import com.example.mycollector.Security.crypto.LoginRsaKeyManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

/**
 * 원본 hsck 프로젝트의 applicationContext-security.xml 대응.
 *
 * 원본과 다른 점(요청하신 대로 "단순 로그인"만 남김):
 *  - IP/MAC/UUID 체크, accessDecisionManager/Voter 없음 - 로그인 여부만 검사
 *  - RSA 암호화는 유지 (원본과 동일하게 아이디/비밀번호를 암호화해서 전송)
 *    → RsaLoginAuthenticationFilter를 기본 폼로그인 필터보다 앞에 꽂아서
 *      원본의 <custom-filter before="FORM_LOGIN_FILTER" .../> 를 그대로 재현
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final CustomAuthenticationSuccessHandler successHandler;
    private final LoginRsaKeyManager rsaKeyManager;

    public SecurityConfig(CustomAuthenticationSuccessHandler successHandler,
                           LoginRsaKeyManager rsaKeyManager) {
        this.successHandler = successHandler;
        this.rsaKeyManager = rsaKeyManager;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, AuthenticationManager authenticationManager) throws Exception {

        // 일부러 @Component/빈으로 등록하지 않고 여기서 직접 생성한다.
        // (RsaLoginAuthenticationFilter 클래스 주석 참고 - Boot의 필터 이중 등록 방지)
        RsaLoginAuthenticationFilter rsaLoginAuthenticationFilter = new RsaLoginAuthenticationFilter(rsaKeyManager);
        rsaLoginAuthenticationFilter.setAuthenticationManager(authenticationManager);
        rsaLoginAuthenticationFilter.setFilterProcessesUrl("/login");
        // setFilterProcessesUrl()만 쓰면 GET/POST 구분 없이 "/login"에 오는 모든 요청을
        // 이 필터가 가로챈다. GET 요청(로그인 페이지 조회, 실패 후 리다이렉트 등)까지
        // 걸려서 "POST 아니면 인증 실패" -> "/login?error로 리다이렉트" -> 그것도 GET이라
        // 또 걸림 -> 무한 리다이렉트가 나므로, POST만 처리하도록 명시해야 한다.
        rsaLoginAuthenticationFilter.setRequiresAuthenticationRequestMatcher(
                new AntPathRequestMatcher("/login", "POST"));
        rsaLoginAuthenticationFilter.setAuthenticationSuccessHandler(successHandler);
        rsaLoginAuthenticationFilter.setAuthenticationFailureHandler(
                new SimpleUrlAuthenticationFailureHandler("/login?error"));

        http
            // 로그인 페이지가 정적 HTML(login.html)이라 CSRF 토큰을 폼에 심기 어려워 비활성화.
            // (내부 관제용 단일 관리자 로그인이라는 전제하의 트레이드오프)
            .csrf().disable()

            .authorizeHttpRequests(authorize -> authorize
                    // /login/public-key: 로그인 페이지 JS가 RSA 공개키를 받아가는 경로
                    // /collect.do: 모니터링 에이전트가 데이터 올리는 API - 로그인 불가하니 허용
                    .antMatchers("/login", "/login/public-key", "/collect.do", "/favicon.ico").permitAll()
                    .anyRequest().authenticated()
            )

            // 원본의 <custom-filter before="FORM_LOGIN_FILTER" .../> 대응:
            // RSA로 암호화된 아이디/비밀번호를 복호화하는 필터를 기본 폼로그인 필터보다 먼저 태움.
            // (성공/실패 시 각각 successHandler/failureHandler가 리다이렉트하며 체인을 끝내버리므로
            //  바로 아래 formLogin()이 등록하는 기본 필터는 원본과 마찬가지로 실제로는 실행되지 않는다)
            .addFilterBefore(rsaLoginAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)

            .formLogin(form -> form
                    .loginPage("/login")
                    .loginProcessingUrl("/login")
                    .successHandler(successHandler)
                    .failureUrl("/login?error")
                    .permitAll()
            )

            .logout(logout -> logout
                    .logoutUrl("/logout")
                    .logoutSuccessUrl("/login")
                    .invalidateHttpSession(true)          // → SessionListener가 감지해서 뒷정리
                    .permitAll()
            )

            // 대시보드 화면이 5초마다 부르는 API(/servers/**)는, 로그인 안 됐을 때
            // 로그인 페이지로 리다이렉트하지 않고 401만 내려줌 (JSON을 기대하는 fetch가 깨지지 않도록)
            .exceptionHandling(ex -> ex
                    .defaultAuthenticationEntryPointFor(
                            (request, response, authException) ->
                                    response.sendError(401, "로그인이 필요합니다."),
                            new AntPathRequestMatcher("/servers/**")
                    )
            );

        return http.build();
    }

    /**
     * PasswordEncoder 빈은 이제 여기서 만들지 않는다.
     * SystemEnvPasswordEncoder(@Component)가 PasswordEncoder를 구현하고 있어서
     * 스프링이 자동으로 그 빈을 찾아 DaoAuthenticationProvider에 사용한다.
     * (원본 hsck의 <bean id="passwdEncoder" class="...HrxPasswordEncoderDecider"/> 대응)
     */

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }
}
