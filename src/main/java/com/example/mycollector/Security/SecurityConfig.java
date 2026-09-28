package com.example.mycollector.Security;

import com.example.mycollector.Security.crypto.LoginRsaKeyManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.session.ChangeSessionIdAuthenticationStrategy;
import org.springframework.security.web.authentication.session.CompositeSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.ConcurrentSessionControlAuthenticationStrategy;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.Arrays;


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

        // ===== 동시 세션 제어를 이 필터에 수동으로 연결 =====
        // .sessionManagement().maximumSessions(1) 설정은 스프링이 formLogin()으로 직접
        // 만든 필터에는 자동으로 연결해주지만, 우리처럼 필터를 직접 new해서 쓰는 경우엔
        // 이 연결이 자동으로 안 일어난다. 그래서 "로그인 시점에 기존 세션을 찾아서
        // 튕겨내는" 로직(ConcurrentSessionControlAuthenticationStrategy)을 여기서 직접
        // 만들어서 필터에 꽂아준다. (아래 sessionManagement()의 ConcurrentSessionFilter는
        // "이미 튕겨진 세션이 다음 요청을 보냈을 때 감지"하는 역할이라 이것과는 별개로 필요함)
        ConcurrentSessionControlAuthenticationStrategy concurrentSessionStrategy =
                new ConcurrentSessionControlAuthenticationStrategy(sessionRegistry());
        concurrentSessionStrategy.setMaximumSessions(1);
        concurrentSessionStrategy.setExceptionIfMaximumExceeded(false); // 새 로그인을 막지 않고, 기존 세션을 튕겨냄

        rsaLoginAuthenticationFilter.setSessionAuthenticationStrategy(new CompositeSessionAuthenticationStrategy(Arrays.asList(
                concurrentSessionStrategy,
                new ChangeSessionIdAuthenticationStrategy(),       // 세션 고정 공격 방지 (세션ID 교체)
                new RegisterSessionAuthenticationStrategy(sessionRegistry()) // 새 세션을 레지스트리에 등록
        )));

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
                        // POST 요청일 때만 로그아웃 처리 (기본값으로 두면 GET도 허용될 수 있음).
                        // 이렇게 하면 주소창에 /logout을 직접 입력(=GET)하는 것만으로는
                        // 로그아웃되지 않고, 대시보드의 로그아웃 버튼(POST 폼 제출)을 눌러야만 동작함.
                        .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "POST"))
                        .logoutSuccessUrl("/login")
                        .invalidateHttpSession(true)          // → SessionListener가 감지해서 뒷정리
                        .permitAll()
                )

                // ===== 동시 세션 제어 (원본 hsck의 exclusiveLogin=true 대응) =====
                // 같은 아이디로 다른 PC/브라우저에서 로그인하면, 기존에 로그인해있던 세션을
                // 만료시킨다. maxSessionsPreventsLogin(false) = 나중에 로그인한 쪽을 막는 게
                // 아니라, 나중 로그인은 성공시키고 "기존" 세션을 튕겨낸다.
                .sessionManagement(session -> session
                        .maximumSessions(1)
                        .maxSessionsPreventsLogin(false)
                        .expiredUrl("/login?expired")
                        .sessionRegistry(sessionRegistry())
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
     */

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    /** 동시 세션 제어가 "현재 누가 로그인해있는지" 추적하는 저장소 */
    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }

    /**
     * 세션이 소멸될 때(타임아웃/로그아웃) SessionRegistry에도 그 사실이 반영되도록 하는
     * 컨테이너 리스너. 이게 없으면 이미 죽은 세션이 SessionRegistry에 계속 "살아있는 것"
     * 으로 남아서 동시 세션 제어가 오작동할 수 있다.
     * (우리가 만든 SessionListener와는 별개로 둘 다 등록되어 함께 동작한다)
     */
    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }
}
