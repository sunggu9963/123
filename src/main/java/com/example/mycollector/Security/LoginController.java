package com.example.mycollector.Security;

import com.example.mycollector.Security.crypto.LoginRsaKeyManager;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * 로그인 폼 페이지 + RSA 공개키 제공.
 *
 * 원본과 다른 점: POST 로그인 처리, 로그아웃 처리는 더 이상 여기서 하지 않는다.
 * Spring Security의 UsernamePasswordAuthenticationFilter 자리를 대신하는
 * RsaLoginAuthenticationFilter(loginProcessingUrl="/login")와
 * LogoutFilter(logoutUrl="/logout")가 자동으로 가로채서 처리하기 때문 (SecurityConfig 참고).
 */
@Controller
public class LoginController {

    private final LoginRsaKeyManager rsaKeyManager;

    public LoginController(LoginRsaKeyManager rsaKeyManager) {
        this.rsaKeyManager = rsaKeyManager;
    }

    @GetMapping("/login")
    public ResponseEntity<Resource> loginPage() {
        Resource resource = new ClassPathResource("dashboard/login.html");
        return ResponseEntity.ok().contentType(MediaType.TEXT_HTML).body(resource);
    }

    /**
     * 로그인 페이지의 JS가 아이디/비밀번호를 암호화할 때 쓸 공개키.
     * 원본의 "서버가 RSA 공개키를 로그인 페이지에 내려주는" 부분에 대응.
     *
     * 서버가 재시작되면 키가 바뀌므로, 브라우저나 중간 캐시가 이 응답을 캐시해서
     * 옛날 공개키를 계속 돌려주는 일이 없도록 캐시를 명시적으로 금지한다.
     */
    @GetMapping(value = "/login/public-key", produces = MediaType.TEXT_PLAIN_VALUE)
    @ResponseBody
    public ResponseEntity<String> publicKey() {
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .body(rsaKeyManager.getPublicKeyPem());
    }
}
