package com.example.mycollector.Security;

import com.example.mycollector.Security.crypto.LoginRsaKeyManager;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;


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
     */
    @GetMapping(value = "/login/public-key", produces = MediaType.TEXT_PLAIN_VALUE)
    @ResponseBody
    public String publicKey() {
        return rsaKeyManager.getPublicKeyPem();
    }
}
