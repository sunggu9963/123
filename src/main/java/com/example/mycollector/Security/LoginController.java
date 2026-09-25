package com.example.mycollector.Security;

import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;


@Controller
public class LoginController {

    @GetMapping("/login")
    public ResponseEntity<Resource> loginPage() {
        Resource resource = new ClassPathResource("dashboard/login.html");
        return ResponseEntity.ok().contentType(MediaType.TEXT_HTML).body(resource);
    }
}
