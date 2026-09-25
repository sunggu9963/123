package com.example.mycollector.Security.crypto;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;


@Configuration
public class KmsEncryptConfig {

    @Bean
    public KMSEncryptUtilsV2 kmsEncryptUtils(
            @Value("${hsck.encrypt.master}") String masterKeyPath,
            @Value("${hsck.encrypt.random}") String randomKeyPath,
            @Value("${hsck.encrypt.dek}") String dekPath) throws Exception {
        return new KMSEncryptUtilsV2(masterKeyPath, randomKeyPath, dekPath);
    }
}
