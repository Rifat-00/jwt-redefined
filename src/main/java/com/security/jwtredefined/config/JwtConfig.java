package com.security.jwtredefined.config;


import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.Data;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.crypto.SecretKey;
import java.time.Instant;

@Configuration
@Data
public class JwtConfig {
    @Bean
    public SecretKey secretKey() {
        String secretKey = "cECBTpCjewdSCO9VRgdIo3Zl7pa0vUdsa+jVX5qz74g=\n";
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public long jwtExpiration(){
        return 60*60*1000;
    }

    @Bean
    public long refreshExpiration(){
        return 60*60*1000*24;
    }



}
