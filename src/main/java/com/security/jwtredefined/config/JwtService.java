package com.security.jwtredefined.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

@Service
@RequiredArgsConstructor
public class JwtService {
    private String secretKey = "cECBTpCjewdSCO9VRgdIo3Zl7pa0vUdsa+jVX5qz74g=\n";
    private final long jwtExpiration;
    private final long refreshExpiration;
    
    // Access Token  Refresh Token
    
    //build tokenBuilder
    private String tokenBuilder(
            Map<String, Object> extraClaims,
            UserDetails userDetails,
            long expiration
    ) {
        return Jwts.builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(expiration)))
                .signWith(  secretKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    ;


    //generate token with extra claims
    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return tokenBuilder(extraClaims, userDetails, jwtExpiration);
    }

    //generate token without extra claims
    public String generateToken(UserDetails userdetails) {
        return tokenBuilder(new HashMap<>(), userdetails, jwtExpiration);
    }

    //generate refresh token
    public String refreshToken(UserDetails userdetails) {
        return tokenBuilder(new HashMap<>(), userdetails, refreshExpiration);
    }

    //extract all claims from the token
    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(secretKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    //extract a single claim
    public <T> T extractClaim(String token, Function<Claims, T> claimResolver) {
        final Claims claims = extractAllClaims(token);
        return claimResolver.apply(claims);
    }

    //extract username
    public String extractUsername(String token) {
        try {
            return extractClaim(token, Claims::getSubject);
        } catch (Exception e) {
            return null;
        }
    }

    //extract expiration
    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    //check token if it's expired
    public boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    //check of tokens belongs to the actual user
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    //generate key
    public SecretKey secretKey() {

        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

}
