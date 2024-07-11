package com.appsdeveloperblog.ws.api.ApiGateway.util;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Component
public class JwtUtil {

    private static final int refreshExpirationDateInMs = 1000000000;
    private static final String SECRET = "4261656C64756E674261656C64756E674261656C64756E67";

    public boolean validateToken(final String token) {
         try{
             Jwts.parser().verifyWith(getSignKey()).build().parse(token);
             return true;
         } catch (SignatureException | MalformedJwtException | ExpiredJwtException | UnsupportedJwtException | IllegalArgumentException ignored){
            return false;
         }

    }

    public String generateToken(String userName, String id) {
        Map<String, Object> claims = new HashMap<>();
        return createToken(claims, userName, id);
    }
    public String generateRefreshToken(String token) {
        Map<String, Object> claims = new HashMap<>();

        return createRefreshToken(claims, getUsernameFromToken(token), getIdFromToken(token));
    }

    private String createToken(Map<String, Object> claims, String userName, String id) {
        return Jwts.builder()
                .claims(claims)
                .subject(userName)
                .id(id)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + 1000 * 60 * 30))
                .signWith(getSignKey())
                .compact();
    }
    private String createRefreshToken(Map<String, Object> claims, String userName, String id) {
        return Jwts.builder()
                .claims(claims)
                .subject(userName)
                .id(id)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + refreshExpirationDateInMs))
                .signWith(getSignKey())
                .compact();
    }

    private SecretKey getSignKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET);
        return Keys.hmacShaKeyFor(keyBytes);
    }
    private String getUsernameFromToken(String token) {
        Claims claims = Jwts.parser().setSigningKey(getSignKey()).build().parseClaimsJws(token).getBody();
        return claims.getSubject();

    }
    private String getIdFromToken (String token) {
        Claims claims = Jwts.parser().setSigningKey(getSignKey()).build().parseClaimsJws(token).getBody();
        return claims.getId();

    }

}
