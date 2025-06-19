package org.assets.jwtdemo.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.stream.Collectors;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKey;

@Component
public class JwtUtil {
    private final SecretKey key;
    private final Set<String> tokenBlacklist = Collections.synchronizedSet(new HashSet<>());
    private final Map<String, Set<String>> userActiveTokens = new HashMap<>();

    public JwtUtil(@Value("${jwt.secret}") String secret) {
        this.key = new SecretKeySpec(secret.getBytes(), SignatureAlgorithm.HS256.getJcaName());
    }

    public String generateToken(String username, Collection<? extends GrantedAuthority> authorities) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("roles", authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList()));
        
        return createToken(claims, username);
    }

    private String createToken(Map<String, Object> claims, String subject) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 5 * 60 * 1000)) // 5 minutes
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    public String extractUsername(String token) {
        return extractAllClaims(token).getSubject();
    }

    public List<SimpleGrantedAuthority> extractAuthorities(String token) {
        Claims claims = extractAllClaims(token);
        List<String> roles = claims.get("roles", List.class);
        if (roles != null) {
            return roles.stream()
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());
        }
        return new ArrayList<>();
    }

    public boolean validateToken(String token, String username) {
        try {
            return extractUsername(token).equals(username) && !isExpired(token);
        } catch (Exception e) {
            return false;
        }
    }

    private boolean isExpired(String token) {
        return extractAllClaims(token).getExpiration().before(new Date());
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser().setSigningKey(key).parseClaimsJws(token).getBody();
    }

    public void addToBlacklist(String token) {
        tokenBlacklist.add(token);
    }

    public boolean isBlacklisted(String token) {
        return tokenBlacklist.contains(token);
    }

    public void cleanupBlacklist() {
        tokenBlacklist.removeIf(token -> {
            try {
                return isExpired(token);
            } catch (Exception e) {
                return true;
            }
        });
    }

    public synchronized void storeUserToken(String username, String token) {
        userActiveTokens.computeIfAbsent(username, k -> new HashSet<>()).add(token);
    }

    public synchronized Set<String> getUserTokens(String username) {
        return userActiveTokens.getOrDefault(username, Collections.emptySet());
    }

    public synchronized void blacklistAllUserTokens(String username) {
        Set<String> tokens = userActiveTokens.get(username);
        if (tokens != null) {
            for (String t : tokens) {
                addToBlacklist(t);
            }
            tokens.clear();
        }
    }
}
