package org.assets.jwtdemo.utils;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import org.assets.jwtdemo.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.*;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.*;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Component
public class JwtFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private UserService userService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        String header = request.getHeader("Authorization");

        String token = null;
        String username = null;

        if (header != null && header.startsWith("Bearer ")) {
            token = header.substring(7);
            // Check if token is blacklisted
            if (jwtUtil.isBlacklisted(token)) {
                chain.doFilter(request, response);
                return;
            }
            try {
                username = jwtUtil.extractUsername(token);
            } catch (Exception e) {
                // Token is invalid, continue without authentication
            }
        }

        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            try {
                UserDetails userDetails = userService.loadUserByUsername(username);
                if (jwtUtil.validateToken(token, userDetails.getUsername())) {
                    // Extract authorities from JWT token
                    List<org.springframework.security.core.authority.SimpleGrantedAuthority> authorities = 
                        jwtUtil.extractAuthorities(token);
                    
                    UsernamePasswordAuthenticationToken authToken =
                            new UsernamePasswordAuthenticationToken(userDetails, null, authorities);

                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            } catch (Exception e) {
                // User not found or other error, continue without authentication
            }
        }

        chain.doFilter(request, response);
    }
}
