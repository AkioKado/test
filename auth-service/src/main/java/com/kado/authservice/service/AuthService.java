package com.kado.authservice.service;

import com.kado.authservice.dto.LoginRequest;
import com.kado.authservice.dto.LoginResponse;
import com.kado.authservice.entity.Session;
import com.kado.authservice.entity.User;
import com.kado.authservice.jwt.JwtProvider;
import com.kado.authservice.repository.SessionRepository;
import com.kado.authservice.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Collection;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final SessionRepository sessionRepository;
    private final DaoAuthenticationProvider authenticationManager;
    private final JwtProvider jwtTokenProvider;
    private final PasswordEncoder passwordEncoder;


    public LoginResponse login(LoginRequest loginRequest, String userAgent, String ip) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword())
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String token = jwtTokenProvider.generateAccessToken(authentication);
        String refreshToken = jwtTokenProvider.generateRefreshToken(authentication);
        Session session = Session.builder()
                .token(refreshToken)
                .userAgent(userAgent)
                .ip(ip)
                .build();
        User user = userRepository.findByUsername(loginRequest.getUsername()).get();
        user.getSessions().add(session);
        userRepository.save(user);
        return LoginResponse.builder()
                .accessToken(token)
                .refreshToken(refreshToken)
                .accessTokenExpiration((long) (1000 * 60 * 60 * 24 * 7))
                .refreshTokenExpiration((long) (1000 * 60 * 60 * 24 * 7))
                .build();
    }

    public LoginResponse register(LoginRequest loginRequest, String userAgent, String ip) {
        if (userRepository.existsByUsername(loginRequest.getUsername())) {
            throw new RuntimeException("Username already exists");
        }

        User user = User.builder()
                .username(loginRequest.getUsername())
                .password(passwordEncoder.encode(loginRequest.getPassword()))
                .build();

        userRepository.save(user);

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword())
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String token = jwtTokenProvider.generateAccessToken(authentication);
        String refreshToken = jwtTokenProvider.generateRefreshToken(authentication);

        Session session = Session.builder()
                .token(refreshToken)
                .userAgent(userAgent)
                .ip(ip)
                .build();

        user.getSessions().add(session);
        userRepository.save(user);

        return LoginResponse.builder()
                .accessToken(token)
                .refreshToken(refreshToken)
                .accessTokenExpiration((long) (1000 * 60 * 60 * 24 * 7))
                .refreshTokenExpiration((long) (1000 * 60 * 60 * 24 * 7))
                .build();
    }


    public LoginResponse refreshToken(String refreshToken) {
        if (!jwtTokenProvider.validateToken(refreshToken)) {
            throw new RuntimeException("Invalid refresh token");
        }
        String username = jwtTokenProvider.getUsernameFromToken(refreshToken);
        User user = userRepository.findByUsername(username).get();
        if (user.getSessions().stream().noneMatch(session -> session.getToken().equals(refreshToken))) {
            throw new RuntimeException("Invalid refresh token");
        }
        Authentication authentication = new Authentication() {
            @Override
            public Collection<? extends GrantedAuthority> getAuthorities() {
                return user.getRoles();
            }

            @Override
            public Object getCredentials() {
                return null;
            }

            @Override
            public Object getDetails() {
                return null;
            }

            @Override
            public Object getPrincipal() {
                return user.getUsername();
            }

            @Override
            public boolean isAuthenticated() {
                return true;
            }

            @Override
            public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {

            }

            @Override
            public String getName() {
                return user.getUsername();
            }
        };
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String token = jwtTokenProvider.generateAccessToken(authentication);
        String newRefreshToken = jwtTokenProvider.generateRefreshToken(authentication);
        Session session = sessionRepository.findByToken(refreshToken).get();
        session.setToken(newRefreshToken);
        sessionRepository.save(session);
        return LoginResponse.builder()
                .accessToken(token)
                .refreshToken(newRefreshToken)
                .accessTokenExpiration((long) (1000 * 60 * 60 * 24 * 7))
                .refreshTokenExpiration((long) (1000 * 60 * 60 * 24 * 7))
                .build();
    }

    public void logout(String refreshToken) {
        if (!jwtTokenProvider.validateToken(refreshToken)) {
            throw new RuntimeException("Invalid refresh token");
        }
        String username = jwtTokenProvider.getUsernameFromToken(refreshToken);
        User user = userRepository.findByUsername(username).get();
        if (user.getSessions().stream().noneMatch(session -> session.getToken().equals(refreshToken))) {
            throw new RuntimeException("Invalid refresh token");
        }
        Session session = sessionRepository.findByToken(refreshToken).get();
        sessionRepository.delete(session);
    }
}
