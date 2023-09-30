package com.kado.authservice.controller;

import com.kado.authservice.dto.LoginRequest;
import com.kado.authservice.dto.LoginResponse;
import com.kado.authservice.service.AuthService;
import com.kado.authservice.service.UserService;
import jakarta.servlet.ServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class AuthController {

    private final AuthService userService;

    @PostMapping("/login")
    public LoginResponse login(@RequestBody LoginRequest loginRequest,
        @RequestHeader("User-Agent") String userAgent,
        ServletRequest servletRequest) {
        return userService.login(loginRequest, userAgent, servletRequest.getRemoteAddr());
    }

    @PostMapping("/register")
    public LoginResponse register(@RequestBody LoginRequest loginRequest,
                                  @RequestHeader("User-Agent") String userAgent,
                                  ServletRequest servletRequest) {
        return userService.register(loginRequest, userAgent, servletRequest.getRemoteAddr());
    }

    @PostMapping("/refresh")
    public LoginResponse refresh(@RequestBody String refreshToken) {
        return userService.refreshToken(refreshToken);
    }

    @PostMapping("/logout")
    public void logout(@RequestBody String refreshToken) {
        userService.logout(refreshToken);
    }

}
