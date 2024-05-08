package me.hmzelidrissi.springsecurityjwtboilerplate.services.impl;

import lombok.RequiredArgsConstructor;
import me.hmzelidrissi.springsecurityjwtboilerplate.config.JWTService;
import me.hmzelidrissi.springsecurityjwtboilerplate.dtos.auth.AuthenticationResponseDto;
import me.hmzelidrissi.springsecurityjwtboilerplate.dtos.auth.SigninRequestDto;
import me.hmzelidrissi.springsecurityjwtboilerplate.dtos.auth.SignupRequestDto;
import me.hmzelidrissi.springsecurityjwtboilerplate.entities.Role;
import me.hmzelidrissi.springsecurityjwtboilerplate.entities.User;
import me.hmzelidrissi.springsecurityjwtboilerplate.repositories.UserRepository;
import me.hmzelidrissi.springsecurityjwtboilerplate.services.AuthService;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JWTService jwtService;
    private final AuthenticationManager authenticationManager;

    @Override
    public AuthenticationResponseDto signup(SignupRequestDto request) {
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new RuntimeException("Email already exists");
        }
        var user = User.builder()
                .name(request.getName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.CUSTOMER)
                .build();
        userRepository.save(user);
        var jwtToken = jwtService.generateToken(user);
        return AuthenticationResponseDto.builder()
                .token(jwtToken)
                .name(user.getName())
                .email(user.getEmail())
                .role(String.valueOf(user.getRole()))
                .build();
    }

    @Override
    public AuthenticationResponseDto signin(SigninRequestDto request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );

        var user = userRepository.findByEmail(request.getEmail()).orElseThrow();
        var jwtToken = jwtService.generateToken(user);
        return AuthenticationResponseDto.builder()
                .token(jwtToken)
                .name(user.getName())
                .email(user.getEmail())
                .role(String.valueOf(user.getRole()))
                .build();
    }
}
