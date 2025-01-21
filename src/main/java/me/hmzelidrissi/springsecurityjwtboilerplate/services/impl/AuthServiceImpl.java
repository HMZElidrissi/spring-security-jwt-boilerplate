package me.hmzelidrissi.springsecurityjwtboilerplate.services.impl;

import jakarta.servlet.http.HttpServletResponse;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import lombok.RequiredArgsConstructor;
import me.hmzelidrissi.springsecurityjwtboilerplate.config.CookieUtil;
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
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {
  private final UserRepository userRepository;
  private final PasswordEncoder passwordEncoder;
  private final AuthenticationManager authenticationManager;
  private final JwtEncoder jwtEncoder;
  private final CookieUtil cookieUtil;

  private String generateToken(User user) {
    JwtClaimsSet claims =
        JwtClaimsSet.builder()
            .issuer("bank-management-system")
            .issuedAt(Instant.now())
            .expiresAt(Instant.now().plus(15, ChronoUnit.DAYS))
            .subject(user.getEmail())
            .claim("role", user.getRole().name())
            .build();

    JwsHeader jwsHeader = JwsHeader.with(SignatureAlgorithm.RS256).build();

    return jwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, claims)).getTokenValue();
  }

  @Override
  public AuthenticationResponseDto signup(SignupRequestDto request, HttpServletResponse response) {
    if (userRepository.existsByEmail(request.email())) {
      throw new RuntimeException("Email already exists");
    }
    var user =
        User.builder()
            .name(request.name())
            .email(request.email())
            .password(passwordEncoder.encode(request.password()))
            .role(Role.CUSTOMER)
            .build();
    userRepository.save(user);

    var jwtToken = generateToken(user);
    cookieUtil.createCookie(response, jwtToken);

    return AuthenticationResponseDto.builder()
        .name(user.getName())
        .email(user.getEmail())
        .role(String.valueOf(user.getRole()))
        .build();
  }

  @Override
  public AuthenticationResponseDto signin(SigninRequestDto request, HttpServletResponse response) {
    authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(request.email(), request.password()));

    var user =
        userRepository
            .findByEmail(request.email())
            .orElseThrow(() -> new RuntimeException("User not found"));

    var jwtToken = generateToken(user);
    cookieUtil.createCookie(response, jwtToken);

    return AuthenticationResponseDto.builder()
        .name(user.getName())
        .email(user.getEmail())
        .role(String.valueOf(user.getRole()))
        .build();
  }

  @Override
  public void signout(HttpServletResponse response) {
    cookieUtil.clearCookie(response);
  }
}
