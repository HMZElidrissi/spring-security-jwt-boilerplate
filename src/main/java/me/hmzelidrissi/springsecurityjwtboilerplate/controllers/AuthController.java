package me.hmzelidrissi.springsecurityjwtboilerplate.controllers;

import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import me.hmzelidrissi.springsecurityjwtboilerplate.dtos.auth.AuthenticationResponseDto;
import me.hmzelidrissi.springsecurityjwtboilerplate.dtos.auth.SigninRequestDto;
import me.hmzelidrissi.springsecurityjwtboilerplate.dtos.auth.SignupRequestDto;
import me.hmzelidrissi.springsecurityjwtboilerplate.services.AuthService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

  private final AuthService authService;

  @PostMapping("/signup")
  public ResponseEntity<AuthenticationResponseDto> signup(
      @Valid @RequestBody SignupRequestDto request, HttpServletResponse response) {
    return ResponseEntity.ok(authService.signup(request, response));
  }

  @PostMapping("/signin")
  public ResponseEntity<AuthenticationResponseDto> signin(
      @Valid @RequestBody SigninRequestDto request, HttpServletResponse response) {
    return ResponseEntity.ok(authService.signin(request, response));
  }

  @PostMapping("/signout")
  public ResponseEntity<Void> signout(HttpServletResponse response) {
    authService.signout(response);
    return ResponseEntity.ok().build();
  }
}
