package me.hmzelidrissi.springsecurityjwtboilerplate.services;

import jakarta.servlet.http.HttpServletResponse;
import me.hmzelidrissi.springsecurityjwtboilerplate.dtos.auth.AuthenticationResponseDto;
import me.hmzelidrissi.springsecurityjwtboilerplate.dtos.auth.SigninRequestDto;
import me.hmzelidrissi.springsecurityjwtboilerplate.dtos.auth.SignupRequestDto;

public interface AuthService {

    AuthenticationResponseDto signup(SignupRequestDto request, HttpServletResponse response);

    AuthenticationResponseDto signin(SigninRequestDto request, HttpServletResponse response);

    void signout(HttpServletResponse response);
}
