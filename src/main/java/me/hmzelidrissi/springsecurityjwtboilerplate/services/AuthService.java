package me.hmzelidrissi.springsecurityjwtboilerplate.services;

import me.hmzelidrissi.springsecurityjwtboilerplate.dtos.auth.AuthenticationResponseDto;
import me.hmzelidrissi.springsecurityjwtboilerplate.dtos.auth.SigninRequestDto;
import me.hmzelidrissi.springsecurityjwtboilerplate.dtos.auth.SignupRequestDto;

public interface AuthService {

    AuthenticationResponseDto signup(SignupRequestDto request);

    AuthenticationResponseDto signin(SigninRequestDto request);
}
