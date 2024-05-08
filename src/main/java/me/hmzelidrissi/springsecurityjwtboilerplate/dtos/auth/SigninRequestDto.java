package me.hmzelidrissi.springsecurityjwtboilerplate.dtos.auth;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Builder
@Data
@AllArgsConstructor
@NoArgsConstructor
public class SigninRequestDto {
    @NotNull(message = "email is required")
    @Email(message = "email should be valid")
    private String email;

    @NotNull(message = "password is required")
    private String password;
}
