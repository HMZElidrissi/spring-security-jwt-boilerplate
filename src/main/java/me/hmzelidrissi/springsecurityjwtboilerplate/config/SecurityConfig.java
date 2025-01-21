package me.hmzelidrissi.springsecurityjwtboilerplate.config;

import static me.hmzelidrissi.springsecurityjwtboilerplate.entities.Permission.*;
import static me.hmzelidrissi.springsecurityjwtboilerplate.entities.Role.ADMIN;
import static me.hmzelidrissi.springsecurityjwtboilerplate.entities.Role.MANAGER;
import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableMethodSecurity
public class SecurityConfig {
    private final CookieUtil cookieUtil;
    @Value("${spring.security.oauth2.resourceserver.jwt.private-key}")
    private RSAPrivateKey privateKey;

    @Value("${spring.security.oauth2.resourceserver.jwt.public-key}")
    private RSAPublicKey publicKey;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                .csrf(AbstractHttpConfigurer::disable) // AbstractHttpConfigurer::disable is a method reference to the disable method of the AbstractHttpConfigurer class
                .authorizeHttpRequests(req ->
                        req.requestMatchers("/api/v1/auth/**")
                                .permitAll()
                                .requestMatchers("/api/v1/management/**").hasAnyRole(ADMIN.name(), MANAGER.name())
                                .requestMatchers(HttpMethod.GET, "/api/v1/management/**").hasAnyAuthority(ADMIN_READ.name(), MANAGER_READ.name())
                                .requestMatchers(HttpMethod.POST, "/api/v1/management/**").hasAnyAuthority(ADMIN_CREATE.name(), MANAGER_CREATE.name())
                                .requestMatchers(HttpMethod.PUT, "/api/v1/management/**").hasAnyAuthority(ADMIN_UPDATE.name(), MANAGER_UPDATE.name())
                                .requestMatchers(HttpMethod.DELETE, "/api/v1/management/**").hasAnyAuthority(ADMIN_DELETE.name(), MANAGER_DELETE.name())

                                /*.requestMatchers(HttpMethod.GET, "/api/v1/admin/**").hasRole(ADMIN.name())
                                .requestMatchers(HttpMethod.POST, "/api/v1/admin/**").hasAuthority(ADMIN_CREATE.name())
                                .requestMatchers(HttpMethod.PUT, "/api/v1/admin/**").hasAuthority(ADMIN_UPDATE.name())
                                .requestMatchers(HttpMethod.DELETE, "/api/v1/admin/**").hasAuthority(ADMIN_DELETE.name())*/

                                .anyRequest()
                                .authenticated()
                )
                .sessionManagement(session -> session.sessionCreationPolicy(STATELESS))
                .oauth2ResourceServer(oauth2 -> {
                    oauth2.bearerTokenResolver(cookieBearerTokenResolver());
                    oauth2.jwt(jwt -> jwt
                            .decoder(jwtDecoder())
                            .jwtAuthenticationConverter(jwtAuthenticationConverter())
                    );
                });

        return httpSecurity.build();
    }

    @Bean
    public BearerTokenResolver cookieBearerTokenResolver() {
        return cookieUtil::extractToken;
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withPublicKey(publicKey).build();
    }

    @Bean
    public JwtEncoder jwtEncoder() {
        JWK jwk = new RSAKey.Builder(publicKey).privateKey(privateKey).build();
        JWKSource<SecurityContext> jwks = new ImmutableJWKSet<>(new JWKSet(jwk));
        return new NimbusJwtEncoder(jwks);
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter authoritiesConverter = new JwtGrantedAuthoritiesConverter();
        authoritiesConverter.setAuthoritiesClaimName("role");
        authoritiesConverter.setAuthorityPrefix("ROLE_");

        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(authoritiesConverter);
        return converter;
    }
}
