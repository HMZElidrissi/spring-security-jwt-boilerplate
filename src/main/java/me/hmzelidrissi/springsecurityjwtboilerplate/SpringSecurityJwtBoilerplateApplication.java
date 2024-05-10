package me.hmzelidrissi.springsecurityjwtboilerplate;

import me.hmzelidrissi.springsecurityjwtboilerplate.dtos.auth.SignupRequestDto;
import me.hmzelidrissi.springsecurityjwtboilerplate.entities.Role;
import me.hmzelidrissi.springsecurityjwtboilerplate.services.AuthService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class SpringSecurityJwtBoilerplateApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityJwtBoilerplateApplication.class, args);
	}

	/**
	 * This method will run on application startup
	 * CommndLineRunner Usually used to run some code on application startup
	 * In this case we are using it to create some users (admin, manager)
	 * @param service
	 * @return CommandLineRunner
	 */
	/*@Bean
	public CommandLineRunner commandLineRunner(
			AuthService service
	) {
		return args -> {
			var admin = SignupRequestDto.builder()
					.name("admin")
					.email("admin@mail.com")
					.password("password")
					.role(Role.ADMIN)
					.build();
			System.out.println("Admin token :" + service.signup(admin).getToken());

			var manager = SignupRequestDto.builder()
					.name("manager")
					.email("manager@mail.com")
					.password("password")
					.role(Role.MANAGER)
					.build();
			System.out.println("Manager token :" + service.signup(manager).getToken());
		};
	}*/

}
