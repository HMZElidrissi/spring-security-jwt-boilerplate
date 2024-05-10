#  Secure your spring boot REST endpoints using JWT

This boilerplate provides a basic template for securing a Spring REST API using Spring Security and JWT (JSON Web Tokens) using [jwtk/jjwt](https://github.com/jwtk/jjwt) library. It also includes support for roles and permissions, allowing you to easily manage access control for your API endpoints.

## Features

* Authentication and authorization using Spring Security
* Token-based authentication using JWT
* Role-based access control
* Permission-based access control (There is examples using annotation-based authorization and configuration-based authorization)
* Example API endpoints for demonstration purposes

## Setup

1. Clone the repository and import it into your preferred IDE
2. Create a new file named `env.properties` in the root directory of your project
3. Copy the contents of `env.properties.example` into `env.properties`
4. Update the properties in `env.properties` with your own values:
    * `DB_URL`: your Postgresql database URL (e.g. `jdbc:postgresql://localhost:5432/mydb`)
    * `DB_USERNAME`: your Postgresql database username
    * `DB_PASSWORD`: your Postgresql database password
    * `JWT_SECRET_KEY`: your secret key for token generation
5. Run the application using your preferred method (e.g. `mvn spring-boot:run`)

## Usage

1. Use the `POST /login` endpoint to authenticate and obtain a token
2. Use the obtained token to access protected API endpoints
3. Use the `@PreAuthorize("hasRole('ROLE_ADMIN')")` and `@PreAuthorize("hasPermission('PERMISSION_ADMIN')")` annotations to secure your endpoints

## Contributing

If you'd like to contribute to this boilerplate, please submit a pull request with your proposed changes. All contributions are welcome!