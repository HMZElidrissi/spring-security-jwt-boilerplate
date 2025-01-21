#  Secure your spring boot REST endpoints using JWT

This boilerplate provides a basic template for securing a Spring REST API using Spring Security OAuth2 resource server.

for more information Check my article [You need to ditch your JWT authentication filter](https://hmzelidrissi.ma/blog/You-need-to-ditch-your-JWT-authentication-filter/)

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
5. Generate the private and public keys `app.private.key` and `app.public.key` using the following commands:
    * `openssl genrsa -out app.private.key 2048`
    * `openssl rsa -in app.private.key -pubout -out app.public.key`
    * Move the generated keys to the `src/main/resources` directory
6. Run the application using your preferred method (e.g. `mvn spring-boot:run`)

## Usage

1. Use the `POST /login` endpoint to authenticate and obtain a token
2. Use the obtained token to access protected API endpoints
3. Use the `@PreAuthorize("hasRole('ROLE_ADMIN')")` and `@PreAuthorize("hasPermission('PERMISSION_ADMIN')")` annotations to secure your endpoints

## Contributing

If you'd like to contribute to this boilerplate, please submit a pull request with your proposed changes. All contributions are welcome!