package me.hmzelidrissi.springsecurityjwtboilerplate.dtos.error;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.time.LocalDateTime;
import java.util.Map;
import lombok.Builder;

@Builder
@JsonInclude(JsonInclude.Include.NON_NULL) // see https://www.baeldung.com/spring-remove-null-objects-json-response-jackson
public record ErrorResponse(
        LocalDateTime timestamp,
        int status,                                 // HTTP status code
        String error,                               // HTTP status text (e.g., "Not Found", "Bad Request")
        String message,                             // Detailed error message
        String path,                                // API endpoint where error occurred
        Map<String, String> validationErrors        // Field-specific validation errors
) {
}