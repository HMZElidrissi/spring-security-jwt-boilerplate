package me.hmzelidrissi.springsecurityjwtboilerplate.exceptions;


public class ResourceNotFoundException extends RuntimeException {
  public ResourceNotFoundException(String message) {
    super(message);
  }
}
