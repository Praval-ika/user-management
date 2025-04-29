package com.celcom.user.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.celcom.user.config.TokenProvider;
import com.celcom.user.entity.User;
import com.celcom.user.model.LoginUser;
import com.celcom.user.model.UserBo;
import com.celcom.user.model.PasswordResetBo;
import com.celcom.user.service.UserService;
import com.celcom.user.exception.UserNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/users")
public class UserController {

	private static final Logger log = LoggerFactory.getLogger(UserController.class);

	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private TokenProvider tokenProvider;

	@Autowired
	UserService userService;

	@GetMapping("/all")
	public ResponseEntity<?> getAllUsers(@RequestParam(required = false) String envName) {
		return new ResponseEntity<>("success", HttpStatus.OK);
	}

	@GetMapping("/{id}")
	public ResponseEntity<?> getUserById(@PathVariable Long id, @RequestParam(required = false) String envName) {
		log.info("API call to get user details for ID: {}", id);
		try {
			User user = userService.getUserById(id);
			log.info("Successfully retrieved user with ID: {}", id);
			return new ResponseEntity<>(user, HttpStatus.OK);
		} catch (UserNotFoundException e) {
			log.error("Error retrieving user with ID: {} - {}", id, e.getMessage());
			return new ResponseEntity<>(e.getMessage(), HttpStatus.NOT_FOUND);
		} catch (Exception e) {
			log.error("Unexpected error retrieving user with ID: {} - {}", id, e.getMessage());
			return new ResponseEntity<>("An unexpected error occurred", HttpStatus.INTERNAL_SERVER_ERROR);
		}
	}

	@DeleteMapping("/{id}")
	public ResponseEntity<?> deleteUserById(@PathVariable Long id, @RequestParam(required = false) String envName) {
		log.info("API call to delete user with ID: {}", id);
		try {
			boolean deleted = userService.deleteUserById(id);
			if (deleted) {
				log.info("Successfully deleted user with ID: {}", id);
				return new ResponseEntity<>("User with ID " + id + " has been deleted successfully", HttpStatus.OK);
			} else {
				log.warn("Failed to delete user with ID: {}", id);
				return new ResponseEntity<>("Failed to delete user with ID " + id, HttpStatus.INTERNAL_SERVER_ERROR);
			}
		} catch (UserNotFoundException e) {
			log.error("Error deleting user with ID: {} - {}", id, e.getMessage());
			return new ResponseEntity<>(e.getMessage(), HttpStatus.NOT_FOUND);
		} catch (Exception e) {
			log.error("Unexpected error deleting user with ID: {} - {}", id, e.getMessage());
			return new ResponseEntity<>("An unexpected error occurred while deleting user", HttpStatus.INTERNAL_SERVER_ERROR);
		}
	}

	@PostMapping("/create")
	public User createUser(@RequestBody UserBo userBo, @RequestParam(required = false) String envName) {
		return this.userService.createUser(userBo);
	}

	@PostMapping(value = "/authenticate")
	public String generateToken(@RequestBody LoginUser loginUser, @RequestParam(required = false) String envName)
			throws AuthenticationException {

		final Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(loginUser.getUserName(), loginUser.getPassWord()));
		SecurityContextHolder.getContext().setAuthentication(authentication);
		return tokenProvider.generateToken(authentication);
	}

	@PostMapping("/change-password")
	public ResponseEntity<?> changePassword(@RequestBody PasswordResetBo passwordResetBo, 
			@RequestParam(required = false) String envName) {
		log.info("API call to change password for user: {}", passwordResetBo.getUserName());
		
		// Validate request parameters
		if (passwordResetBo.getUserName() == null || passwordResetBo.getUserName().trim().isEmpty()) {
			log.error("Username is required for password change");
			return new ResponseEntity<>("Username is required", HttpStatus.BAD_REQUEST);
		}
		
		if (passwordResetBo.getOldPassword() == null || passwordResetBo.getOldPassword().trim().isEmpty()) {
			log.error("Current password is required for user: {}", passwordResetBo.getUserName());
			return new ResponseEntity<>("Current password is required", HttpStatus.BAD_REQUEST);
		}
		
		if (passwordResetBo.getNewPassword() == null || passwordResetBo.getNewPassword().trim().isEmpty()) {
			log.error("New password is required for user: {}", passwordResetBo.getUserName());
			return new ResponseEntity<>("New password is required", HttpStatus.BAD_REQUEST);
		}
		
		if (passwordResetBo.getConfirmNewPassword() == null || passwordResetBo.getConfirmNewPassword().trim().isEmpty()) {
			log.error("Confirm new password is required for user: {}", passwordResetBo.getUserName());
			return new ResponseEntity<>("Confirm new password is required", HttpStatus.BAD_REQUEST);
		}
		
		// Validate that new password and confirm password match
		if (!passwordResetBo.getNewPassword().equals(passwordResetBo.getConfirmNewPassword())) {
			log.error("New password and confirm password do not match for user: {}", passwordResetBo.getUserName());
			return new ResponseEntity<>("New password and confirm password do not match", HttpStatus.BAD_REQUEST);
		}
		
		try {
			boolean changed = userService.changePassword(passwordResetBo);
			if (changed) {
				log.info("Successfully changed password for user: {}", passwordResetBo.getUserName());
				return new ResponseEntity<>("Password changed successfully", HttpStatus.OK);
			} else {
				log.warn("Failed to change password for user: {}", passwordResetBo.getUserName());
				return new ResponseEntity<>("Failed to change password", HttpStatus.INTERNAL_SERVER_ERROR);
			}
		} catch (UserNotFoundException e) {
			log.error("Error changing password for user: {} - {}", passwordResetBo.getUserName(), e.getMessage());
			return new ResponseEntity<>(e.getMessage(), HttpStatus.NOT_FOUND);
		} catch (RuntimeException e) {
			if (e.getMessage().contains("Current password is incorrect")) {
				log.error("Current password verification failed for user: {}", passwordResetBo.getUserName());
				return new ResponseEntity<>("Current password is incorrect", HttpStatus.BAD_REQUEST);
			} else if (e.getMessage().contains("New password and confirm password do not match")) {
				log.error("New password and confirm password do not match for user: {}", passwordResetBo.getUserName());
				return new ResponseEntity<>("New password and confirm password do not match", HttpStatus.BAD_REQUEST);
			} else {
				log.error("Unexpected error changing password for user: {} - {}", 
						passwordResetBo.getUserName(), e.getMessage());
				return new ResponseEntity<>("An unexpected error occurred while changing password", 
						HttpStatus.INTERNAL_SERVER_ERROR);
			}
		} catch (Exception e) {
			log.error("Unexpected error changing password for user: {} - {}", 
					passwordResetBo.getUserName(), e.getMessage());
			return new ResponseEntity<>("An unexpected error occurred while changing password", 
					HttpStatus.INTERNAL_SERVER_ERROR);
		}
	}

}
