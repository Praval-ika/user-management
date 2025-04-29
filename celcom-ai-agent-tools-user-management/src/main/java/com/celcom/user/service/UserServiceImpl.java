package com.celcom.user.service;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.ObjectUtils;

import com.celcom.user.entity.User;
import com.celcom.user.exception.InvalidUserIdException;
import com.celcom.user.exception.UserAlreadyExistException;
import com.celcom.user.exception.UserNotFoundException;
import com.celcom.user.model.UserBo;
import com.celcom.user.model.PasswordResetBo;
import com.celcom.user.repository.UserRepository;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service(value = "userService")
public class UserServiceImpl implements UserDetailsService, UserService {

	@Autowired
	UserRepository userRepository;

	@Autowired
	HttpServletRequest req;

	private final String alphaNumeric = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvxyz";

	private final String otpNumeric = "1234567890";

	public User getUserDetails(String userName) {

		User user = this.userRepository.findByUserName(userName);
		if (user != null) {
			return user;
		} else {
			throw new UserNotFoundException("No data available with this userId: " + userName, "UserServiceImpl",
					"getUserDetails");
		}
	}

	private String generatePassword(int passwordLength) {
		StringBuilder password = new StringBuilder(passwordLength);
		for (int i = 0; i < passwordLength; i++) {
			int index = (int) (alphaNumeric.length() * Math.random());
			password.append(alphaNumeric.charAt(index));
		}
		return password.toString();
	}

	private String generateOtp(int passwordLength) {
		StringBuilder otp = new StringBuilder(passwordLength);
		for (int i = 0; i < passwordLength; i++) {
			int index = (int) (otpNumeric.length() * Math.random());
			otp.append(otpNumeric.charAt(index));
		}
		return otp.toString();
	}

	public UserDetails loadUserByUsername(String username) {
		User user = this.userRepository.findByUserName(username);
		if (user == null) {
			throw new UserNotFoundException("No data available with this userName: " + username, "UserServiceImpl",
					"loadUserByUsername");
		}
		return new org.springframework.security.core.userdetails.User(user.getUserName(), user.getPassWord(),
				getAuthority(user));
	}

	private Set<SimpleGrantedAuthority> getAuthority(User user) {
		Set<SimpleGrantedAuthority> authorities = new HashSet<>();
		String[] roles = user.getRoles().split(",");
		for (String role : roles) {
			authorities.add(new SimpleGrantedAuthority("ROLE_" + role));
		}
		return authorities;
	}

	@Override
	public List<User> getAllUsers() {
		return this.userRepository.findAll();
	}

	@Override
	public String getUserRole(String userName) {
		return String.valueOf(req.getAttribute("userRole"));
	}

	@Override
	public User getUserById(Long id) {
		log.info("Fetching user details for user ID: {}", id);
		User user = this.userRepository.findById(id).orElse(null);
		if (user != null) {
			log.info("User found with ID: {}", id);
			return user;
		} else {
			log.error("User not found with ID: {}", id);
			throw new UserNotFoundException("No data available with this userId: " + id, "UserServiceImpl",
					"getUserById");
		}
	}

	@Override
	public boolean deleteUserById(Long id) {
		log.info("Attempting to delete user with ID: {}", id);
		try {
			User user = this.userRepository.findById(id).orElse(null);
			if (user != null) {
				log.info("User found with ID: {}, proceeding with deletion", id);
				this.userRepository.deleteById(id);
				log.info("User with ID: {} successfully deleted", id);
				return true;
			} else {
				log.error("User not found with ID: {}, cannot delete", id);
				throw new UserNotFoundException("No data available with this userId: " + id, "UserServiceImpl",
						"deleteUserById");
			}
		} catch (UserNotFoundException e) {
			log.error("UserNotFoundException while deleting user with ID: {} - {}", id, e.getMessage());
			throw e;
		} catch (Exception e) {
			log.error("Unexpected error while deleting user with ID: {} - {}", id, e.getMessage());
			throw new RuntimeException("Failed to delete user with ID: " + id, e);
		}
	}

	@Override
	public boolean changePassword(PasswordResetBo passwordResetBo) {
		log.info("Attempting to change password for user: {}", passwordResetBo.getUserName());
		try {
			User user = this.userRepository.findByUserName(passwordResetBo.getUserName());
			if (user != null) {
				log.info("User found with username: {}, verifying current password", passwordResetBo.getUserName());
				
				// Verify current password
				BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
				if (passwordEncoder.matches(passwordResetBo.getOldPassword(), user.getPassWord())) {
					log.info("Current password verified for user: {}", passwordResetBo.getUserName());
					
					// Update password
					user.setPassWord(passwordEncoder.encode(passwordResetBo.getNewPassword()));
					this.userRepository.save(user);
					
					log.info("Password successfully changed for user: {}", passwordResetBo.getUserName());
					return true;
				} else {
					log.error("Current password verification failed for user: {}", passwordResetBo.getUserName());
					throw new RuntimeException("Current password is incorrect");
				}
			} else {
				log.error("User not found with username: {}", passwordResetBo.getUserName());
				throw new UserNotFoundException("No data available with this username: " + passwordResetBo.getUserName(), 
						"UserServiceImpl", "changePassword");
			}
		} catch (UserNotFoundException e) {
			log.error("UserNotFoundException while changing password for user: {} - {}", 
					passwordResetBo.getUserName(), e.getMessage());
			throw e;
		} catch (Exception e) {
			log.error("Unexpected error while changing password for user: {} - {}", 
					passwordResetBo.getUserName(), e.getMessage());
			throw new RuntimeException("Failed to change password for user: " + passwordResetBo.getUserName(), e);
		}
	}

	public User createUser(UserBo userBo) {
		if (userBo.getUserName() != null) {
			User userDetails = this.userRepository.findByUserName(userBo.getUserName());
			if (ObjectUtils.isEmpty(userDetails)) {

				User user = new User();
				user.setId(1l);
				user.setUserName(userBo.getUserName());
				// String password = generatePassword(12);
				user.setPassWord(new BCryptPasswordEncoder().encode(userBo.getPassWord()));
				user.setRoles(userBo.getRoles());
				user.setStatus(userBo.isStatus());
				user.setNewUser(true);

				user.setFirstName(userBo.getFirstName());
				user.setLastName(userBo.getLastName());

				this.userRepository.save(user);

				return user;
			} else {
				throw new InvalidUserIdException("Invalid Userid", "UserServiceImpl", "createUser");
			}
		} else {
			throw new UserAlreadyExistException("User already exists with this userName: " + userBo.getUserName(),
					"UserServiceImpl", "createUser");
		}
	}
}
