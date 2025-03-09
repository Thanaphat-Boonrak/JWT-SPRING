package com.example.securitySpringboots.Service.services.impl;

import com.example.securitySpringboots.DTO.UserDTO;
import com.example.securitySpringboots.Entity.PasswordResetToken;
import com.example.securitySpringboots.Entity.Role;
import com.example.securitySpringboots.Entity.User;
import com.example.securitySpringboots.Repository.PasswordRestRepository;
import com.example.securitySpringboots.Repository.RoleRepository;
import com.example.securitySpringboots.Repository.UserRepository;
import com.example.securitySpringboots.Service.services.UserService;
import com.example.securitySpringboots.Utils.EmailService;
import com.example.securitySpringboots.models.AppRole;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
public class UserServiceImpl implements UserService {

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordRestRepository passwordRestRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    EmailService emailService;

    @Value("${frontend.url}")
    private String  frontendurl;


    @Override
    public void updateUserRole(Long userId, String roleName) {
        User user = userRepository.findById(userId).orElseThrow(() -> new RuntimeException("User not found"));
        AppRole appRole = AppRole.valueOf(roleName);
        Role role = roleRepository.findByRoleName(appRole)
                .orElseThrow(() -> new RuntimeException("Role not found"));
        user.setRole(role);
        userRepository.save(user);
    }


    @Override
    public List<User> getAllUsers() {
        return userRepository.findAll();
    }


    @Override
    public UserDTO getUserById(Long id) {
//        return userRepository.findById(id).orElseThrow();
        User user = userRepository.findById(id).orElseThrow();
        return convertToDto(user);
    }

    @Override
    public User findByUsername(String username) {
        Optional<User> user = userRepository.findByUserName(username);
        return user.orElseThrow(() -> new RuntimeException("User not found"));
    }

    @Override
    public void generatePasswordResetToken(String email) {
        User user = userRepository.findByEmail(email).orElseThrow(() -> new RuntimeException("Email not found"));
        String token = UUID.randomUUID().toString();
        Instant instant = Instant.now().plus(24, ChronoUnit.HOURS);
        PasswordResetToken passwordResetToken = new PasswordResetToken(token,instant,user);
        passwordRestRepository.save(passwordResetToken);
        String resetUrl = frontendurl + "/rest-password?token=" + token;

        emailService.sendPasswordResetEmail(user.getEmail(),resetUrl);
    }

    @Override
    public void resetPassword(String token, String newPassword) {
        PasswordResetToken resetToken = passwordRestRepository.findByToken(token).orElseThrow(() -> new RuntimeException("Token not found"));


        if(resetToken.isUsed()){
            throw new RuntimeException("Token is used");
        }
        if(resetToken.getExpiryDate().isBefore(Instant.now())){
            throw new RuntimeException("Token is expired");
        }

        User user = resetToken.getUser();
        user.setPassword(encoder.encode(newPassword));
        userRepository.save(user);
        resetToken.setUsed(true);
        passwordRestRepository.save(resetToken);
    }

    @Override
    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    @Override
    public void registerUser(User newUser) {
     if(newUser.getPassword() != null) {
         newUser.setPassword(encoder.encode(newUser.getPassword()));
     }
     userRepository.save(newUser);
    }

    private UserDTO convertToDto(User user) {
        return new UserDTO(
                user.getUserId(),
                user.getUserName(),
                user.getEmail(),
                user.isAccountNonLocked(),
                user.isAccountNonExpired(),
                user.isCredentialsNonExpired(),
                user.isEnabled(),
                user.getCredentialsExpiryDate(),
                user.getAccountExpiryDate(),
                user.getTwoFactorSecret(),
                user.isTwoFactorEnabled(),
                user.getSignUpMethod(),
                user.getRole(),
                user.getCreatedDate(),
                user.getUpdatedDate()
        );
    }


}
