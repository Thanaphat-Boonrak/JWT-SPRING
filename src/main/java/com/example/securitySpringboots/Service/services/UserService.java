package com.example.securitySpringboots.Service.services;


import com.example.securitySpringboots.DTO.UserDTO;
import com.example.securitySpringboots.Entity.User;

import java.util.List;

public interface UserService {
    void updateUserRole(Long userId, String roleName);

    List<User> getAllUsers();

    UserDTO getUserById(Long id);
    User findByUsername(String username);

    void generatePasswordResetToken(String email);

    void resetPassword(String token, String newPassword);
}
