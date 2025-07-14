package com.ecom.productCatalog.controller;

import com.ecom.productCatalog.model.User;
import com.ecom.productCatalog.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/users")
public class UserController {

    @Autowired
    private UserService userService;

    // Update user info (Authenticated)
    @PutMapping("/{id}")
    public ResponseEntity<?> updateUser(
            @PathVariable Long id,
            @RequestBody User updatedUser,
            @AuthenticationPrincipal UserDetails userDetails) {

        // Allow update if current user is the target user or is ADMIN
        if (!userService.canModifyUser(id, userDetails)) {
            return ResponseEntity.status(403).body("Forbidden");
        }

        User user = userService.updateUser(id, updatedUser);
        if (user == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(user);
    }

    // Delete user (Authenticated)
    @DeleteMapping("/{id}")
    public ResponseEntity<?> deleteUser(
            @PathVariable Long id,
            @AuthenticationPrincipal UserDetails userDetails) {

        // Allow delete if current user is the target user or is ADMIN
        if (!userService.canModifyUser(id, userDetails)) {
            return ResponseEntity.status(403).body("Forbidden");
        }

        boolean deleted = userService.deleteUser(id);
        if (!deleted) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok("User deleted successfully.");
    }
}