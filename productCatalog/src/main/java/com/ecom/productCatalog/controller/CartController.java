package com.ecom.productCatalog.controller;

import com.ecom.productCatalog.model.CartItem;
import com.ecom.productCatalog.model.User;
import com.ecom.productCatalog.service.CartService;
import com.ecom.productCatalog.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.math.BigDecimal;
import java.util.List;
import java.util.Optional;

@Controller
@RequestMapping("/cart")
public class CartController {

    @Autowired
    private CartService cartService;
    @Autowired
    private UserService userService;

    @GetMapping
    public String viewCart(@AuthenticationPrincipal UserDetails userDetails, Model model) {
        Optional<User> user = userService.findByUsername(userDetails.getUsername());
        List<CartItem> cartItems = cartService.getCartItems(user.orElse(null));
        BigDecimal total = cartService.getTotal(user.orElse(null));
        model.addAttribute("cartItems", cartItems);
        model.addAttribute("total", total);
        return "cart";
    }

    @PostMapping("/add/{productId}")
    public String addToCart(@PathVariable Long productId, @RequestParam(defaultValue = "1") int quantity,
                            @AuthenticationPrincipal UserDetails userDetails) {
        Optional<User> user = userService.findByUsername(userDetails.getUsername());
        cartService.addProductToCart(user.orElse(null), productId, quantity);
        return "redirect:/cart";
    }

    @PostMapping("/update/{cartItemId}")
    public String updateCartItem(@PathVariable Long cartItemId, @RequestParam int quantity) {
        cartService.updateCartItem(cartItemId, quantity);
        return "redirect:/cart";
    }

    @PostMapping("/remove/{cartItemId}")
    public String removeCartItem(@PathVariable Long cartItemId) {
        cartService.removeCartItem(cartItemId);
        return "redirect:/cart";
    }

    @PostMapping("/checkout")
    public String checkout(@AuthenticationPrincipal UserDetails userDetails, Model model) {
        // Implement checkout logic here
        // E.g. create Order, clear cart, etc.
        return "redirect:/orders"; // or a success page
    }
}