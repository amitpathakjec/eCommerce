package com.ecom.productCatalog.controller;

import com.ecom.productCatalog.model.Product;
import com.ecom.productCatalog.service.ProductService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.List;

@Controller
public class BuyerController {

    @Autowired
    private ProductService productService;

    @GetMapping("/buyer/home")
    public String buyerHome(Model model, @AuthenticationPrincipal UserDetails userDetails) {
        List<Product> products = productService.getAllProducts();
        model.addAttribute("products", products);
        model.addAttribute("username", userDetails.getUsername());
        return "buyer-home";
    }
}
