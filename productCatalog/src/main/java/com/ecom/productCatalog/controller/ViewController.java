//package com.ecom.productCatalog.controller;
//
//import com.ecom.productCatalog.model.Product;
//import com.ecom.productCatalog.repository.ProductRepository;
//import lombok.RequiredArgsConstructor;
//import org.springframework.stereotype.Controller;
//import org.springframework.ui.Model;
//import org.springframework.web.bind.annotation.GetMapping;
//
//import java.util.List;
//
//@Controller
//@RequiredArgsConstructor
//public class ViewController {
//
//    private final ProductRepository productRepository;
//
//    @GetMapping("/")
//    public String viewHomePage(Model model) {
//        List<Product> productList = productRepository.findAll();
//        model.addAttribute("products", productList);
//        return "home"; // points to home.html
//    }
//}
