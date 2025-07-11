package com.ecom.productCatalog.controller;

import com.ecom.productCatalog.model.Category;
import com.ecom.productCatalog.service.CategoryService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("api/categories")
public class CategoryController {

    // Dependency Injection - Constructor based. BUT why final?? - Best Practice: Signals that the dependency is required and should not be altered.
    private final CategoryService categoryService;


    public CategoryController(CategoryService categoryService) {
        this.categoryService = categoryService;
    }

    @GetMapping
    public List<Category> getAllCategories(){
        return categoryService.getAllCategories();
    }

}
