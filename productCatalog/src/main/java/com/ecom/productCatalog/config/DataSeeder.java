package com.ecom.productCatalog.config;

import com.ecom.productCatalog.model.Category;
import com.ecom.productCatalog.model.Product;
import com.ecom.productCatalog.repository.CategoryRepository;
import com.ecom.productCatalog.repository.ProductRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import java.math.BigDecimal;
import java.util.Arrays;
import java.util.List;

@Component
@RequiredArgsConstructor
public class DataSeeder implements CommandLineRunner {

    private final CategoryRepository categoryRepository;
    private final ProductRepository productRepository;

    @Override
    public void run(String... args) {
        // Clear all existing data
        productRepository.deleteAll();
        categoryRepository.deleteAll();

        // Create categories
        Category electronics = new Category();
        electronics.setName("Electronics");

        Category clothing = new Category();
        clothing.setName("Clothing");

        Category books = new Category();
        books.setName("Books");

        // Save categories and get back saved entities with IDs
        List<Category> savedCategories = categoryRepository.saveAll(Arrays.asList(electronics, clothing, books));
        Category savedElectronics = savedCategories.get(0);
        Category savedClothing = savedCategories.get(1);
        Category savedBooks = savedCategories.get(2);

        // Create products for Electronics
        Product phone = new Product();
        phone.setName("Smartphone");
        phone.setDescription("A modern Android smartphone");
        phone.setPrice(new BigDecimal("30000"));
        phone.setImageUrl("https://placehold.co/600x400/png");
        phone.setStockQuantity(10);
        phone.setCategory(savedElectronics);

        Product laptop = new Product();
        laptop.setName("Laptop");
        laptop.setDescription("Powerful laptop for work and play");
        laptop.setPrice(new BigDecimal("99000"));
        laptop.setImageUrl("https://placehold.co/600x400/png");
        laptop.setStockQuantity(5);
        laptop.setCategory(savedElectronics);

        // Create products for Clothing
        Product tshirt = new Product();
        tshirt.setName("T-Shirt");
        tshirt.setDescription("100% Cotton T-Shirt");
        tshirt.setPrice(new BigDecimal("1999"));
        tshirt.setImageUrl("https://placehold.co/600x400/png");
        tshirt.setStockQuantity(20);
        tshirt.setCategory(savedClothing);

        Product jeans = new Product();
        jeans.setName("Jeans");
        jeans.setDescription("Comfort fit blue jeans");
        jeans.setPrice(new BigDecimal("3999"));
        jeans.setImageUrl("https://placehold.co/600x400/png");
        jeans.setStockQuantity(15);
        jeans.setCategory(savedClothing);

        // Create products for Books (optional)
        Product novel = new Product();
        novel.setName("Novel");
        novel.setDescription("Bestselling fiction novel");
        novel.setPrice(new BigDecimal("499"));
        novel.setImageUrl("https://placehold.co/600x400/png");
        novel.setStockQuantity(25);
        novel.setCategory(savedBooks);

        Product guide = new Product();
        guide.setName("Study Guide");
        guide.setDescription("Helpful guide for exam preparation");
        guide.setPrice(new BigDecimal("899"));
        guide.setImageUrl("https://placehold.co/600x400/png");
        guide.setStockQuantity(30);
        guide.setCategory(savedBooks);

        // Save products
        productRepository.saveAll(List.of(phone, laptop, tshirt, jeans, novel, guide));
    }
}
