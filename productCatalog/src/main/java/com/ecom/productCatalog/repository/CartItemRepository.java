package com.ecom.productCatalog.repository;

import com.ecom.productCatalog.model.Cart;
import com.ecom.productCatalog.model.CartItem;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface CartItemRepository extends JpaRepository<CartItem, Long> {
    List<CartItem> findByCart(Cart cart);
}
