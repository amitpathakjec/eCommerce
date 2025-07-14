package com.ecom.productCatalog.model;

import jakarta.persistence.*;
import lombok.*;
import java.util.List;

@Entity
@Getter
@Setter
@ToString
@RequiredArgsConstructor
public class Cart {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // One cart per user (bidirectional optional)
    @OneToOne
    @JoinColumn(name = "user_id", unique = true)
    private User user;

    // A cart has many cart items
    @OneToMany(mappedBy = "cart", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    @ToString.Exclude
    private List<CartItem> cartItems;

    public Cart(User user) {
        this.user = user;
    }
}