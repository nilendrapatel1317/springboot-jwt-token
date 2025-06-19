package org.assets.jwtdemo.controller;

import org.assets.jwtdemo.dto.ApiResponse;
import org.assets.jwtdemo.model.Product;
import org.assets.jwtdemo.service.ProductService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/products")
public class ProductController {
    @Autowired
    private ProductService productService;

    // USER & ADMIN: View all products
    @GetMapping
    public ResponseEntity<?> getAllProducts() {
        List<Product> products = productService.getAllProducts();
        return ResponseEntity.ok(new ApiResponse<>(200, products, "Product list"));
    }

    // USER & ADMIN: View single product
    @GetMapping("/{id}")
    public ResponseEntity<?> getProductById(@PathVariable Long id) {
        return productService.getProductById(id)
                .map(product -> ResponseEntity.ok(new ApiResponse<>(200, product, "Product details")))
                .orElseGet(() -> ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(new ApiResponse<>(404, null, "Product not found")));
    }

    // ADMIN: Create product
    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping
    public ResponseEntity<?> createProduct(@RequestBody Product product) {
        Product created = productService.createProduct(product);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(new ApiResponse<>(201, created, "Product created"));
    }

    // ADMIN: Update product
    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping("/update/{id}")
    public ResponseEntity<?> updateProduct(@PathVariable Long id, @RequestBody Product product) {
        Product updated = productService.updateProduct(id, product);
        return ResponseEntity.ok(new ApiResponse<>(200, updated, "Product updated"));
    }

    // ADMIN: Delete product
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/delete/{id}")
    public ResponseEntity<?> deleteProduct(@PathVariable Long id) {
        productService.deleteProduct(id);
        return ResponseEntity.ok(new ApiResponse<>(200, null, "Product deleted"));
    }

    // USER: Add to cart (dummy implementation)
    @PreAuthorize("hasRole('USER')")
    @PostMapping("/{id}/add-to-cart")
    public ResponseEntity<?> addToCart(@PathVariable Long id) {
        // Implement cart logic as needed
        return ResponseEntity.ok(new ApiResponse<>(200, null, "Product added to cart"));
    }

    // USER: Buy product (dummy implementation)
    @PreAuthorize("hasRole('USER')")
    @PostMapping("/{id}/buy")
    public ResponseEntity<?> buyProduct(@PathVariable Long id) {
        // Implement buy logic as needed
        return ResponseEntity.ok(new ApiResponse<>(200, null, "Product purchased"));
    }
} 