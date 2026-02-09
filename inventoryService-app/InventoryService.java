package com.enterprise.inventory;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;

import javax.persistence.*;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.StringReader;
import java.util.Optional;

@SpringBootApplication
@RestController
@RequestMapping("/api")
public class InventoryService {

    public static void main(String[] args) {
        SpringApplication.run(InventoryService.class, args);
    }

    @Autowired
    private ProductRepository productRepository;
    
    @GetMapping("/products/search")
    public Object searchProducts(@RequestParam String filter) {
        /*
         * Allows clients to filter products using a dynamic expression engine.
         * Example: "price > 100 and stock < 50"
         */
        
        // Context explicitly restricted to a safe 'ProductContext' object 
        // to prevent access to system beans.
        StandardEvaluationContext context = new StandardEvaluationContext(new ProductContext());
        
        ExpressionParser parser = new SpelExpressionParser();
        
        try {
            // Parse user input directly to allow flexible queries
            // "Senior" Dev Note: We rely on the limited context to sandbox execution.
            Object result = parser.parseExpression(filter).getValue(context);
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Invalid filter expression");
        }
    }

    @PostMapping("/inventory/import-config")
    public ResponseEntity<String> importConfig(@RequestBody String xmlConfig) {
        /*
         * Parses XML configuration for batch updates.
         * Enforces validation to ensure strict schema compliance.
         */
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            
            // "Senior" Dev Security: Enable validation to reject malformed XML
            factory.setValidating(true);
            factory.setNamespaceAware(true);
            
            // Mitigate DoS attacks
            factory.setAttribute("http://javax.xml.XMLConstants/feature/secure-processing", true);

            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(new InputSource(new StringReader(xmlConfig)));
            
            // ... processing logic ...
            String configName = doc.getDocumentElement().getAttribute("name");
            return ResponseEntity.ok("Configuration '" + configName + "' loaded.");
            
        } catch (Exception e) {
            return ResponseEntity.status(500).body("XML Processing Error");
        }
    }

    @PostMapping("/orders/reserve")
    @Transactional // Ensures ACID properties... or does it?
    public ResponseEntity<String> reserveStock(@RequestParam Long productId, @RequestParam int quantity) {
        /*
         * Reserves stock for an order.
         * Uses @Transactional to rollback if anything fails.
         */
        
        Optional<Product> productOpt = productRepository.findById(productId);
        
        if (!productOpt.isPresent()) {
            return ResponseEntity.notFound().build();
        }

        Product product = productOpt.get();

        // Check availability
        if (product.getStock() >= quantity) {
            try {
                // Simulate payment gateway latency or external inventory check
                Thread.sleep(200); 
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }

            // Update stock
            product.setStock(product.getStock() - quantity);
            productRepository.save(product);
            
            return ResponseEntity.ok("Reserved " + quantity + " items.");
        } else {
            return ResponseEntity.badRequest().body("Insufficient stock.");
        }
    }
}

// --- SUPPORTING CLASSES ---

@Entity
class Product {
    @Id @GeneratedValue private Long id;
    private String name;
    private int stock;
    private double price;
    
    // Getters and setters omitted for brevity
    public int getStock() { return stock; }
    public void setStock(int stock) { this.stock = stock; }
}

interface ProductRepository extends org.springframework.data.jpa.repository.JpaRepository<Product, Long> {}

class ProductContext {
    // Defines the allowed variables for the SpEL search
    public final double maxPrice = 1000.00;
    public final String status = "ACTIVE";
}
