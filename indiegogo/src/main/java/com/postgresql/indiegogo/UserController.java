package com.postgresql.indiegogo;

import java.util.Date;
import java.util.Map;
import java.util.Set;
import javax.servlet.ServletException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@RestController
public class UserController {

    private static final String SECRET_KEY = "your_secret_key";

    @Autowired
    private UserRepo repo;

    @PostMapping("/signUp")
    public ApiResponse addUser(@RequestBody Map<String, String> signUpRequest) {
        String[] requiredFields = { "email", "passwordHash", "firstName", "lastName" };

        Set<String> unauthorizedKeys = signUpRequest.keySet();
        boolean flag = true;

        for (String field : requiredFields) {
            if (!unauthorizedKeys.contains(field)) {
                flag = false;
                break;
            }
        }

        if (unauthorizedKeys.size() > 4) {
            return new ApiResponse("Only the required fields (email, passwordHash, firstName, lastName) are allowed.", null);
        }

        String email = signUpRequest.get("email");
        String passwordHash = signUpRequest.get("passwordHash");
        String firstName = signUpRequest.get("firstName");
        String lastName = signUpRequest.get("lastName");

        if (!flag || email == null || passwordHash == null || firstName == null || lastName == null) {
            return new ApiResponse("All required fields (email, passwordHash, firstName, lastName) must be provided.", signUpRequest);
        }

        if (repo.findByEmail(email) != null) {
            return new ApiResponse("User with email '" + email + "' already exists.", email);
        }

        User user = new User(email, passwordHash, firstName, lastName);
        repo.save(user);
        return new ApiResponse("User added successfully.", user);
    }

    @GetMapping("/GetAllUSers")
    public ApiResponse getAllUsers() {
        return new ApiResponse("Users retrieved successfully", repo.findAll());
    }

    @PostMapping("/signIn")
    public ApiResponse signIn(@RequestBody Map<String, String> credentials) {
        String email = credentials.get("email");
        String password = credentials.get("passwordHash");
        User user = repo.findByEmail(email);

        if (user != null && user.getPasswordHash().equals(password)) {
            String token = generateToken(user.getEmail());
            return new ApiResponse("Sign-in successful", "User: " + user + " Token: " + token);
        } else {
            return new ApiResponse("Invalid email or password", null);
        }
    }

    @SuppressWarnings("deprecation")
	@PostMapping("/authenticate")
    public boolean authenticate(@RequestBody Map<String, String> authRequest) throws ServletException {
        String token = authRequest.get("token");
        if (token == null) {
            throw new ServletException("Token is missing");
        }

        try {
            Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            throw new ServletException("Invalid token");
        }
    }

    @SuppressWarnings("deprecation")
	private String generateToken(String email) {
        Date expiration = new Date(System.currentTimeMillis() + 3600000);
        return Jwts.builder()
                .setSubject(email)
                .setExpiration(expiration)
                .signWith(SignatureAlgorithm.HS512, SECRET_KEY)
                .compact();
    }
}
