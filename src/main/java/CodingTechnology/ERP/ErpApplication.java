package CodingTechnology.ERP;

import CodingTechnology.ERP.model.User;
import CodingTechnology.ERP.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
public class ErpApplication implements CommandLineRunner {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public static void main(String[] args) {
        SpringApplication.run(ErpApplication.class, args);
    }

    @Override
    public void run(String... args) throws Exception {
        // Verifica se o usuário master já existe
        if (userRepository.findByEmail("master@erp.com") == null) {
            User masterUser = new User();
            masterUser.setEmail("master@erp.com");
            masterUser.setPassword(passwordEncoder.encode("Master@123")); // Defina uma senha forte aqui
            masterUser.setRole("ADMIN"); // Define o papel de administrador
            userRepository.save(masterUser);
            System.out.println("Usuário master criado com sucesso!");
        }
    }
}
