package CodingTechnology.ERP.auth.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    @Autowired
    private JwtService jwtService;

    @Autowired
    private CustomUserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userUsername;

        // Se o cabeçalho de autenticação não estiver presente ou não for "Bearer ", ignora o filtro e continua a cadeia
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        // Extrai o token JWT (remove o prefixo "Bearer ")
        jwt = authHeader.substring(7);
        userUsername = jwtService.extractUsername(jwt);

        // Se o nome de usuário for válido e não houver um usuário autenticado na sessão atual
        if (userUsername != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userUsername);

            // Valida o token e o usuário
            if (jwtService.isTokenValid(jwt, userDetails)) {
                // Cria um objeto de autenticação
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                // Define o usuário como autenticado na sessão do Spring Security
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        
        // Continua a cadeia de filtros
        filterChain.doFilter(request, response);
    }
}