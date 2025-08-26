document.addEventListener('DOMContentLoaded', function() {

    const loginForm = document.getElementById('loginForm');
    const registerForm = document.getElementById('registerForm');
    const messageDiv = document.getElementById('message');
    const mainCard = document.querySelector('.card h3');

    // Função para mostrar a mensagem de sucesso ou erro
    function showMessage(text, isSuccess) {
        messageDiv.textContent = text;
        messageDiv.style.color = isSuccess ? 'green' : 'red';
    }

    // Função para lidar com o login
    if (loginForm) {
        loginForm.addEventListener('submit', function(event) {
            event.preventDefault();

            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;

            // Criamos a credencial de autenticação HTTP Basic
            const auth = btoa(email + ":" + password);

            // Chamada para o endpoint de teste seguro
            fetch('/api/users/test', {
                method: 'GET',
                headers: {
                    'Authorization': 'Basic ' + auth,
                    'Content-Type': 'application/json'
                }
            })
            .then(response => {
                if (response.ok) {
                    showMessage('Login bem-sucedido! Redirecionando...', true);
                    // Futuramente, aqui você pode redirecionar o usuário para a página principal do ERP
                    window.location.href = '/dashboard'; // Exemplo de redirecionamento
                } else if (response.status === 401) {
                    showMessage('Email ou senha incorretos.', false);
                } else {
                    showMessage('Ocorreu um erro. Tente novamente.', false);
                }
            })
            .catch(error => {
                console.error('Erro:', error);
                showMessage('Não foi possível conectar ao servidor.', false);
            });
        });
    }

    // Evento de click para a tela de registro
    document.getElementById('registerLink').addEventListener('click', function(event) {
        event.preventDefault();
        mainCard.textContent = "Criar Conta";
        loginForm.classList.add('d-none'); // Oculta o formulário de login
        registerForm.classList.remove('d-none'); // Exibe o formulário de registro
    });

    // Lógica para o formulário de registro
    if (registerForm) {
        registerForm.addEventListener('submit', function(event) {
            event.preventDefault();
            const email = document.getElementById('registerEmail').value;
            const password = document.getElementById('registerPassword').value;

            fetch('/api/users/register', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ email, password })
            })
            // Mude response.json() para response.text()
            .then(response => response.text()) 
            .then(data => {
                if (data === "User registered successfully!") {
                    showMessage(data, true);
                    setTimeout(() => {
                        mainCard.textContent = "Acesso ao ERP";
                        loginForm.classList.remove('d-none');
                        registerForm.classList.add('d-none');
                        showMessage('Login com sua nova conta!', false);
                    }, 2000);
                } else {
                    showMessage(data, false);
                }
            })
            .catch(error => {
                console.error('Erro:', error);
                showMessage('Não foi possível registrar o usuário.', false);
            });
        });
    }

    // Se o usuário clicar no link "Voltar"
    document.getElementById('backToLoginLink').addEventListener('click', function(event) {
        event.preventDefault();
        mainCard.textContent = "Acesso ao ERP";
        loginForm.classList.remove('d-none');
        registerForm.classList.add('d-none');
    });

});