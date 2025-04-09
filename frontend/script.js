// Simple form validation for login page
document.getElementById('loginForm')?.addEventListener('submit', function (e) {
  e.preventDefault();
  
  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;

  if (!username || !password) {
    alert('Please fill in both username and password.');
    return;
  }

  // Send login request to backend
  fetch('http://localhost:8080/api/login', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ username, password }),
  })
  .then(response => response.json())
  .then(data => {
    const messageElement = document.getElementById('message');
    if (data.success) {
      messageElement.textContent = 'Login successful! You can now use the CLI.';
      messageElement.style.color = 'green';
    } else {
      messageElement.textContent = 'Login failed: ' + data.message;
      messageElement.style.color = 'red';
    }
  })
  .catch(error => {
    const messageElement = document.getElementById('message');
    messageElement.textContent = 'Error: ' + error.message;
    messageElement.style.color = 'red';
  });
});

// Simple form validation for sign-up page
document.getElementById('signupForm')?.addEventListener('submit', function (e) {
  e.preventDefault();

  const username = document.getElementById('newUsername').value;
  const password = document.getElementById('newPassword').value;
  const confirmPassword = document.getElementById('confirmPassword').value;
  const messageElement = document.getElementById('message');

  // Validation check
  if (!username || !password || !confirmPassword) {
    messageElement.textContent = 'Please fill in all fields.';
    messageElement.style.color = 'red';
    return;
  }

  if (password !== confirmPassword) {
    messageElement.textContent = 'Passwords do not match.';
    messageElement.style.color = 'red';
    return;
  }

  // Send registration request to backend - URL is correct
  fetch('http://localhost:8080/api/register', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ username, password }),
  })
  .then(response => response.json())
  .then(data => {
    if (data.success) {
      messageElement.textContent = 'Account created successfully! You can now use the CLI.';
      messageElement.style.color = 'green';
      setTimeout(() => {
        window.location.href = 'login.html';
      }, 2000);
    } else {
      messageElement.textContent = 'Registration failed: ' + data.message;
      messageElement.style.color = 'red';
    }
  })
  .catch(error => {
    messageElement.textContent = 'Error: ' + error.message;
    messageElement.style.color = 'red';
  });
});
