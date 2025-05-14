// Elementos del DOM
const loginSection = document.getElementById('loginSection');
const registerSection = document.getElementById('registerSection');
const appSection = document.getElementById('appSection');

const loginForm = document.getElementById('loginForm');
const usernameInput = document.getElementById('username');
const passwordInput = document.getElementById('password');
const loginMessage = document.getElementById('loginMessage');
const showRegisterLink = document.getElementById('showRegister');

const registerForm = document.getElementById('registerForm');
const newUsernameInput = document.getElementById('newUsername');
const newPasswordInput = document.getElementById('newPassword');
const confirmPasswordInput = document.getElementById('confirmPassword');
const registerMessage = document.getElementById('registerMessage');
const showLoginLink = document.getElementById('showLogin');
const registerLoader = document.getElementById('registerLoader');

const logoutButton = document.getElementById('logoutButton');
const messageInput = document.getElementById('message');
const encryptButton = document.getElementById('encryptButton');
const decryptButton = document.getElementById('decryptButton');
const appMessage = document.getElementById('appMessage');
const resultTextarea = document.getElementById('result');

const OPERATION_TIMEOUT = 30000; // 30 segundos de tiempo de espera para operaciones
const USERS_STORAGE_KEY = 'app_rsa_users'; // Clave para localStorage

// --- Funciones Auxiliares para Criptografía ---
function arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}

function base64ToArrayBuffer(base64) {
    const binary_string = window.atob(base64);
    const len = binary_string.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes.buffer;
}

// --- Lógica de Mensajes ---
function showMessage(element, text, type = 'info') { // types: info, error, success
    element.textContent = text;
    element.classList.remove('hidden', 'message-box-info', 'message-box-error', 'message-box-success');
    if (type === 'error') element.classList.add('message-box-error');
    else if (type === 'success') element.classList.add('message-box-success');
    else element.classList.add('message-box-info');
}

function hideMessage(element) {
    element.classList.add('hidden');
    element.textContent = '';
}

function toggleButtonLoading(button, isLoading, loaderElement = null) {
    const loader = loaderElement || button.querySelector('.loader');
    if (isLoading) {
        button.disabled = true;
        if (loader) loader.classList.remove('hidden');
    } else {
        button.disabled = false;
        if (loader) loader.classList.add('hidden');
    }
}

// --- Lógica de Almacenamiento de Usuarios (localStorage - INSEGURO PARA PRODUCCIÓN) ---
function getUsers() {
    const users = localStorage.getItem(USERS_STORAGE_KEY);
    return users ? JSON.parse(users) : {};
}

async function saveUser(username, password) {
    // ADVERTENCIA: Guardar contraseñas y claves privadas en localStorage es EXTREMADAMENTE INSEGURO.
    // Esto es solo para demostración en un entorno sin backend.
    const users = getUsers();
    if (users[username]) {
        return { success: false, message: 'El usuario ya existe.' };
    }

    try {
        // Generar par de claves RSA-OAEP
        const keyPair = await window.crypto.subtle.generateKey(
            {
                name: "RSA-OAEP",
                modulusLength: 2048,
                publicExponent: new Uint8Array([0x01, 0x00, 0x01]), // 65537
                hash: "SHA-256",
            },
            true, // exportable
            ["encrypt", "decrypt"]
        );

        const publicKeyJWK = await window.crypto.subtle.exportKey("jwk", keyPair.publicKey);
        const privateKeyJWK = await window.crypto.subtle.exportKey("jwk", keyPair.privateKey);

        users[username] = { 
            password: password, // Contraseña en texto plano (inseguro)
            publicKeyJWK: publicKeyJWK,
            privateKeyJWK: privateKeyJWK 
        };
        localStorage.setItem(USERS_STORAGE_KEY, JSON.stringify(users));
        return { success: true };
    } catch (error) {
        console.error("Error generando claves o guardando usuario:", error);
        return { success: false, message: 'Error al generar claves criptográficas.' };
    }
}

function verifyUser(username, password) {
    const users = getUsers();
    const userData = users[username];
    return userData && userData.password === password;
}

// --- Lógica de Autenticación y Vistas ---
function showLoginView() {
    loginSection.classList.remove('hidden');
    registerSection.classList.add('hidden');
    appSection.classList.add('hidden');
    hideMessage(loginMessage);
    hideMessage(registerMessage);
}

function showRegisterView() {
    loginSection.classList.add('hidden');
    registerSection.classList.remove('hidden');
    appSection.classList.add('hidden');
    hideMessage(loginMessage);
    hideMessage(registerMessage);
}

function showAppView() {
    loginSection.classList.add('hidden');
    registerSection.classList.add('hidden');
    appSection.classList.remove('hidden');
}

async function handleRegister(event) {
    event.preventDefault();
    hideMessage(registerMessage);
    const username = newUsernameInput.value.trim();
    const password = newPasswordInput.value;
    const confirmPassword = confirmPasswordInput.value;

    if (!username || !password || !confirmPassword) {
        showMessage(registerMessage, 'Todos los campos son obligatorios.', 'error');
        return;
    }
    if (password !== confirmPassword) {
        showMessage(registerMessage, 'Las contraseñas no coinciden.', 'error');
        return;
    }
    if (password.length < 6) {
        showMessage(registerMessage, 'La contraseña debe tener al menos 6 caracteres.', 'error');
        return;
    }
    
    const registerButton = registerForm.querySelector('button[type="submit"]');
    toggleButtonLoading(registerButton, true, registerLoader);

    const result = await saveUser(username, password);
    
    toggleButtonLoading(registerButton, false, registerLoader);

    if (result.success) {
        showMessage(registerMessage, '¡Usuario registrado exitosamente! Ahora puedes iniciar sesión.', 'success');
        registerForm.reset();
        setTimeout(showLoginView, 2500); 
    } else {
        showMessage(registerMessage, result.message || 'Error al registrar el usuario.', 'error');
    }
}

function handleLogin(event) {
    event.preventDefault();
    hideMessage(loginMessage);
    const username = usernameInput.value.trim();
    const password = passwordInput.value;

    if (!username || !password) {
        showMessage(loginMessage, 'Ingresa usuario y contraseña.', 'error');
        return;
    }

    if (verifyUser(username, password)) {
        sessionStorage.setItem('isLoggedIn', 'true');
        sessionStorage.setItem('loggedInUser', username);
        showAppView();
        loginForm.reset();
    } else {
        showMessage(loginMessage, 'Usuario o contraseña incorrectos.', 'error');
    }
}

function handleLogout(timedOut = false) {
    sessionStorage.removeItem('isLoggedIn');
    sessionStorage.removeItem('loggedInUser');
    showLoginView();
    messageInput.value = '';
    resultTextarea.value = '';
    hideMessage(appMessage);
    if (timedOut) {
        showMessage(loginMessage, 'La sesión ha finalizado debido a inactividad o tiempo de espera excedido.', 'error');
    }
}

function checkSession() {
    if (sessionStorage.getItem('isLoggedIn') === 'true') {
        showAppView();
    } else {
        showLoginView();
    }
}

window.addEventListener('beforeunload', () => {}); // Podría usarse para limpieza si fuera necesario

// --- Lógica de Encriptación/Desencriptación RSA-OAEP con Timeout ---
function createTimeoutPromise(timeoutMs) {
    return new Promise((_, reject) => {
        setTimeout(() => {
            reject(new Error('Tiempo de espera de la operación excedido.'));
        }, timeoutMs);
    });
}

async function performOperationWithTimeout(operationFn, operationName) {
    hideMessage(appMessage);
    resultTextarea.value = '';
    toggleButtonLoading(encryptButton, true); // Deshabilitar ambos
    toggleButtonLoading(decryptButton, true);
    showMessage(appMessage, `Procesando ${operationName}...`);

    try {
        const operationPromise = operationFn(); // operationFn es ahora async

        const result = await Promise.race([
            operationPromise,
            createTimeoutPromise(OPERATION_TIMEOUT)
        ]);
        
        resultTextarea.value = result;
        showMessage(appMessage, `Mensaje ${operationName} exitosamente.`, 'info');

    } catch (error) {
        console.error(`Error en ${operationName}:`, error);
        if (error.message && error.message.includes('Tiempo de espera')) {
            showMessage(appMessage, `Error: La operación de ${operationName} tardó demasiado y fue cancelada.`, 'error');
        } else if (error.name === 'DataError' || (error.message && error.message.toLowerCase().includes("decrypt"))){
             showMessage(appMessage, `Error al ${operationName.slice(0,-5)}: Datos incorrectos o clave inválida.`, 'error');
        } else {
            showMessage(appMessage, `Error al ${operationName.slice(0,-5)} el mensaje. Detalles: ${error.message}`, 'error');
        }
    } finally {
        toggleButtonLoading(encryptButton, false);
        toggleButtonLoading(decryptButton, false);
    }
}

async function encryptMessageRSA() {
    const messageToEncrypt = messageInput.value;
    if (!messageToEncrypt.trim()) {
        showMessage(appMessage, 'Por favor, ingresa un mensaje para encriptar.', 'error');
        return;
    }
    
    await performOperationWithTimeout(async () => {
        const loggedInUser = sessionStorage.getItem('loggedInUser');
        const users = getUsers();
        const userData = users[loggedInUser];

        if (!userData || !userData.publicKeyJWK) {
            throw new Error("No se encontró la clave pública del usuario.");
        }

        const publicKey = await window.crypto.subtle.importKey(
            "jwk",
            userData.publicKeyJWK,
            { name: "RSA-OAEP", hash: "SHA-256" },
            true,
            ["encrypt"]
        );

        const encodedMessage = new TextEncoder().encode(messageToEncrypt);
        const encryptedBuffer = await window.crypto.subtle.encrypt(
            { name: "RSA-OAEP" },
            publicKey,
            encodedMessage
        );
        return arrayBufferToBase64(encryptedBuffer);
    }, 'encriptación');
}

async function decryptMessageRSA() {
    const messageToDecryptBase64 = messageInput.value;
     if (!messageToDecryptBase64.trim()) {
        showMessage(appMessage, 'Por favor, ingresa un mensaje (Base64) para desencriptar.', 'error');
        return;
    }
    
    await performOperationWithTimeout(async () => {
        const loggedInUser = sessionStorage.getItem('loggedInUser');
        const users = getUsers();
        const userData = users[loggedInUser];

        if (!userData || !userData.privateKeyJWK) {
            throw new Error("No se encontró la clave privada del usuario.");
        }
        
        const privateKey = await window.crypto.subtle.importKey(
            "jwk",
            userData.privateKeyJWK,
            { name: "RSA-OAEP", hash: "SHA-256" },
            true,
            ["decrypt"]
        );
        
        const encryptedBuffer = base64ToArrayBuffer(messageToDecryptBase64);
        const decryptedBuffer = await window.crypto.subtle.decrypt(
            { name: "RSA-OAEP" },
            privateKey,
            encryptedBuffer
        );
        return new TextDecoder().decode(decryptedBuffer);
    }, 'desencriptación');
}

// --- Inicialización y Event Listeners ---
// Asegurarse de que el DOM esté completamente cargado antes de añadir listeners
// si los elementos no están disponibles inmediatamente.
// En este caso, como el script está al final del body, no debería ser un problema.

// Verificar si los elementos existen antes de añadir listeners, como buena práctica
if (loginForm) loginForm.addEventListener('submit', handleLogin);
if (registerForm) registerForm.addEventListener('submit', handleRegister);

if (showRegisterLink) showRegisterLink.addEventListener('click', showRegisterView);
if (showLoginLink) showLoginLink.addEventListener('click', showLoginView);

if (logoutButton) logoutButton.addEventListener('click', () => handleLogout(false));
if (encryptButton) encryptButton.addEventListener('click', encryptMessageRSA);
if (decryptButton) decryptButton.addEventListener('click', decryptMessageRSA);

window.addEventListener('load', checkSession);
