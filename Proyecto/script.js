// Elementos del DOM
// Obtener referencias a los principales contenedores de secciones de la página.
const loginSection = document.getElementById('loginSection'); // Sección de inicio de sesión
const registerSection = document.getElementById('registerSection'); // Sección de registro
const appSection = document.getElementById('appSection'); // Sección principal de la aplicación (encriptador)

// Obtener referencias a los elementos del formulario de inicio de sesión.
const loginForm = document.getElementById('loginForm'); // Formulario de login
const usernameInput = document.getElementById('username'); // Campo de entrada para el nombre de usuario (login)
const passwordInput = document.getElementById('password'); // Campo de entrada para la contraseña (login)
const loginMessage = document.getElementById('loginMessage'); // Elemento para mostrar mensajes en la sección de login
const showRegisterLink = document.getElementById('showRegister'); // Enlace para mostrar la sección de registro

// Obtener referencias a los elementos del formulario de registro.
const registerForm = document.getElementById('registerForm'); // Formulario de registro
const newUsernameInput = document.getElementById('newUsername'); // Campo para el nuevo nombre de usuario (registro)
const newPasswordInput = document.getElementById('newPassword'); // Campo para la nueva contraseña (registro)
const confirmPasswordInput = document.getElementById('confirmPassword'); // Campo para confirmar la contraseña (registro)
const registerMessage = document.getElementById('registerMessage'); // Elemento para mostrar mensajes en la sección de registro
const showLoginLink = document.getElementById('showLogin'); // Enlace para mostrar la sección de login
const registerLoader = document.getElementById('registerLoader'); // Indicador de carga para el botón de registro

// Obtener referencias a los elementos de la sección principal de la aplicación.
const logoutButton = document.getElementById('logoutButton'); // Botón para cerrar sesión
const messageInput = document.getElementById('message'); // Textarea para el mensaje a encriptar/desencriptar
const encryptButton = document.getElementById('encryptButton'); // Botón para encriptar
const decryptButton = document.getElementById('decryptButton'); // Botón para desencriptar
const appMessage = document.getElementById('appMessage'); // Elemento para mostrar mensajes en la app
const resultTextarea = document.getElementById('result'); // Textarea para mostrar el resultado de la operación

// Constantes de configuración
const OPERATION_TIMEOUT =15000; // 30 segundos de tiempo de espera para operaciones criptográficas.
const USERS_STORAGE_KEY = 'app_rsa_users'; // Clave utilizada para guardar los datos de usuario en localStorage.

// --- Funciones Auxiliares para Criptografía ---

/**
 * Convierte un ArrayBuffer a una cadena Base64.
 * Útil para representar datos binarios (como un mensaje encriptado) en formato de texto.
 * @param {ArrayBuffer} buffer - El ArrayBuffer a convertir.
 * @returns {string} La representación en Base64 del buffer.
 */
function arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer); // Crear una vista de 8 bits del buffer
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]); // Convertir cada byte a su carácter correspondiente
    }
    return window.btoa(binary); // Usar la función btoa del navegador para la codificación Base64
}

/**
 * Convierte una cadena Base64 a un ArrayBuffer.
 * Necesario para revertir la operación de arrayBufferToBase64 antes de la desencriptación.
 * @param {string} base64 - La cadena Base64 a convertir.
 * @returns {ArrayBuffer} El ArrayBuffer resultante.
 */
function base64ToArrayBuffer(base64) {
    const binary_string = window.atob(base64); // Usar atob para decodificar la cadena Base64
    const len = binary_string.length;
    const bytes = new Uint8Array(len); // Crear un ArrayBuffer del tamaño adecuado
    for (let i = 0; i < len; i++) {
        bytes[i] = binary_string.charCodeAt(i); // Llenar el buffer con los códigos de carácter
    }
    return bytes.buffer;
}

// --- Lógica de Mensajes ---

/**
 * Muestra un mensaje al usuario en un elemento específico.
 * @param {HTMLElement} element - El elemento HTML donde se mostrará el mensaje.
 * @param {string} text - El texto del mensaje.
 * @param {string} [type='info'] - El tipo de mensaje ('info', 'error', 'success'), controla el estilo.
 */
function showMessage(element, text, type = 'info') {
    if (!element) return; // Salir si el elemento no existe
    element.textContent = text; // Establecer el contenido de texto
    // Limpiar clases previas y añadir la clase base 'message-box' y la específica del tipo
    element.classList.remove('hidden', 'message-box-info', 'message-box-error', 'message-box-success');
    if (type === 'error') {
        element.classList.add('message-box-error');
    } else if (type === 'success') {
        element.classList.add('message-box-success');
    } else {
        element.classList.add('message-box-info');
    }
}

/**
 * Oculta un elemento de mensaje y limpia su contenido.
 * @param {HTMLElement} element - El elemento HTML del mensaje a ocultar.
 */
function hideMessage(element) {
    if (!element) return; // Salir si el elemento no existe
    element.classList.add('hidden'); // Añadir clase para ocultar
    element.textContent = ''; // Limpiar el texto
}

/**
 * Activa/desactiva el estado de carga de un botón (deshabilitarlo y mostrar/ocultar un loader).
 * @param {HTMLButtonElement} button - El botón a modificar.
 * @param {boolean} isLoading - True si se debe mostrar el estado de carga, false en caso contrario.
 * @param {HTMLElement} [loaderElement=null] - El elemento loader específico, si no es hijo directo del botón.
 */
function toggleButtonLoading(button, isLoading, loaderElement = null) {
    if (!button) return; // Salir si el botón no existe
    const loader = loaderElement || button.querySelector('.loader'); // Obtener el loader
    if (isLoading) {
        button.disabled = true; // Deshabilitar el botón
        if (loader) loader.classList.remove('hidden'); // Mostrar el loader
    } else {
        button.disabled = false; // Habilitar el botón
        if (loader) loader.classList.add('hidden'); // Ocultar el loader
    }
}

// --- Lógica de Almacenamiento de Usuarios (localStorage - INSEGURO PARA PRODUCCIÓN) ---

/**
 * Obtiene el objeto de usuarios desde localStorage.
 * Los usuarios se guardan como un objeto JSON stringificado.
 * @returns {object} Un objeto donde las claves son nombres de usuario y los valores son datos del usuario.
 */
function getUsers() {
    const users = localStorage.getItem(USERS_STORAGE_KEY); // Leer de localStorage
    return users ? JSON.parse(users) : {}; // Parsear JSON o devolver objeto vacío si no hay nada
}

/**
 * Guarda un nuevo usuario en localStorage, incluyendo su contraseña (inseguro) y par de claves RSA.
 * ADVERTENCIA: Este método de almacenamiento es inseguro para producción.
 * @param {string} username - El nombre de usuario a registrar.
 * @param {string} password - La contraseña del usuario (se guarda en texto plano).
 * @returns {Promise<object>} Un objeto indicando éxito o fracaso y un mensaje.
 */
async function saveUser(username, password) {
    // Recordatorio: Guardar contraseñas en texto plano y claves privadas en localStorage es EXTREMADAMENTE INSEGURO.
    // Esto es solo para fines de demostración en una aplicación sin backend.
    const users = getUsers(); // Obtener usuarios existentes
    if (users[username]) {
        return { success: false, message: 'El usuario ya existe.' }; // Verificar si el usuario ya existe
    }

    try {
        // Generar un par de claves RSA-OAEP para el nuevo usuario.
        // Estas claves se usarán para encriptar/desencriptar mensajes.
        const keyPair = await window.crypto.subtle.generateKey(
            {
                name: "RSA-OAEP", // Algoritmo RSA con relleno OAEP
                modulusLength: 2048, // Longitud del módulo en bits (seguridad estándar)
                publicExponent: new Uint8Array([0x01, 0x00, 0x01]), // Exponente público estándar (65537)
                hash: "SHA-256", // Algoritmo hash para OAEP
            },
            true, // Indica que la clave puede ser exportada (necesario para guardarla)
            ["encrypt", "decrypt"] // Usos permitidos para las claves (encriptar con pública, desencriptar con privada)
        );

        // Exportar las claves a formato JWK (JSON Web Key) para poder almacenarlas como JSON.
        const publicKeyJWK = await window.crypto.subtle.exportKey("jwk", keyPair.publicKey);
        const privateKeyJWK = await window.crypto.subtle.exportKey("jwk", keyPair.privateKey);

        // Almacenar los datos del usuario, incluyendo la contraseña y las claves.
        users[username] = { 
            password: password, // Contraseña en texto plano (¡INSEGURO!)
            publicKeyJWK: publicKeyJWK, // Clave pública en formato JWK
            privateKeyJWK: privateKeyJWK  // Clave privada en formato JWK (¡INSEGURO ALMACENAR ASÍ!)
        };
        localStorage.setItem(USERS_STORAGE_KEY, JSON.stringify(users)); // Guardar el objeto de usuarios actualizado en localStorage
        return { success: true }; // Indicar éxito
    } catch (error) {
        console.error("Error generando claves o guardando usuario:", error);
        return { success: false, message: 'Error al generar claves criptográficas.' }; // Indicar fallo
    }
}

/**
 * Verifica si un nombre de usuario y contraseña coinciden con los almacenados.
 * @param {string} username - El nombre de usuario a verificar.
 * @param {string} password - La contraseña a verificar.
 * @returns {boolean} True si las credenciales son válidas, false en caso contrario.
 */
function verifyUser(username, password) {
    const users = getUsers(); // Obtener todos los usuarios
    const userData = users[username]; // Obtener datos del usuario específico
    // Verificar que el usuario exista y que la contraseña coincida (comparación directa, insegura).
    return userData && userData.password === password; 
}

// --- Lógica de Autenticación y Vistas (manejo de qué sección se muestra) ---

/** Muestra la vista de inicio de sesión y oculta las demás. */
function showLoginView() {
    if (loginSection) loginSection.classList.remove('hidden');
    if (registerSection) registerSection.classList.add('hidden');
    if (appSection) appSection.classList.add('hidden');
    hideMessage(loginMessage); // Ocultar mensajes previos de login
    hideMessage(registerMessage); // Ocultar mensajes previos de registro
}

/** Muestra la vista de registro y oculta las demás. */
function showRegisterView() {
    if (loginSection) loginSection.classList.add('hidden');
    if (registerSection) registerSection.classList.remove('hidden');
    if (appSection) appSection.classList.add('hidden');
    hideMessage(loginMessage);
    hideMessage(registerMessage);
}

/** Muestra la vista principal de la aplicación (encriptador) y oculta las demás. */
function showAppView() {
    if (loginSection) loginSection.classList.add('hidden');
    if (registerSection) registerSection.classList.add('hidden');
    if (appSection) appSection.classList.remove('hidden');
}

/**
 * Maneja el evento de envío del formulario de registro.
 * Valida los datos, llama a saveUser para guardar el nuevo usuario y sus claves.
 * @param {Event} event - El objeto evento del formulario.
 */
async function handleRegister(event) {
    event.preventDefault(); // Prevenir el envío tradicional del formulario
    hideMessage(registerMessage); // Ocultar mensajes previos

    // Obtener y validar los valores de los campos
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
    if (password.length < 6) { // Validación simple de longitud de contraseña
        showMessage(registerMessage, 'La contraseña debe tener al menos 6 caracteres.', 'error');
        return;
    }
    
    const registerButton = registerForm.querySelector('button[type="submit"]');
    toggleButtonLoading(registerButton, true, registerLoader); // Mostrar estado de carga

    // Intentar guardar el usuario (esto incluye la generación de claves RSA, que es asíncrona)
    const result = await saveUser(username, password); 
    
    toggleButtonLoading(registerButton, false, registerLoader); // Quitar estado de carga

    if (result.success) {
        showMessage(registerMessage, '¡Usuario registrado exitosamente! Ahora puedes iniciar sesión.', 'success');
        if (registerForm) registerForm.reset(); // Limpiar el formulario
        setTimeout(showLoginView, 2500); // Redirigir a la vista de login después de un momento
    } else {
        showMessage(registerMessage, result.message || 'Error al registrar el usuario.', 'error');
    }
}

/**
 * Maneja el evento de envío del formulario de inicio de sesión.
 * Verifica las credenciales y, si son válidas, inicia la sesión.
 * @param {Event} event - El objeto evento del formulario.
 */
function handleLogin(event) {
    event.preventDefault();
    hideMessage(loginMessage);

    const username = usernameInput.value.trim();
    const password = passwordInput.value;

    if (!username || !password) {
        showMessage(loginMessage, 'Ingresa usuario y contraseña.', 'error');
        return;
    }

    // Verificar las credenciales contra los datos almacenados
    if (verifyUser(username, password)) {
        // Si son válidas, marcar al usuario como logueado en sessionStorage.
        // sessionStorage persiste solo mientras la pestaña del navegador está abierta.
        sessionStorage.setItem('isLoggedIn', 'true'); 
        sessionStorage.setItem('loggedInUser', username); // Guardar el nombre del usuario logueado
        showAppView(); // Mostrar la aplicación principal
        if (loginForm) loginForm.reset(); // Limpiar el formulario de login
    } else {
        showMessage(loginMessage, 'Usuario o contraseña incorrectos.', 'error');
    }
}

/**
 * Maneja el cierre de sesión del usuario.
 * Limpia los datos de sesión y redirige a la vista de login.
 * @param {boolean} [timedOut=false] - Indica si el logout fue causado por un timeout.
 */
function handleLogout(timedOut = false) {
    sessionStorage.removeItem('isLoggedIn'); // Eliminar indicador de sesión
    sessionStorage.removeItem('loggedInUser'); // Eliminar nombre de usuario logueado
    showLoginView(); // Mostrar la vista de login
    // Limpiar campos de la aplicación
    if (messageInput) messageInput.value = '';
    if (resultTextarea) resultTextarea.value = '';
    hideMessage(appMessage);

    if (timedOut) { // Si fue por timeout, mostrar un mensaje específico
        showMessage(loginMessage, 'La sesión ha finalizado debido a inactividad o tiempo de espera excedido.', 'error');
    }
}

/**
 * Verifica el estado de la sesión al cargar la página.
 * Si el usuario ya está logueado (según sessionStorage), muestra la app; si no, muestra el login.
 */
function checkSession() {
    if (sessionStorage.getItem('isLoggedIn') === 'true') {
        showAppView();
    } else {
        showLoginView();
    }
}

// Event listener para acciones antes de que la página se descargue (cierre de pestaña/navegador).
// sessionStorage se limpia automáticamente, así que no se necesita acción explícita aquí para eso.
window.addEventListener('beforeunload', () => {}); 

// --- Lógica de Encriptación/Desencriptación RSA-OAEP con Timeout ---

/**
 * Crea una promesa que se rechaza después de un tiempo de espera especificado.
 * Se usa con Promise.race para implementar timeouts en operaciones asíncronas.
 * @param {number} timeoutMs - El tiempo de espera en milisegundos.
 * @returns {Promise} Una promesa que se rechaza si se alcanza el timeout.
 */
function createTimeoutPromise(timeoutMs) {
    return new Promise((_, reject) => { // El resolve no se usa, solo el reject
        setTimeout(() => {
            reject(new Error('Tiempo de espera de la operación excedido.'));
        }, timeoutMs);
    });
}

/**
 * Ejecuta una operación asíncrona (como encriptar/desencriptar) con un mecanismo de timeout.
 * @param {Function} operationFn - La función (posiblemente asíncrona) que realiza la operación.
 * @param {string} operationName - Un nombre descriptivo de la operación para los mensajes.
 */
async function performOperationWithTimeout(operationFn, operationName) {
    hideMessage(appMessage); // Ocultar mensajes previos de la app
    if (resultTextarea) resultTextarea.value = ''; // Limpiar resultado previo

    // Deshabilitar ambos botones de operación y mostrar loaders
    toggleButtonLoading(encryptButton, true); 
    toggleButtonLoading(decryptButton, true);
    showMessage(appMessage, `Procesando ${operationName}...`); // Mensaje de "procesando"

    try {
        // operationFn() devuelve una promesa porque las operaciones criptográficas son asíncronas.
        const operationPromise = operationFn(); 

        // Promise.race() espera a que la primera promesa (operación o timeout) se resuelva o rechace.
        const result = await Promise.race([
            operationPromise,
            createTimeoutPromise(OPERATION_TIMEOUT)
        ]);
        
        if (resultTextarea) resultTextarea.value = result; // Mostrar el resultado
        showMessage(appMessage, `Mensaje ${operationName} exitosamente.`, 'info'); // Mensaje de éxito

    } catch (error) {
        console.error(`Error en ${operationName}:`, error); // Loguear el error en consola
        // Manejar diferentes tipos de errores
        if (error.message && error.message.includes('Tiempo de espera')) {
            showMessage(appMessage, `Error: La operación de ${operationName} tardó demasiado y fue cancelada.`, 'error');
        } else if (error.name === 'DataError' || (error.message && error.message.toLowerCase().includes("decrypt"))){
            // Errores comunes al desencriptar: datos corruptos, clave incorrecta, texto no es Base64 válido.
             showMessage(appMessage, `Error al ${operationName.slice(0,-5)}: Datos incorrectos o clave inválida.`, 'error');
        } else {
            showMessage(appMessage, `Error al ${operationName.slice(0,-5)} el mensaje. Detalles: ${error.message}`, 'error');
        }
    } finally {
        // Siempre rehabilitar los botones y ocultar loaders, independientemente del resultado.
        toggleButtonLoading(encryptButton, false);
        toggleButtonLoading(decryptButton, false);
    }
}

/**
 * Encripta el mensaje del textarea usando la clave pública RSA-OAEP del usuario logueado.
 */
async function encryptMessageRSA() {
    const messageToEncrypt = messageInput.value;
    if (!messageToEncrypt.trim()) { // Validar que haya un mensaje
        showMessage(appMessage, 'Por favor, ingresa un mensaje para encriptar.', 'error');
        return;
    }
    
    // Ejecutar la encriptación con timeout
    await performOperationWithTimeout(async () => {
        const loggedInUser = sessionStorage.getItem('loggedInUser'); // Obtener usuario actual
        const users = getUsers();
        const userData = users[loggedInUser];

        if (!userData || !userData.publicKeyJWK) { // Verificar que tengamos la clave pública
            throw new Error("No se encontró la clave pública del usuario.");
        }

        // Importar la clave pública JWK para poder usarla con SubtleCrypto.
        const publicKey = await window.crypto.subtle.importKey(
            "jwk", // Formato de la clave
            userData.publicKeyJWK, // La clave pública en formato JWK
            { name: "RSA-OAEP", hash: "SHA-256" }, // Algoritmo y hash
            true, // Si la clave es exportable (no relevante aquí, pero requerido por la API a veces)
            ["encrypt"] // Uso permitido para esta clave importada
        );

        // Convertir el mensaje de texto a un ArrayBuffer (UTF-8).
        const encodedMessage = new TextEncoder().encode(messageToEncrypt);
        
        // Encriptar el mensaje.
        const encryptedBuffer = await window.crypto.subtle.encrypt(
            { name: "RSA-OAEP" }, // Algoritmo (debe coincidir con la clave)
            publicKey, // La clave pública importada
            encodedMessage // El mensaje codificado como ArrayBuffer
        );
        // Convertir el resultado encriptado (ArrayBuffer) a Base64 para mostrarlo.
        return arrayBufferToBase64(encryptedBuffer);
    }, 'encriptación'); // Nombre de la operación para mensajes
}

/**
 * Desencripta el mensaje (esperado en Base64) del textarea usando la clave privada RSA-OAEP del usuario.
 */
async function decryptMessageRSA() {
    const messageToDecryptBase64 = messageInput.value;
     if (!messageToDecryptBase64.trim()) { // Validar que haya un mensaje
        showMessage(appMessage, 'Por favor, ingresa un mensaje (Base64) para desencriptar.', 'error');
        return;
    }
    
    // Ejecutar la desencriptación con timeout
    await performOperationWithTimeout(async () => {
        const loggedInUser = sessionStorage.getItem('loggedInUser');
        const users = getUsers();
        const userData = users[loggedInUser];

        if (!userData || !userData.privateKeyJWK) { // Verificar que tengamos la clave privada
            throw new Error("No se encontró la clave privada del usuario.");
        }
        
        // Importar la clave privada JWK.
        const privateKey = await window.crypto.subtle.importKey(
            "jwk",
            userData.privateKeyJWK,
            { name: "RSA-OAEP", hash: "SHA-256" },
            true,
            ["decrypt"] // Uso permitido: desencriptar
        );
        
        // Convertir el mensaje Base64 de nuevo a un ArrayBuffer.
        const encryptedBuffer = base64ToArrayBuffer(messageToDecryptBase64);
        
        // Desencriptar el mensaje.
        const decryptedBuffer = await window.crypto.subtle.decrypt(
            { name: "RSA-OAEP" },
            privateKey, // La clave privada importada
            encryptedBuffer // El buffer encriptado
        );
        // Convertir el ArrayBuffer desencriptado de nuevo a una cadena de texto (UTF-8).
        return new TextDecoder().decode(decryptedBuffer);
    }, 'desencriptación'); // Nombre de la operación para mensajes
}

// --- Inicialización y Event Listeners ---
// Es buena práctica asegurarse de que el DOM esté completamente cargado antes de añadir listeners,
// especialmente si el script se carga en el <head>. En este caso, como el script está
// al final del <body>, los elementos ya deberían estar disponibles.
// No obstante, se añaden verificaciones de existencia de elementos antes de atachar listeners.

if (loginForm) loginForm.addEventListener('submit', handleLogin);
if (registerForm) registerForm.addEventListener('submit', handleRegister);

if (showRegisterLink) showRegisterLink.addEventListener('click', showRegisterView);
if (showLoginLink) showLoginLink.addEventListener('click', showLoginView);

if (logoutButton) logoutButton.addEventListener('click', () => handleLogout(false)); // Logout manual no es por timeout
if (encryptButton) encryptButton.addEventListener('click', encryptMessageRSA);
if (decryptButton) decryptButton.addEventListener('click', decryptMessageRSA);

// Al cargar la ventana, verificar si hay una sesión activa.
window.addEventListener('load', checkSession);
