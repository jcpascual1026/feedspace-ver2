<?php
//login user
// This file processes the login form submission. It checks the provided user_id and password against the database, and if valid, it sets session variables to keep the user logged in.
session_start();
include '../../../../config/db.php';
header('Content-Type: application/json; charset=utf-8');

if ($_SERVER["REQUEST_METHOD"] !== "POST") {
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
    exit();
}

$identifier = trim($_POST['identifier'] ?? $_POST['user_id'] ?? '');
$password = $_POST['password'] ?? '';

if (empty($identifier) || empty($password)) {
    http_response_code(400);
    echo json_encode(['error' => 'Email/School ID and password required']);
    exit();
}

// Search by user_id or email
$stmt = $conn->prepare("SELECT * FROM users WHERE user_id = ? OR email = ? LIMIT 1");
$stmt->bind_param("ss", $identifier, $identifier);
$stmt->execute();
// Get result and fetch user data
$result = $stmt->get_result();
$user = $result->fetch_assoc();
// If user not found, return error
if (!$user) {
    http_response_code(404);
    echo json_encode(['error' => 'Account does not exist. Please sign up or check your email/School ID.']);
    exit();
}
// Verify password
$storedPassword = $user['password_hash'];
$loginSuccess = false;

if (password_verify($password, $storedPassword)) {
    $loginSuccess = true;
    // Rehash if needed
    if (password_needs_rehash($storedPassword, PASSWORD_DEFAULT)) {
        $newHash = password_hash($password, PASSWORD_DEFAULT);
        $updateStmt = $conn->prepare("UPDATE users SET password_hash = ? WHERE user_id = ?");
        $updateStmt->bind_param("ss", $newHash, $user['user_id']);
        $updateStmt->execute();
    }
} elseif ($password === $storedPassword) {
    // Legacy plaintext password support: migrate to secure hash
    $loginSuccess = true;
    $newHash = password_hash($password, PASSWORD_DEFAULT);
    $updateStmt = $conn->prepare("UPDATE users SET password_hash = ? WHERE user_id = ?");
    $updateStmt->bind_param("ss", $newHash, $user['user_id']);
    $updateStmt->execute();
}

if ($loginSuccess) {
    $_SESSION['user_id'] = $user['user_id'];
    $_SESSION['first_name'] = $user['first_name'];
    $_SESSION['last_name'] = $user['last_name'];

    echo json_encode(['success' => true, 'message' => 'Login successful!']);
} else {
    http_response_code(401);
    echo json_encode(['error' => 'Password incorrect']);
}
?>