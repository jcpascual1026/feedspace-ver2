<?php
// API endpoint to verify OTP for user registration or password reset
session_start();
include '../../../../config/db.php';

header('Content-Type: application/json');

if ($_SERVER["REQUEST_METHOD"] !== "POST") {
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
    exit();
}

$user_id = $_POST['user_id'] ?? '';
$otp_code = trim($_POST['otp_code'] ?? '');

if (empty($user_id) || empty($otp_code)) {
    http_response_code(400);
    echo json_encode(['error' => 'user_id and otp_code required']);
    exit();
}

// Check OTP validity
$stmt = $conn->prepare("
    SELECT expires_at
    FROM otp
    WHERE user_id = ?
    AND otp_code = ?
    AND expires_at > NOW()
    AND is_used = 0
    LIMIT 1
");
$stmt->bind_param("ss", $user_id, $otp_code);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows === 0) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid or expired OTP']);
    exit();
}

$stmt->close();

// Mark OTP as used
$stmt = $conn->prepare("UPDATE otp SET is_used = 1 WHERE user_id = ? AND otp_code = ? AND is_used = 0 LIMIT 1");
$stmt->bind_param('ss', $user_id, $otp_code);
$stmt->execute();
$stmt->close();

// Update user verification status and create login session
$stmt = $conn->prepare("SELECT user_id, first_name, last_name, email FROM users WHERE user_id = ? LIMIT 1");
$stmt->bind_param('s', $user_id);
$stmt->execute();
$userResult = $stmt->get_result();
$user = $userResult->fetch_assoc();
$stmt->close();

if ($user) {
    $_SESSION['user_id'] = $user['user_id'];
    $_SESSION['first_name'] = $user['first_name'];
    $_SESSION['last_name'] = $user['last_name'];
    $_SESSION['email'] = $user['email'];
    $_SESSION['logged_in'] = true;
}

echo json_encode([
    'success' => true,
    'message' => 'OTP verified successfully!',
    'user_id' => $user_id
]);
?>