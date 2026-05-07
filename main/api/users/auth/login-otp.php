<?php
// API endpoint to send OTP for login using email
session_start();
include '../../../../config/db.php';

header('Content-Type: application/json; charset=utf-8');

if ($_SERVER["REQUEST_METHOD"] !== "POST") {
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
    exit();
}

$email = trim($_POST['email'] ?? '');
$user_id_input = trim($_POST['user_id'] ?? '');

if (!empty($user_id_input)) {
    // Resend case: get email from user_id
    $stmt = $conn->prepare("SELECT email, first_name FROM users WHERE user_id = ? LIMIT 1");
    $stmt->bind_param('s', $user_id_input);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($result->num_rows === 0) {
        http_response_code(404);
        echo json_encode(['error' => 'User not found']);
        exit();
    }
    $user = $result->fetch_assoc();
    $email = $user['email'];
    $first_name = $user['first_name'];
    $user_id = $user_id_input;
} else {
    // Initial send case
    if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        http_response_code(400);
        echo json_encode(['error' => 'Valid email required']);
        exit();
    }

    // Check user exists
    $stmt = $conn->prepare("SELECT user_id, first_name FROM users WHERE email = ? LIMIT 1");
    $stmt->bind_param('s', $email);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows === 0) {
        http_response_code(404);
        echo json_encode(['error' => 'Email not found']);
        exit();
    }

    $user = $result->fetch_assoc();
    $user_id = $user['user_id'];
    $first_name = $user['first_name'];
}

// Generate OTP
$otp = sprintf("%06d", rand(100000, 999999));

// Delete old OTPs for this user
$conn->query("DELETE FROM otp WHERE user_id = " . $conn->real_escape_string($user_id));

// Insert new OTP using database time to avoid timezone mismatch
$stmt = $conn->prepare("INSERT INTO otp (user_id, otp_code, expires_at, created_at) VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 10 MINUTE), NOW())");
$stmt->bind_param("ss", $user_id, $otp);

if (!$stmt->execute()) {
    http_response_code(500);
    echo json_encode(['error' => 'Failed to generate OTP']);
    exit();
}

$mailSent = sendEmailOTP($email, $first_name, $otp);

$response = [
    'success' => true,
    'message' => $mailSent ? 'OTP sent successfully!' : 'OTP generated, but email delivery failed. Please check your email settings.',
    'user_id' => $user_id,
    'expires_in' => '10 minutes',
    'mail_sent' => $mailSent
];

if (!$mailSent) {
    $response['otp_code'] = $otp;
}

echo json_encode($response);

function sendEmailOTP($email, $first_name, $otp) {
    $subject = "Your Verification Code";
    $message = "Hello $first_name!\n\n";
    $message .= "Your verification code is: $otp\n\n";
    $message .= "This code expires in 10 minutes.\n";
    $message .= "If you didn't request this, ignore this email.\n";

    $headers = "From: noreply@yourapp.com\r\n";
    $headers .= "Reply-To: support@yourapp.com\r\n";
    $headers .= "Content-Type: text/plain; charset=UTF-8\r\n";

    return @mail($email, $subject, $message, $headers);
}
?>
