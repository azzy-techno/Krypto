<?php
/**
 * Krypto Tech Services — Contact Form Handler
 * Processes contact form submissions and sends email notification.
 */

if ($_SERVER["REQUEST_METHOD"] !== "POST") {
    http_response_code(405);
    exit("Invalid request method.");
}

// Sanitize inputs
$name          = htmlspecialchars(trim($_POST['name'] ?? ''));
$company_name  = htmlspecialchars(trim($_POST['company_name'] ?? ''));
$visitor_email = filter_var($_POST['email'] ?? '', FILTER_SANITIZE_EMAIL);
$visitor_phone = htmlspecialchars(trim($_POST['number'] ?? ''));
$message       = htmlspecialchars(trim($_POST['message'] ?? ''));

// Validate required fields
if (empty($name) || empty($visitor_email) || empty($message)) {
    http_response_code(400);
    exit("Please fill in all required fields.");
}

if (!filter_var($visitor_email, FILTER_VALIDATE_EMAIL)) {
    http_response_code(400);
    exit("Please provide a valid email address.");
}

// Email setup
$to           = "smahmed30@gmail.com";
$email_from   = "info@kryptotechservices.com";
$email_subject = "New Contact Form Submission — Krypto Tech Services";
$email_body   = "You have received a new message from the Krypto website contact form.\n\n"
              . "-------------------------------\n"
              . "Name:    $name\n"
              . "Company: $company_name\n"
              . "Email:   $visitor_email\n"
              . "Phone:   $visitor_phone\n"
              . "-------------------------------\n\n"
              . "Message:\n$message\n";

$headers  = "From: $email_from\r\n";
$headers .= "Reply-To: $visitor_email\r\n";
$headers .= "X-Mailer: PHP/" . phpversion() . "\r\n";

// Send and redirect
if (mail($to, $email_subject, $email_body, $headers)) {
    header("Location: contact.html?sent=1");
    exit();
} else {
    http_response_code(500);
    exit("Email sending failed. Please try again or contact us directly.");
}
