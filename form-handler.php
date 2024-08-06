<?php
$name = $_POST['name'];
$company_name = $_POST['company_name'];
$visitor_email = $_POST['email'];
$visitor_phone = $_POST['number'];
$message = $_POST['message'];

$email_from = 'info@kryptotechservices.com';

$email_subject = 'New Form Submission';

$email_body = "User Name: $name.\n".
              "User Company_Name: $company_name.\n".
              "User Email: $visitor_email.\n".
              "User Number: $visitor_phone.\n".
              "User Message: $message.\n";

$to = "smahmed30@gmail.com";

$headers = "From: $email_from \r\n";

$headers .= "Reply-To: $visitor_email \r\n";

mail($to, $email_subject, $email_body, $headers);

header("Location: contact.html");
?>