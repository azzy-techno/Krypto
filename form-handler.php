<?php
// Check if the form is submitted via POST
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Sanitize and validate the input data
    $name = htmlspecialchars(trim($_POST['name']));
    $company_name = htmlspecialchars(trim($_POST['company_name']));
    $visitor_email = filter_var($_POST['email'], FILTER_SANITIZE_EMAIL);
    $visitor_phone = htmlspecialchars(trim($_POST['number']));
    $message = htmlspecialchars(trim($_POST['message']));

    // Ensure that all required fields are filled out
    if (!empty($name) && !empty($visitor_email) && !empty($message)) {
        // Set up the email details
        $email_from = 'info@kryptotechservices.com';
        $email_subject = 'New Form Submission';
        $email_body = "User Name: $name.\n".
                      "User Company Name: $company_name.\n".
                      "User Email: $visitor_email.\n".
                      "User Number: $visitor_phone.\n".
                      "User Message: $message.\n";
        $to = "smahmed30@gmail.com";
        $headers = "From: $email_from \r\n";
        $headers .= "Reply-To: $visitor_email \r\n";

        // Attempt to send the email
        if (mail($to, $email_subject, $email_body, $headers)) {
            header("Location: contact.html");
            exit(); // Stop further execution after redirection
        } else {
            echo "Email sending failed.";
        }
    } else {
        echo "Please fill in all required fields.";
    }
} else {
    echo "Invalid request method.";
}
?>
