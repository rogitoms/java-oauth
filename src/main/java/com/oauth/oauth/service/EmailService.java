package com.oauth.oauth.service;

import jakarta.mail.internet.MimeMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;
import jakarta.mail.MessagingException;
import org.springframework.mail.SimpleMailMessage;;

@Service
public class EmailService {

    private static final Logger logger = LoggerFactory.getLogger(EmailService.class);

    @Autowired
    private JavaMailSender emailSender;

    @Autowired
    private TemplateEngine templateEngine;

    public void sendOtpEmail(String to, String otp) {
        try {
            logger.info("📨 Preparing OTP email for {}", to);

            MimeMessage message = emailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setTo(to);
            helper.setSubject("Your OTP for Login");

            // ✅ Generate Email Content
            Context context = new Context();
            context.setVariable("otp", otp);
            String htmlContent = templateEngine.process("otp-email-template", context);
            
            helper.setText(htmlContent, true);

            // ✅ Send Email
            emailSender.send(message);
            logger.info("✅ OTP email sent successfully to {}", to);
            
        } catch (Exception e) {
            logger.error("❌ Failed to send OTP email: {}", e.getMessage(), e);
        }
    }

    public void sendPasswordResetEmail(String to, String token) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(to);
        message.setSubject("Password Reset Request");
        message.setText("To reset your password, please use the following code: " + token + 
                        "\n\nThis code will expire in 10 minutes.");
        
        emailSender.send(message);
    }


}
