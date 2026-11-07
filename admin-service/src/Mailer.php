<?php

declare(strict_types=1);

namespace Logbanner\Admin;

use PHPMailer\PHPMailer\Exception as MailerException;
use PHPMailer\PHPMailer\PHPMailer;

// Sends alert mail through the SMTP server configured in the
// environment. With no SMTP_HOST configured nothing is sent and the
// caller gets sent=false with a reason, so no code path can claim
// an email went out when it did not. Credentials are never
// hard-coded; they come from SMTP_USER / SMTP_PASS only.
final class Mailer
{
    public static function configured(): bool
    {
        return getenv('SMTP_HOST') !== false && getenv('SMTP_HOST') !== ''
            && getenv('ALERT_TO') !== false && getenv('ALERT_TO') !== '';
    }

    // Returns ['sent' => bool, 'reason' => string]. A failed send
    // is logged and reported, never thrown, so one bad alert cannot
    // take down the whole alert check.
    public static function send(string $subject, string $body): array
    {
        if (!self::configured()) {
            $reason = 'SMTP is not configured (set SMTP_HOST and ALERT_TO)';
            error_log('logbanner alerts: ' . $reason . '; alert not sent: ' . $subject);
            return ['sent' => false, 'reason' => $reason];
        }
        $from = getenv('SMTP_FROM');
        if ($from === false || $from === '') {
            // Placeholder default, and it must be a dotted domain:
            // PHPMailer's address validator rejects a single-label
            // domain such as logbanner@localhost, so that value
            // fails every send. Set a real mailbox in production.
            $from = 'logbanner@example.local';
        }

        $mail = new PHPMailer(true);
        try {
            $mail->isSMTP();
            $mail->Host = (string) getenv('SMTP_HOST');
            $mail->Port = (int) (getenv('SMTP_PORT') ?: 25);
            $user = getenv('SMTP_USER');
            if ($user !== false && $user !== '') {
                $mail->SMTPAuth = true;
                $mail->Username = $user;
                $mail->Password = (string) getenv('SMTP_PASS');
            }
            $secure = getenv('SMTP_SECURE');
            if ($secure === 'tls') {
                $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
            } elseif ($secure === 'ssl') {
                $mail->SMTPSecure = PHPMailer::ENCRYPTION_SMTPS;
            }
            $mail->setFrom($from, 'logbanner');
            $mail->addAddress((string) getenv('ALERT_TO'));
            $mail->Subject = $subject;
            $mail->Body = $body;
            $mail->send();
            return ['sent' => true, 'reason' => 'sent'];
        } catch (MailerException $e) {
            error_log('logbanner alerts: failed to send mail: ' . $e->getMessage());
            return ['sent' => false, 'reason' => 'SMTP send failed: ' . $e->getMessage()];
        }
    }
}
