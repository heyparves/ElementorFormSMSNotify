Based on the provided code, here is a comprehensive `README.md` file designed for your plugin.

***

# Elementor Twilio SMS Notifier

**Elementor Twilio SMS Notifier** is a robust WordPress plugin designed to bridge the gap between your Elementor Pro forms and Twilio's SMS gateway. It allows site administrators to receive real-time SMS notifications whenever a form is submitted and provides a secure REST API endpoint for external SMS triggers.

## 🚀 Features

* **Elementor Pro Integration:** Automatically detects Elementor Pro forms and allows per-form SMS configuration.
* **Secure Credential Storage:** Sensitive data like Twilio Auth Tokens and Webhook Secrets are **AES-256-CBC encrypted** using WordPress secret keys before being stored in the database.
* **Dynamic SMS Templates:** Use field tokens (e.g., `{field:email}`) and global tokens (e.g., `{form_name}`, `{date}`) to customize your notification messages.
* **REST API Webhook:** Includes a protected POST endpoint to send SMS messages from external applications.
* **Admin Dashboard:** * Connection tester to verify Twilio API status.
    * Test SMS tool to verify delivery.
    * User-friendly interface with toggle switches and token "chips" for easy template building.
* **Developer Friendly:** Built with clean PHP, AJAX-driven settings, and industry-standard security practices.

## 📋 Requirements

* **PHP:** 7.4 or higher.
* **WordPress:** 5.0 or higher.
* **Elementor Pro:** Required for the form submission features.
* **Twilio Account:** An active Account SID, Auth Token, and a Twilio phone number.

## 🛠️ Installation

1.  Download the plugin folder.
2.  Upload the `elementor-twilio-sms-notifier` folder to your `/wp-content/plugins/` directory.
3.  Activate the plugin through the 'Plugins' menu in WordPress.
4.  Navigate to the **Twilio SMS** menu in your WordPress admin sidebar.

## ⚙️ Configuration

### 1. API Settings
Go to **Twilio SMS > API Settings** to enter your:
* **Account SID:** Found in your Twilio Console.
* **Auth Token:** Found in your Twilio Console.
* **From Number:** Your Twilio-purchased phone number (E.164 format, e.g., `+15551234567`).
* **Webhook Secret:** Create a strong key to protect your REST API endpoint.

### 2. Elementor Forms
Navigate to the **Elementor Forms** tab. The plugin automatically scans your published pages for Elementor Form widgets.
* **Enable/Disable:** Toggle SMS notifications for specific forms.
* **Recipient:** Set the phone number that should receive the notification.
* **Template:** Customize the message. Click the blue field chips to insert dynamic data from your form into the message.

### 3. Webhook Usage
If you wish to trigger SMS from outside of WordPress, use the **Webhook** tab to find your unique endpoint and authentication headers.

**Example Request:**
```bash
curl -X POST "https://yourdomain.com/wp-json/etsn/v1/send-sms" \
  -H "Content-Type: application/json" \
  -H "X-ETSN-Secret: YOUR_CONFIGURED_SECRET" \
  -d '{"to": "+15557654321", "message": "Hello from the API!"}'
```

## 📝 Available Tokens

| Token | Description |
| :--- | :--- |
| `{field:ID}` | Data from a specific form field (replace ID with the field ID). |
| `{form_name}` | The name of the Elementor form. |
| `{site_name}` | Your WordPress site title. |
| `{date}` | The timestamp of the submission. |
| `{page_url}` | The URL where the form was submitted. |

## 🔒 Security Note
This plugin prioritizes security. Raw credentials never sit in plaintext within your database. By utilizing `SECURE_AUTH_KEY` and `SECURE_AUTH_SALT` from your `wp-config.php`, the plugin ensures that even if your database is exported, your Twilio credentials remain encrypted.

## 👤 Author
**Parves**
* **Version:** 1.0.0
* **License:** GPL2
