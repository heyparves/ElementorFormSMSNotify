<?php
/**
 * Plugin Name:  Elementor Twilio SMS Notifier
 * Description:  Send Twilio SMS on Elementor Pro form submission and via REST webhook. Includes per-form field mapping, connection test, and test SMS.
 * Version:      2.1.0
 * Author:       Parves
 * License:      GPL2
 * Requires PHP: 7.4
 */

if ( ! defined( 'ABSPATH' ) ) exit;

// ============================================================
// CONSTANTS
// ============================================================
define( 'ETSN_VERSION',       '2.1.0' );
define( 'ETSN_OPTION_SID',    'etsn_account_sid' );
define( 'ETSN_OPTION_TOKEN',  'etsn_auth_token' );
define( 'ETSN_OPTION_FROM',   'etsn_from_number' );
define( 'ETSN_OPTION_SECRET', 'etsn_webhook_secret' );
define( 'ETSN_OPTION_FORMS',  'etsn_form_configs' );
define( 'ETSN_SLUG',          'twilio-sms-notifier' );


// ============================================================
// SECTION 1 — SECURE CREDENTIAL HELPERS
// AES-256-CBC encrypted using WP secret keys as key material.
// Raw credentials never sit plaintext in the database.
// ============================================================

function etsn_encrypt( string $value ): string {
    if ( empty( $value ) ) return '';
    if ( ! function_exists( 'openssl_encrypt' ) ) {
        return base64_encode( $value );
    }
    $key    = substr( hash( 'sha256', SECURE_AUTH_KEY . SECURE_AUTH_SALT ), 0, 32 );
    $iv_len = openssl_cipher_iv_length( 'aes-256-cbc' );
    $iv     = openssl_random_pseudo_bytes( $iv_len );
    $enc    = openssl_encrypt( $value, 'aes-256-cbc', $key, 0, $iv );
    return base64_encode( $iv . '::' . $enc );
}

function etsn_decrypt( string $stored ): string {
    if ( empty( $stored ) ) return '';
    if ( ! function_exists( 'openssl_decrypt' ) ) {
        return (string) base64_decode( $stored );
    }
    $raw = (string) base64_decode( $stored );
    if ( strpos( $raw, '::' ) === false ) {
        return $raw; // legacy plain value
    }
    $parts = explode( '::', $raw, 2 );
    $iv    = $parts[0];
    $enc   = $parts[1];
    $key   = substr( hash( 'sha256', SECURE_AUTH_KEY . SECURE_AUTH_SALT ), 0, 32 );
    $dec   = openssl_decrypt( $enc, 'aes-256-cbc', $key, 0, $iv );
    return $dec !== false ? $dec : '';
}

function etsn_set_credential( string $option, string $value ): void {
    update_option( $option, etsn_encrypt( $value ), false );
}

function etsn_get_credential( string $option ): string {
    $raw = get_option( $option, '' );
    return $raw ? etsn_decrypt( (string) $raw ) : '';
}

function etsn_mask( string $value ): string {
    $len = mb_strlen( $value );
    if ( $len === 0 ) return '';
    if ( $len <= 8  ) return str_repeat( '*', $len );
    return mb_substr( $value, 0, 4 ) . str_repeat( '*', $len - 8 ) . mb_substr( $value, -4 );
}


// ============================================================
// SECTION 2 — CORE: SEND SMS VIA TWILIO
// ============================================================

function etsn_send_sms( string $to, string $message ) {
    $sid   = etsn_get_credential( ETSN_OPTION_SID );
    $token = etsn_get_credential( ETSN_OPTION_TOKEN );
    $from  = get_option( ETSN_OPTION_FROM, '' );

    if ( ! $sid || ! $token || ! $from ) {
        return new WP_Error( 'missing_config', 'Twilio credentials are not fully configured.' );
    }

    $response = wp_remote_post(
        'https://api.twilio.com/2010-04-01/Accounts/' . $sid . '/Messages.json',
        array(
            'headers'   => array(
                'Authorization' => 'Basic ' . base64_encode( $sid . ':' . $token ),
                'Content-Type'  => 'application/x-www-form-urlencoded',
            ),
            'body'      => http_build_query( array( 'To' => $to, 'From' => $from, 'Body' => $message ) ),
            'timeout'   => 20,
            'sslverify' => true,
        )
    );

    if ( is_wp_error( $response ) ) {
        return $response;
    }

    $code = (int) wp_remote_retrieve_response_code( $response );
    $body = json_decode( wp_remote_retrieve_body( $response ), true );

    if ( $code !== 201 ) {
        $msg = isset( $body['message'] ) ? $body['message'] : ( isset( $body['error_message'] ) ? $body['error_message'] : 'Unexpected HTTP ' . $code . ' from Twilio.' );
        return new WP_Error( 'twilio_api_error', $msg );
    }

    return $body;
}

function etsn_test_connection(): array {
    $sid   = etsn_get_credential( ETSN_OPTION_SID );
    $token = etsn_get_credential( ETSN_OPTION_TOKEN );

    if ( ! $sid || ! $token ) {
        return array( 'success' => false, 'message' => 'Account SID and Auth Token must be saved first.' );
    }

    $response = wp_remote_get(
        'https://api.twilio.com/2010-04-01/Accounts/' . $sid . '.json',
        array(
            'headers'   => array( 'Authorization' => 'Basic ' . base64_encode( $sid . ':' . $token ) ),
            'timeout'   => 15,
            'sslverify' => true,
        )
    );

    if ( is_wp_error( $response ) ) {
        return array( 'success' => false, 'message' => 'Network error: ' . $response->get_error_message() );
    }

    $code = (int) wp_remote_retrieve_response_code( $response );
    $body = json_decode( wp_remote_retrieve_body( $response ), true );

    if ( $code === 200 ) {
        $friendly = isset( $body['friendly_name'] ) ? $body['friendly_name'] : $sid;
        $status   = ucfirst( isset( $body['status'] ) ? $body['status'] : 'active' );
        return array( 'success' => true, 'message' => 'Connected. Account: <strong>' . esc_html( $friendly ) . '</strong> &mdash; Status: ' . esc_html( $status ) );
    }

    $err = isset( $body['message'] ) ? $body['message'] : 'HTTP ' . $code;
    return array( 'success' => false, 'message' => 'Authentication failed: ' . esc_html( $err ) );
}


// ============================================================
// SECTION 3 — AJAX HANDLERS
// Each handler: verifies nonce + manage_options capability.
// ============================================================

add_action( 'wp_ajax_etsn_test_connection', 'etsn_ajax_test_connection' );
function etsn_ajax_test_connection() {
    check_ajax_referer( 'etsn_ajax_nonce', 'nonce' );
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_send_json_error( array( 'message' => 'Permission denied.' ), 403 );
    }
    wp_send_json( etsn_test_connection() );
}

add_action( 'wp_ajax_etsn_test_sms', 'etsn_ajax_test_sms' );
function etsn_ajax_test_sms() {
    check_ajax_referer( 'etsn_ajax_nonce', 'nonce' );
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_send_json_error( array( 'message' => 'Permission denied.' ), 403 );
    }

    $to      = sanitize_text_field( wp_unslash( isset( $_POST['to'] ) ? $_POST['to'] : '' ) );
    $message = sanitize_textarea_field( wp_unslash( isset( $_POST['message'] ) ? $_POST['message'] : '' ) );

    if ( ! $to ) {
        wp_send_json( array( 'success' => false, 'message' => 'Please enter a recipient phone number.' ) );
    }

    if ( ! $message ) {
        $message = 'Test SMS from ' . get_bloginfo( 'name' ) . '. Twilio SMS Notifier v' . ETSN_VERSION . ' is working.';
    }

    $result = etsn_send_sms( $to, $message );

    if ( is_wp_error( $result ) ) {
        wp_send_json( array( 'success' => false, 'message' => $result->get_error_message() ) );
    }

    $sid_val = isset( $result['sid'] ) ? $result['sid'] : 'n/a';
    wp_send_json( array( 'success' => true, 'message' => 'SMS sent successfully. Message SID: ' . esc_html( $sid_val ) ) );
}

add_action( 'wp_ajax_etsn_save_credentials', 'etsn_ajax_save_credentials' );
function etsn_ajax_save_credentials() {
    check_ajax_referer( 'etsn_ajax_nonce', 'nonce' );
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_send_json_error( array( 'message' => 'Permission denied.' ), 403 );
    }

    $sid    = sanitize_text_field( wp_unslash( isset( $_POST['sid'] )    ? $_POST['sid']    : '' ) );
    $token  = sanitize_text_field( wp_unslash( isset( $_POST['token'] )  ? $_POST['token']  : '' ) );
    $from   = sanitize_text_field( wp_unslash( isset( $_POST['from'] )   ? $_POST['from']   : '' ) );
    $secret = sanitize_text_field( wp_unslash( isset( $_POST['secret'] ) ? $_POST['secret'] : '' ) );

    $saved = array();
    if ( $sid )    { etsn_set_credential( ETSN_OPTION_SID,    $sid );    $saved[] = 'Account SID'; }
    if ( $token )  { etsn_set_credential( ETSN_OPTION_TOKEN,  $token );  $saved[] = 'Auth Token'; }
    if ( $from )   { update_option( ETSN_OPTION_FROM, $from, false );    $saved[] = 'From Number'; }
    if ( $secret ) { etsn_set_credential( ETSN_OPTION_SECRET, $secret ); $saved[] = 'Webhook Secret'; }

    if ( empty( $saved ) ) {
        wp_send_json( array( 'success' => false, 'message' => 'No new values were provided.' ) );
    }

    wp_send_json( array( 'success' => true, 'message' => 'Saved: ' . implode( ', ', $saved ) . '. All credentials are AES-256 encrypted in the database.' ) );
}

add_action( 'wp_ajax_etsn_save_form_config', 'etsn_ajax_save_form_config' );
function etsn_ajax_save_form_config() {
    check_ajax_referer( 'etsn_ajax_nonce', 'nonce' );
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_send_json_error( array( 'message' => 'Permission denied.' ), 403 );
    }

    $form_id  = sanitize_key( wp_unslash( isset( $_POST['form_id'] )  ? $_POST['form_id']  : '' ) );
    $enabled  = ! empty( $_POST['enabled'] ) && $_POST['enabled'] === '1';
    $to       = sanitize_text_field( wp_unslash( isset( $_POST['to'] )       ? $_POST['to']       : '' ) );
    $template = sanitize_textarea_field( wp_unslash( isset( $_POST['template'] ) ? $_POST['template'] : '' ) );

    if ( ! $form_id ) {
        wp_send_json( array( 'success' => false, 'message' => 'Invalid form ID.' ) );
    }

    $configs             = get_option( ETSN_OPTION_FORMS, array() );
    $configs[ $form_id ] = array(
        'enabled'  => $enabled,
        'to'       => $to,
        'template' => $template,
    );
    update_option( ETSN_OPTION_FORMS, $configs );

    wp_send_json( array( 'success' => true, 'message' => 'Form configuration saved.' ) );
}


// ============================================================
// SECTION 4 — ADMIN MENU + ASSET REGISTRATION
// ============================================================

add_action( 'admin_menu', 'etsn_admin_menu' );
function etsn_admin_menu() {
    add_menu_page(
        'Twilio SMS Notifier',
        'Twilio SMS',
        'manage_options',
        ETSN_SLUG,
        'etsn_page_settings',
        'dashicons-phone',
        58
    );
    add_submenu_page( ETSN_SLUG, 'API Settings',    'API Settings',    'manage_options', ETSN_SLUG,              'etsn_page_settings' );
    add_submenu_page( ETSN_SLUG, 'Elementor Forms', 'Elementor Forms', 'manage_options', ETSN_SLUG . '-forms',   'etsn_page_forms' );
    add_submenu_page( ETSN_SLUG, 'Webhook',         'Webhook',         'manage_options', ETSN_SLUG . '-webhook', 'etsn_page_webhook' );
}

add_action( 'admin_enqueue_scripts', 'etsn_enqueue_assets' );
function etsn_enqueue_assets( $hook ) {
    // Only load on our plugin pages
    $our_hooks = array(
        'toplevel_page_' . ETSN_SLUG,
        'twilio-sms_page_' . ETSN_SLUG,
        'twilio-sms_page_' . ETSN_SLUG . '-forms',
        'twilio-sms_page_' . ETSN_SLUG . '-webhook',
    );
    if ( ! in_array( $hook, $our_hooks, true ) ) {
        return;
    }

    // Register a dummy handle so we can attach inline CSS/JS to it
    wp_register_style( 'etsn-admin', false, array(), ETSN_VERSION );
    wp_enqueue_style( 'etsn-admin' );
    wp_add_inline_style( 'etsn-admin', etsn_admin_css() );

    // Depend on jQuery which WP always has in admin
    wp_register_script( 'etsn-admin', false, array( 'jquery' ), ETSN_VERSION, true );
    wp_enqueue_script( 'etsn-admin' );
    wp_add_inline_script( 'etsn-admin', etsn_admin_js() );

    // Pass PHP data to JS
    wp_localize_script( 'etsn-admin', 'ETSN', array(
        'nonce'   => wp_create_nonce( 'etsn_ajax_nonce' ),
        'ajaxurl' => admin_url( 'admin-ajax.php' ),
    ) );
}


// ============================================================
// SECTION 5 — PAGE: API SETTINGS
// ============================================================

function etsn_page_settings() {
    $sid_masked    = etsn_mask( etsn_get_credential( ETSN_OPTION_SID ) );
    $token_masked  = etsn_mask( etsn_get_credential( ETSN_OPTION_TOKEN ) );
    $from          = esc_attr( get_option( ETSN_OPTION_FROM, '' ) );
    $secret_masked = etsn_mask( etsn_get_credential( ETSN_OPTION_SECRET ) );
    $has_creds     = etsn_get_credential( ETSN_OPTION_SID ) && etsn_get_credential( ETSN_OPTION_TOKEN );
    ?>
    <div class="wrap etsn-wrap">
        <h1>
            <span class="dashicons dashicons-phone"></span>
            Twilio SMS &mdash; API Settings
        </h1>

        <?php etsn_nav_tabs( 'settings' ); ?>

        <div class="etsn-status-bar <?php echo $has_creds ? 'etsn-status-connected' : 'etsn-status-warning'; ?>" id="etsn-connection-status">
            <span class="dashicons <?php echo $has_creds ? 'dashicons-yes-alt' : 'dashicons-warning'; ?>"></span>
            <?php if ( $has_creds ) : ?>
                Credentials are saved and encrypted. Click <strong>Test Connection</strong> to verify with Twilio.
            <?php else : ?>
                No credentials saved yet. Enter your Twilio credentials below.
            <?php endif; ?>
        </div>

        <!-- Credentials Card -->
        <div class="etsn-card">
            <h2>
                <span class="dashicons dashicons-lock"></span>
                Twilio Credentials
            </h2>
            <p class="etsn-hint">
                Credentials are <strong>AES-256-CBC encrypted</strong> using your WordPress secret keys before being stored in the database. They are never exposed in page HTML.
            </p>

            <table class="etsn-table">
                <tr>
                    <th><label for="etsn_sid">Account SID</label></th>
                    <td>
                        <input type="password" id="etsn_sid" class="regular-text"
                               autocomplete="new-password"
                               placeholder="ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" />
                        <?php if ( $sid_masked ) : ?>
                            <span class="etsn-saved-badge">Saved: <code><?php echo esc_html( $sid_masked ); ?></code></span>
                        <?php endif; ?>
                        <p class="description">Leave blank to keep existing value.</p>
                    </td>
                </tr>
                <tr>
                    <th><label for="etsn_token">Auth Token</label></th>
                    <td>
                        <input type="password" id="etsn_token" class="regular-text"
                               autocomplete="new-password"
                               placeholder="Your Twilio Auth Token" />
                        <?php if ( $token_masked ) : ?>
                            <span class="etsn-saved-badge">Saved: <code><?php echo esc_html( $token_masked ); ?></code></span>
                        <?php endif; ?>
                        <p class="description">
                            Found at <a href="https://console.twilio.com" target="_blank" rel="noopener">console.twilio.com</a>.
                            Leave blank to keep existing.
                        </p>
                    </td>
                </tr>
                <tr>
                    <th><label for="etsn_from">From Number</label></th>
                    <td>
                        <input type="text" id="etsn_from" class="regular-text"
                               placeholder="+15551234567"
                               value="<?php echo $from; ?>" />
                        <p class="description">Your Twilio phone number in E.164 format (e.g. +15551234567).</p>
                    </td>
                </tr>
                <tr>
                    <th><label for="etsn_secret">Webhook Secret Key</label></th>
                    <td>
                        <input type="password" id="etsn_secret" class="regular-text"
                               autocomplete="new-password"
                               placeholder="A strong random secret" />
                        <?php if ( $secret_masked ) : ?>
                            <span class="etsn-saved-badge">Saved: <code><?php echo esc_html( $secret_masked ); ?></code></span>
                        <?php endif; ?>
                        <p class="description">
                            Sent as <code>X-ETSN-Secret</code> header to protect the webhook endpoint.
                            Leave blank to keep existing.
                        </p>
                    </td>
                </tr>
            </table>

            <div class="etsn-actions">
                <button type="button" class="button button-primary" id="etsn-save-creds">
                    <span class="dashicons dashicons-saved"></span> Save Credentials
                </button>
                <button type="button" class="button" id="etsn-test-conn">
                    <span class="dashicons dashicons-update"></span> Test Connection
                </button>
            </div>
            <div class="etsn-inline-result" id="etsn-cred-result"></div>
        </div>

        <!-- Test SMS Card -->
        <div class="etsn-card<?php echo $has_creds ? '' : ' etsn-card-locked'; ?>" id="etsn-test-sms-card">
            <h2>
                <span class="dashicons dashicons-email-alt"></span>
                Send Test SMS
            </h2>
            <?php if ( ! $has_creds ) : ?>
                <p class="etsn-hint">Save your Twilio credentials above to unlock this section.</p>
            <?php endif; ?>
            <table class="etsn-table">
                <tr>
                    <th><label for="etsn_test_to">Send To</label></th>
                    <td>
                        <input type="text" id="etsn_test_to" class="regular-text"
                               placeholder="+15557654321"
                               <?php echo $has_creds ? '' : 'disabled'; ?> />
                        <p class="description">Recipient phone number in E.164 format.</p>
                    </td>
                </tr>
                <tr>
                    <th><label for="etsn_test_msg">Message</label></th>
                    <td>
                        <textarea id="etsn_test_msg" class="large-text" rows="3"
                                  <?php echo $has_creds ? '' : 'disabled'; ?>
                        >Test SMS from <?php echo esc_textarea( get_bloginfo( 'name' ) ); ?>. Twilio SMS Notifier v<?php echo ETSN_VERSION; ?> is working correctly.</textarea>
                    </td>
                </tr>
            </table>
            <div class="etsn-actions">
                <button type="button" class="button button-primary" id="etsn-send-test"
                        <?php echo $has_creds ? '' : 'disabled'; ?>>
                    <span class="dashicons dashicons-controls-play"></span> Send Test SMS
                </button>
            </div>
            <div class="etsn-inline-result" id="etsn-test-result"></div>
        </div>

    </div><!-- .etsn-wrap -->
    <?php
}


// ============================================================
// SECTION 6 — PAGE: ELEMENTOR FORMS
// ============================================================

function etsn_page_forms() {
    $pro_active = defined( 'ELEMENTOR_PRO_VERSION' ) || class_exists( '\ElementorPro\Plugin' );

    if ( ! $pro_active ) {
        ?>
        <div class="wrap etsn-wrap">
            <h1>
                <span class="dashicons dashicons-feedback"></span>
                Twilio SMS &mdash; Elementor Forms
            </h1>
            <?php etsn_nav_tabs( 'forms' ); ?>
            <div class="etsn-status-bar etsn-status-warning">
                <span class="dashicons dashicons-warning"></span>
                <strong>Elementor Pro</strong> is not active. Please install and activate Elementor Pro to use this feature.
            </div>
        </div>
        <?php
        return;
    }

    $forms   = etsn_get_elementor_forms();
    $configs = get_option( ETSN_OPTION_FORMS, array() );
    ?>
    <div class="wrap etsn-wrap">
        <h1>
            <span class="dashicons dashicons-feedback"></span>
            Twilio SMS &mdash; Elementor Forms
        </h1>
        <?php etsn_nav_tabs( 'forms' ); ?>

        <?php if ( empty( $forms ) ) : ?>
            <div class="etsn-status-bar etsn-status-warning">
                <span class="dashicons dashicons-info"></span>
                No Elementor Pro forms found. Create a form using the Elementor Form widget and publish the page &mdash; it will appear here automatically.
            </div>
        <?php else : ?>

            <p class="etsn-hint">
                Found <strong><?php echo count( $forms ); ?></strong> form(s).
                Enable SMS for each form, set the recipient number, and customise the message template.
                Click any field token chip to insert it at the cursor.
            </p>

            <?php foreach ( $forms as $form ) :
                $fid      = esc_attr( $form['id'] );
                $cfg      = isset( $configs[ $form['id'] ] ) ? $configs[ $form['id'] ] : array();
                $enabled  = ! empty( $cfg['enabled'] );
                $to_val   = esc_attr( isset( $cfg['to'] ) ? $cfg['to'] : '' );
                $tmpl_val = esc_textarea( isset( $cfg['template'] ) ? $cfg['template'] : etsn_default_template( $form['fields'] ) );
                ?>
                <div class="etsn-card etsn-form-card" data-form-id="<?php echo $fid; ?>">

                    <div class="etsn-form-header">
                        <div class="etsn-form-header-info">
                            <h3><?php echo esc_html( $form['name'] ); ?></h3>
                            <span class="etsn-form-meta">
                                Page:
                                <a href="<?php echo esc_url( get_permalink( $form['page_id'] ) ); ?>" target="_blank" rel="noopener">
                                    <?php echo esc_html( get_the_title( $form['page_id'] ) ?: '(ID: ' . $form['page_id'] . ')' ); ?>
                                </a>
                                &nbsp;&mdash;&nbsp; <?php echo count( $form['fields'] ); ?> field(s) detected
                            </span>
                        </div>
                        <label class="etsn-toggle" title="Enable or disable SMS for this form">
                            <input type="checkbox" class="etsn-form-enabled" <?php checked( $enabled ); ?> />
                            <span class="etsn-toggle-track">
                                <span class="etsn-toggle-thumb"></span>
                            </span>
                            <span class="etsn-toggle-label"><?php echo $enabled ? 'Enabled' : 'Disabled'; ?></span>
                        </label>
                    </div>

                    <table class="etsn-table">
                        <tr>
                            <th><label>Send SMS To</label></th>
                            <td>
                                <input type="text" class="regular-text etsn-form-to"
                                       value="<?php echo $to_val; ?>"
                                       placeholder="+15557654321" />
                                <p class="description">Recipient phone in E.164 format.</p>
                            </td>
                        </tr>
                        <tr>
                            <th><label>SMS Template</label></th>
                            <td>
                                <textarea class="large-text etsn-form-template" rows="6"><?php echo $tmpl_val; ?></textarea>
                                <p class="description" style="margin-bottom:8px">
                                    Click a token to insert it at the cursor position:
                                </p>
                                <div class="etsn-tokens">
                                    <?php foreach ( $form['fields'] as $field ) : ?>
                                        <button type="button"
                                                class="etsn-token"
                                                data-token="{field:<?php echo esc_attr( $field['id'] ); ?>}"
                                                title="<?php echo esc_attr( $field['label'] ); ?>">
                                            <span class="etsn-token-code">{field:<?php echo esc_html( $field['id'] ); ?>}</span>
                                            <span class="etsn-token-label"><?php echo esc_html( $field['label'] ); ?></span>
                                        </button>
                                    <?php endforeach; ?>
                                    <button type="button" class="etsn-token etsn-token-global" data-token="{form_name}" title="Form name">{form_name}</button>
                                    <button type="button" class="etsn-token etsn-token-global" data-token="{site_name}" title="Site name">{site_name}</button>
                                    <button type="button" class="etsn-token etsn-token-global" data-token="{date}" title="Submission date and time">{date}</button>
                                    <button type="button" class="etsn-token etsn-token-global" data-token="{page_url}" title="Page URL">{page_url}</button>
                                </div>
                            </td>
                        </tr>
                    </table>

                    <div class="etsn-actions">
                        <button type="button" class="button button-primary etsn-save-form-btn">
                            <span class="dashicons dashicons-saved"></span> Save This Form
                        </button>
                    </div>
                    <div class="etsn-inline-result etsn-form-result"></div>
                </div>
            <?php endforeach; ?>

        <?php endif; ?>
    </div>
    <?php
}


// ============================================================
// SECTION 7 — PAGE: WEBHOOK
// ============================================================

function etsn_page_webhook() {
    $webhook_url   = rest_url( 'etsn/v1/send-sms' );
    $secret_masked = etsn_mask( etsn_get_credential( ETSN_OPTION_SECRET ) );
    $secret_set    = (bool) etsn_get_credential( ETSN_OPTION_SECRET );
    ?>
    <div class="wrap etsn-wrap">
        <h1>
            <span class="dashicons dashicons-rest-api"></span>
            Twilio SMS &mdash; Webhook
        </h1>
        <?php etsn_nav_tabs( 'webhook' ); ?>

        <?php if ( ! $secret_set ) : ?>
            <div class="etsn-status-bar etsn-status-warning">
                <span class="dashicons dashicons-warning"></span>
                No webhook secret is set. Your endpoint is currently unprotected. Set a secret key in
                <a href="<?php echo esc_url( admin_url( 'admin.php?page=' . ETSN_SLUG ) ); ?>">API Settings</a>.
            </div>
        <?php endif; ?>

        <div class="etsn-card">
            <h2>
                <span class="dashicons dashicons-admin-links"></span>
                Endpoint Details
            </h2>
            <table class="etsn-table">
                <tr>
                    <th>Webhook URL</th>
                    <td>
                        <div class="etsn-copy-row">
                            <code><?php echo esc_url( $webhook_url ); ?></code>
                            <button type="button" class="button etsn-copy-btn"
                                    data-copy="<?php echo esc_attr( $webhook_url ); ?>">
                                <span class="dashicons dashicons-clipboard"></span> Copy URL
                            </button>
                        </div>
                    </td>
                </tr>
                <tr>
                    <th>Method</th>
                    <td><code>POST</code></td>
                </tr>
                <tr>
                    <th>Auth Header</th>
                    <td>
                        <code>X-ETSN-Secret: your_secret_key</code>
                        <p class="description">
                            Saved secret: <strong><?php echo esc_html( $secret_masked ? $secret_masked : '(not set)' ); ?></strong>
                        </p>
                    </td>
                </tr>
                <tr>
                    <th>Content-Type</th>
                    <td><code>application/json</code></td>
                </tr>
            </table>
        </div>

        <div class="etsn-card">
            <h2>
                <span class="dashicons dashicons-editor-code"></span>
                Request &amp; Response Reference
            </h2>
            <p><strong>Request Body (JSON)</strong></p>
            <pre class="etsn-code">{
  "to":      "+15557654321",
  "message": "Your SMS body text"
}</pre>
            <p style="margin-top:16px"><strong>Success Response &mdash; HTTP 200</strong></p>
            <pre class="etsn-code">{
  "success":    true,
  "message_id": "SMxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  "status":     "queued"
}</pre>
            <p style="margin-top:16px"><strong>Error Response &mdash; HTTP 403 / 500</strong></p>
            <pre class="etsn-code">{
  "success": false,
  "error":   "Human-readable error description"
}</pre>
        </div>

        <div class="etsn-card">
            <h2>
                <span class="dashicons dashicons-editor-code"></span>
                cURL Example
            </h2>
            <div style="margin-bottom:8px">
                <button type="button" class="button etsn-copy-btn"
                        data-copy='curl -X POST "<?php echo esc_attr( $webhook_url ); ?>" -H "Content-Type: application/json" -H "X-ETSN-Secret: YOUR_SECRET" -d "{\"to\":\"+15557654321\",\"message\":\"Hello from webhook!\"}"'>
                    <span class="dashicons dashicons-clipboard"></span> Copy cURL
                </button>
            </div>
            <pre class="etsn-code">curl -X POST "<?php echo esc_url( $webhook_url ); ?>" \
  -H "Content-Type: application/json" \
  -H "X-ETSN-Secret: YOUR_SECRET_KEY" \
  -d '{"to": "+15557654321", "message": "Hello from webhook!"}'</pre>
        </div>

        <div class="etsn-card">
            <h2>
                <span class="dashicons dashicons-editor-code"></span>
                JavaScript / Fetch Example
            </h2>
            <pre class="etsn-code">const res = await fetch("<?php echo esc_url( $webhook_url ); ?>", {
  method:  "POST",
  headers: {
    "Content-Type": "application/json",
    "X-ETSN-Secret": "YOUR_SECRET_KEY"
  },
  body: JSON.stringify({
    to:      "+15557654321",
    message: "Hello from JavaScript!"
  })
});
const data = await res.json();
// { success: true, message_id: "SM...", status: "queued" }</pre>
        </div>

    </div>
    <?php
}


// ============================================================
// SECTION 8 — SHARED: NAVIGATION TABS
// ============================================================

function etsn_nav_tabs( $active ) {
    $tabs = array(
        'settings' => array( 'label' => 'API Settings',    'page' => ETSN_SLUG ),
        'forms'    => array( 'label' => 'Elementor Forms', 'page' => ETSN_SLUG . '-forms' ),
        'webhook'  => array( 'label' => 'Webhook',         'page' => ETSN_SLUG . '-webhook' ),
    );
    echo '<nav class="etsn-nav-tabs">';
    foreach ( $tabs as $key => $tab ) {
        $url   = admin_url( 'admin.php?page=' . $tab['page'] );
        $class = 'etsn-tab' . ( $key === $active ? ' etsn-tab-active' : '' );
        echo '<a href="' . esc_url( $url ) . '" class="' . esc_attr( $class ) . '">' . esc_html( $tab['label'] ) . '</a>';
    }
    echo '</nav>';
}


// ============================================================
// SECTION 9 — ELEMENTOR FORM SCANNER
// ============================================================

function etsn_get_elementor_forms() {
    $forms = array();

    $post_ids = get_posts( array(
        'post_type'      => array( 'page', 'post', 'elementor_library' ),
        'posts_per_page' => 300,
        'post_status'    => array( 'publish', 'private' ),
        'meta_key'       => '_elementor_data',
        'fields'         => 'ids',
    ) );

    foreach ( $post_ids as $post_id ) {
        $data = get_post_meta( $post_id, '_elementor_data', true );
        if ( ! $data ) continue;
        $elements = json_decode( is_string( $data ) ? $data : '[]', true );
        if ( is_array( $elements ) ) {
            etsn_find_forms_recursive( $elements, (int) $post_id, $forms );
        }
    }

    return $forms;
}

function etsn_find_forms_recursive( array $elements, int $page_id, array &$forms ) {
    foreach ( $elements as $el ) {
        $widget_type = isset( $el['widgetType'] ) ? $el['widgetType'] : '';
        if ( $widget_type === 'form' ) {
            $settings  = isset( $el['settings'] ) ? $el['settings'] : array();
            $form_id   = isset( $el['id'] ) ? $el['id'] : uniqid( 'form_', true );
            $form_name = isset( $settings['form_name'] ) ? $settings['form_name'] : 'Unnamed Form';
            $fields    = array();

            $raw_fields = isset( $settings['form_fields'] ) ? $settings['form_fields'] : array();
            foreach ( $raw_fields as $f ) {
                $fid   = isset( $f['custom_id'] ) ? $f['custom_id'] : ( isset( $f['_id'] ) ? $f['_id'] : '' );
                $label = isset( $f['field_label'] ) ? $f['field_label'] : ucfirst( $fid );
                $type  = isset( $f['field_type'] ) ? $f['field_type'] : 'text';
                $skip  = array( 'submit', 'html', 'step', 'recaptcha', 'recaptcha_v3', 'hidden' );
                if ( $fid && ! in_array( $type, $skip, true ) ) {
                    $fields[] = array( 'id' => $fid, 'label' => $label, 'type' => $type );
                }
            }

            $forms[ $form_id ] = array(
                'id'      => $form_id,
                'name'    => $form_name,
                'page_id' => $page_id,
                'fields'  => $fields,
            );
        }

        if ( ! empty( $el['elements'] ) && is_array( $el['elements'] ) ) {
            etsn_find_forms_recursive( $el['elements'], $page_id, $forms );
        }
    }
}

function etsn_default_template( array $fields ) {
    $lines = array( 'New form submission on {site_name}', '' );
    foreach ( $fields as $f ) {
        $lines[] = $f['label'] . ': {field:' . $f['id'] . '}';
    }
    $lines[] = '';
    $lines[] = 'Date: {date}';
    $lines[] = 'Page: {page_url}';
    return implode( "\n", $lines );
}


// ============================================================
// SECTION 10 — ELEMENTOR PRO FORM HOOK
// ============================================================

add_action( 'elementor_pro/forms/new_record', 'etsn_handle_form_submission', 10, 2 );
function etsn_handle_form_submission( $record, $handler ) {
    $configs = get_option( ETSN_OPTION_FORMS, array() );
    if ( empty( $configs ) ) return;

    $widget_id = $record->get_form_settings( 'id' );
    $cfg       = null;

    if ( $widget_id && isset( $configs[ $widget_id ] ) && ! empty( $configs[ $widget_id ]['enabled'] ) ) {
        $cfg = $configs[ $widget_id ];
    } else {
        foreach ( $configs as $c ) {
            if ( ! empty( $c['enabled'] ) ) {
                $cfg = $c;
                break;
            }
        }
    }

    if ( ! $cfg || empty( $cfg['enabled'] ) || empty( $cfg['to'] ) ) return;

    // Build field map
    $raw_fields = $record->get( 'fields' );
    $field_map  = array();
    foreach ( $raw_fields as $id => $field ) {
        $field_map[ $id ] = sanitize_text_field( isset( $field['value'] ) ? $field['value'] : '' );
    }

    $template = isset( $cfg['template'] ) ? $cfg['template'] : '';

    // Replace {field:ID} tokens
    $message = preg_replace_callback(
        '/\{field:([a-zA-Z0-9_\-]+)\}/',
        function ( $m ) use ( $field_map ) {
            return isset( $field_map[ $m[1] ] ) ? $field_map[ $m[1] ] : '(field:' . $m[1] . ' not found)';
        },
        $template
    );

    // Global tokens
    $page_id = $record->get_form_settings( 'page_id' );
    $message = str_replace(
        array( '{form_name}', '{site_name}', '{date}', '{page_url}' ),
        array(
            (string) $record->get_form_settings( 'form_name' ),
            get_bloginfo( 'name' ),
            wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ) ),
            $page_id ? get_permalink( $page_id ) : home_url(),
        ),
        $message
    );

    $result = etsn_send_sms( $cfg['to'], $message );
    if ( is_wp_error( $result ) ) {
        error_log( '[ETSN] Form SMS failed (widget: ' . $widget_id . '): ' . $result->get_error_message() );
    }
}


// ============================================================
// SECTION 11 — REST API WEBHOOK ENDPOINT
// ============================================================

add_action( 'rest_api_init', 'etsn_register_rest_route' );
function etsn_register_rest_route() {
    register_rest_route( 'etsn/v1', '/send-sms', array(
        'methods'             => WP_REST_Server::CREATABLE,
        'callback'            => 'etsn_webhook_handler',
        'permission_callback' => 'etsn_webhook_permission',
        'args'                => array(
            'to'      => array( 'required' => true,  'type' => 'string', 'sanitize_callback' => 'sanitize_text_field' ),
            'message' => array( 'required' => true,  'type' => 'string', 'sanitize_callback' => 'sanitize_textarea_field' ),
        ),
    ) );
}

function etsn_webhook_permission( WP_REST_Request $request ) {
    $secret   = etsn_get_credential( ETSN_OPTION_SECRET );
    $provided = (string) $request->get_header( 'X-ETSN-Secret' );

    if ( empty( $secret ) ) {
        error_log( '[ETSN] WARNING: Webhook secret is not configured — endpoint is publicly accessible.' );
        return true;
    }

    if ( ! hash_equals( $secret, $provided ) ) {
        return new WP_Error( 'etsn_forbidden', 'Invalid or missing webhook secret.', array( 'status' => 403 ) );
    }

    return true;
}

function etsn_webhook_handler( WP_REST_Request $request ) {
    $to      = $request->get_param( 'to' );
    $message = $request->get_param( 'message' );
    $result  = etsn_send_sms( $to, $message );

    if ( is_wp_error( $result ) ) {
        return new WP_REST_Response( array( 'success' => false, 'error' => $result->get_error_message() ), 500 );
    }

    return new WP_REST_Response( array(
        'success'    => true,
        'message_id' => isset( $result['sid'] )    ? $result['sid']    : null,
        'status'     => isset( $result['status'] )  ? $result['status']  : null,
    ), 200 );
}


// ============================================================
// SECTION 12 — INLINE CSS
// ============================================================

function etsn_admin_css() {
    return '
/* ── Wrap ────────────────────────────────────────────────── */
.etsn-wrap { max-width: 900px; }
.etsn-wrap > h1 { display:flex; align-items:center; gap:8px; margin-bottom:4px; font-size:22px; }
.etsn-wrap > h1 .dashicons { font-size:24px; width:24px; height:24px; color:#2271b1; }

/* ── Tabs ─────────────────────────────────────────────────── */
.etsn-nav-tabs {
    display: flex;
    gap: 4px;
    margin: 16px 0 24px;
    border-bottom: 2px solid #dcdcde;
    padding-bottom: 0;
}
.etsn-tab {
    display: inline-block;
    padding: 9px 20px;
    border-radius: 6px 6px 0 0;
    text-decoration: none;
    color: #50575e;
    background: #f0f0f1;
    border: 1px solid #dcdcde;
    border-bottom: none;
    margin-bottom: -2px;
    font-weight: 500;
    font-size: 13px;
    transition: background 0.15s, color 0.15s;
}
.etsn-tab:hover { background: #fff; color: #2271b1; }
.etsn-tab-active {
    background: #fff;
    color: #2271b1;
    border-bottom-color: #fff;
    font-weight: 700;
}

/* ── Status bars ─────────────────────────────────────────── */
.etsn-status-bar {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 11px 16px;
    border-radius: 6px;
    margin-bottom: 20px;
    font-size: 13px;
    line-height: 1.5;
}
.etsn-status-bar .dashicons { flex-shrink: 0; }
.etsn-status-connected { background: #d1e7dd; color: #0a3622; border: 1px solid #a3cfbb; }
.etsn-status-warning   { background: #fff3cd; color: #664d03; border: 1px solid #ffe69c; }
.etsn-status-error     { background: #f8d7da; color: #58151c; border: 1px solid #f1aeb5; }

/* ── Cards ───────────────────────────────────────────────── */
.etsn-card {
    background: #fff;
    border: 1px solid #dcdcde;
    border-radius: 8px;
    padding: 24px 28px;
    margin-bottom: 24px;
    box-shadow: 0 1px 4px rgba(0,0,0,.05);
}
.etsn-card h2 {
    display: flex;
    align-items: center;
    gap: 7px;
    margin: 0 0 14px;
    padding-bottom: 12px;
    border-bottom: 1px solid #f0f0f1;
    font-size: 15px;
    color: #1d2327;
}
.etsn-card h2 .dashicons { color: #2271b1; }
.etsn-card-locked {
    opacity: 0.5;
    pointer-events: none;
}

/* ── Table ───────────────────────────────────────────────── */
.etsn-table { width: 100%; border-collapse: collapse; }
.etsn-table th {
    width: 190px;
    text-align: left;
    vertical-align: top;
    padding: 12px 16px 12px 0;
    font-weight: 600;
    font-size: 13px;
    color: #1d2327;
}
.etsn-table td { padding: 8px 0 14px; }
.etsn-table td .description { margin-top: 5px; }
.etsn-table input[type="text"],
.etsn-table input[type="password"],
.etsn-table textarea { width: 100%; box-sizing: border-box; }

/* ── Saved badge ─────────────────────────────────────────── */
.etsn-saved-badge {
    display: inline-block;
    margin-left: 10px;
    font-size: 12px;
    color: #646970;
    background: #f6f7f7;
    border: 1px solid #dcdcde;
    border-radius: 4px;
    padding: 2px 8px;
    vertical-align: middle;
}
.etsn-hint {
    color: #646970;
    font-size: 13px;
    margin: 0 0 16px;
    line-height: 1.5;
}

/* ── Actions + inline results ────────────────────────────── */
.etsn-actions {
    display: flex;
    gap: 10px;
    align-items: center;
    flex-wrap: wrap;
    margin-top: 18px;
}
.etsn-actions .button { display: inline-flex; align-items: center; gap: 5px; }
.etsn-actions .dashicons { font-size: 16px; width: 16px; height: 16px; }
.etsn-inline-result {
    display: none;
    margin-top: 12px;
    padding: 10px 14px;
    border-radius: 5px;
    font-size: 13px;
    line-height: 1.5;
}
.etsn-inline-result.etsn-ok  { background: #d1e7dd; color: #0a3622; border: 1px solid #a3cfbb; }
.etsn-inline-result.etsn-err { background: #f8d7da; color: #58151c; border: 1px solid #f1aeb5; }

/* ── Code blocks ─────────────────────────────────────────── */
.etsn-code {
    background: #1d2327;
    color: #d4d4d4;
    padding: 16px 20px;
    border-radius: 6px;
    overflow-x: auto;
    font-size: 12.5px;
    line-height: 1.65;
    white-space: pre;
    font-family: Consolas, "Courier New", monospace;
}
.etsn-copy-row { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.etsn-copy-row code {
    background: #f6f7f7;
    padding: 6px 12px;
    border-radius: 4px;
    font-size: 13px;
    word-break: break-all;
    border: 1px solid #dcdcde;
}
.etsn-copy-btn { display: inline-flex !important; align-items: center; gap: 5px; }
.etsn-copy-btn .dashicons { font-size: 16px; width: 16px; height: 16px; }

/* ── Form card header ────────────────────────────────────── */
.etsn-form-header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 12px;
    padding-bottom: 12px;
    border-bottom: 1px solid #f0f0f1;
    margin-bottom: 14px;
}
.etsn-form-header h3 { margin: 0 0 4px; font-size: 15px; color: #1d2327; }
.etsn-form-meta { display: block; font-size: 12px; color: #8c8f94; }

/* ── Toggle switch ───────────────────────────────────────── */
.etsn-toggle {
    display: inline-flex;
    align-items: center;
    gap: 9px;
    cursor: pointer;
    user-select: none;
    white-space: nowrap;
    flex-shrink: 0;
}
.etsn-toggle input[type="checkbox"] { display: none; }
.etsn-toggle-track {
    position: relative;
    width: 44px;
    height: 24px;
    background: #c3c4c7;
    border-radius: 12px;
    transition: background 0.2s;
    flex-shrink: 0;
}
.etsn-toggle input:checked ~ .etsn-toggle-track { background: #2271b1; }
.etsn-toggle-thumb {
    position: absolute;
    top: 3px;
    left: 3px;
    width: 18px;
    height: 18px;
    background: #fff;
    border-radius: 50%;
    transition: left 0.2s;
    box-shadow: 0 1px 3px rgba(0,0,0,0.3);
}
.etsn-toggle input:checked ~ .etsn-toggle-track .etsn-toggle-thumb { left: 23px; }
.etsn-toggle-label { font-size: 13px; color: #3c434a; font-weight: 500; min-width: 52px; }

/* ── Field token chips ───────────────────────────────────── */
.etsn-tokens { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px; }
.etsn-token {
    display: inline-flex;
    flex-direction: column;
    align-items: flex-start;
    background: #eff6ff;
    color: #1d4ed8;
    padding: 4px 10px;
    border-radius: 20px;
    font-size: 11.5px;
    cursor: pointer;
    border: 1px solid #bfdbfe;
    transition: background 0.15s;
    line-height: 1.4;
    font-family: Consolas, "Courier New", monospace;
    text-align: left;
}
.etsn-token:hover { background: #dbeafe; border-color: #93c5fd; }
.etsn-token-code { font-weight: 600; }
.etsn-token-label { font-size: 10px; color: #64748b; font-family: -apple-system, sans-serif; }
.etsn-token-global {
    background: #f0fdf4;
    color: #166534;
    border-color: #bbf7d0;
}
.etsn-token-global:hover { background: #dcfce7; border-color: #86efac; }

/* ── Spin animation for loading state ───────────────────── */
@keyframes etsn-spin { to { transform: rotate(360deg); } }
.etsn-spin { animation: etsn-spin 0.8s linear infinite; display: inline-block; }
';
}


// ============================================================
// SECTION 13 — INLINE JAVASCRIPT
// ============================================================

function etsn_admin_js() {
    return '
(function($){
    "use strict";

    // ── Save Credentials ─────────────────────────────────────
    $(document).on("click", "#etsn-save-creds", function() {
        var $btn = $(this);
        $btn.prop("disabled", true).find(".dashicons").attr("class", "dashicons dashicons-update etsn-spin");
        $.ajax({
            url:    ETSN.ajaxurl,
            method: "POST",
            data: {
                action: "etsn_save_credentials",
                nonce:  ETSN.nonce,
                sid:    $.trim($("#etsn_sid").val()),
                token:  $.trim($("#etsn_token").val()),
                from:   $.trim($("#etsn_from").val()),
                secret: $.trim($("#etsn_secret").val())
            },
            success: function(r) {
                etsnShow("#etsn-cred-result", r.success, r.message || "Unknown response.");
                if (r.success) {
                    $("#etsn-test-sms-card").removeClass("etsn-card-locked");
                    $("#etsn-send-test, #etsn_test_to, #etsn_test_msg").prop("disabled", false);
                }
            },
            error: function(xhr) {
                etsnShow("#etsn-cred-result", false, "AJAX request failed (HTTP " + xhr.status + "). Check server logs.");
            },
            complete: function() {
                $btn.prop("disabled", false).find(".dashicons").attr("class", "dashicons dashicons-saved");
            }
        });
    });

    // ── Test Connection ──────────────────────────────────────
    $(document).on("click", "#etsn-test-conn", function() {
        var $btn = $(this);
        var $bar = $("#etsn-connection-status");
        $btn.prop("disabled", true).find(".dashicons").addClass("etsn-spin");
        $.ajax({
            url:    ETSN.ajaxurl,
            method: "POST",
            data: {
                action: "etsn_test_connection",
                nonce:  ETSN.nonce
            },
            success: function(r) {
                var icon = r.success ? "dashicons-yes-alt" : "dashicons-dismiss";
                var cls  = r.success ? "etsn-status-connected" : "etsn-status-error";
                $bar.removeClass("etsn-status-warning etsn-status-connected etsn-status-error")
                    .addClass(cls)
                    .html("<span class=\"dashicons " + icon + "\"></span> " + (r.message || "No message."));
                etsnShow("#etsn-cred-result", r.success, r.message || "No message.");
                if (r.success) {
                    $("#etsn-test-sms-card").removeClass("etsn-card-locked");
                    $("#etsn-send-test, #etsn_test_to, #etsn_test_msg").prop("disabled", false);
                }
            },
            error: function(xhr) {
                etsnShow("#etsn-cred-result", false, "AJAX request failed (HTTP " + xhr.status + ").");
            },
            complete: function() {
                $btn.prop("disabled", false).find(".dashicons").removeClass("etsn-spin");
            }
        });
    });

    // ── Send Test SMS ────────────────────────────────────────
    $(document).on("click", "#etsn-send-test", function() {
        var to = $.trim($("#etsn_test_to").val());
        if (!to) {
            etsnShow("#etsn-test-result", false, "Please enter a recipient phone number.");
            return;
        }
        var $btn = $(this);
        $btn.prop("disabled", true).find(".dashicons").addClass("etsn-spin");
        $.ajax({
            url:    ETSN.ajaxurl,
            method: "POST",
            data: {
                action:  "etsn_test_sms",
                nonce:   ETSN.nonce,
                to:      to,
                message: $.trim($("#etsn_test_msg").val())
            },
            success: function(r) {
                etsnShow("#etsn-test-result", r.success, r.message || "No message.");
            },
            error: function(xhr) {
                etsnShow("#etsn-test-result", false, "AJAX request failed (HTTP " + xhr.status + ").");
            },
            complete: function() {
                $btn.prop("disabled", false).find(".dashicons").removeClass("etsn-spin");
            }
        });
    });

    // ── Save Per-Form Config ─────────────────────────────────
    $(document).on("click", ".etsn-save-form-btn", function() {
        var $btn  = $(this);
        var $card = $btn.closest(".etsn-form-card");
        var $res  = $card.find(".etsn-form-result");
        $btn.prop("disabled", true).find(".dashicons").addClass("etsn-spin");
        $.ajax({
            url:    ETSN.ajaxurl,
            method: "POST",
            data: {
                action:   "etsn_save_form_config",
                nonce:    ETSN.nonce,
                form_id:  $card.data("form-id"),
                enabled:  $card.find(".etsn-form-enabled").is(":checked") ? "1" : "0",
                to:       $.trim($card.find(".etsn-form-to").val()),
                template: $card.find(".etsn-form-template").val()
            },
            success: function(r) {
                etsnShow($res, r.success, r.message || "No message.");
            },
            error: function(xhr) {
                etsnShow($res, false, "AJAX request failed (HTTP " + xhr.status + ").");
            },
            complete: function() {
                $btn.prop("disabled", false).find(".dashicons").removeClass("etsn-spin");
            }
        });
    });

    // ── Toggle Label Update ──────────────────────────────────
    $(document).on("change", ".etsn-form-enabled", function() {
        $(this).closest(".etsn-toggle").find(".etsn-toggle-label")
               .text(this.checked ? "Enabled" : "Disabled");
    });

    // ── Token Click → Insert at Cursor ───────────────────────
    $(document).on("click", ".etsn-token", function() {
        var token = $(this).data("token");
        var $ta   = $(this).closest(".etsn-form-card").find(".etsn-form-template");
        if (!$ta.length || !token) return;
        var el  = $ta[0];
        var s   = el.selectionStart;
        var e   = el.selectionEnd;
        var val = el.value;
        el.value = val.slice(0, s) + token + val.slice(e);
        el.selectionStart = el.selectionEnd = s + token.length;
        el.focus();
    });

    // ── Copy Button ──────────────────────────────────────────
    $(document).on("click", ".etsn-copy-btn", function() {
        var text = $(this).data("copy");
        var $btn = $(this);
        if (!text || !navigator.clipboard) return;
        navigator.clipboard.writeText(text).then(function() {
            var origHtml = $btn.html();
            $btn.html("<span class=\"dashicons dashicons-yes\"></span> Copied!").prop("disabled", true);
            setTimeout(function() {
                $btn.html(origHtml).prop("disabled", false);
            }, 2000);
        });
    });

    // ── Helper: show result banner ───────────────────────────
    function etsnShow(selector, ok, msg) {
        $(selector)
            .stop(true, true)
            .removeClass("etsn-ok etsn-err")
            .addClass(ok ? "etsn-ok" : "etsn-err")
            .html(msg)
            .slideDown(180);
    }

}(jQuery));
';
}