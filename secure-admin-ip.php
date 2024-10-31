<?php
/*
* Plugin Name: Secure Admin IP
* Description: Simply restrict access to your WordPress admin for the specific IP addresses.
* Version: 2.0
* Author: Michal Novák
* Author URI: https://www.novami.cz
* License: GPL3
* Text Domain: secure-admin-ip
*/

if (!defined('ABSPATH')) {
    die('Direct access not allowed!');
}


/**
 * Class SecureAdminIP
 */
class SecureAdminIP
{
    const SAI_OPTIONS = 'sai_options';
    const SAI_HASH = 'sai_hash';
    const SAI_LIST = 'sai_list';
    const SAI_LIST_EXTERNAL_URL = 'sai_list_external_url';
    const SAI_LIST_EXTERNAL_CACHE = 'sai_list_external_cache';

    private $plugin_name;
    private $hash_secret;
    private $hash_get;
    private $hash_cookie;
    private $user_ip;

    private $whitelist;
    private $external_whitelist_url;

    public static $instance;

    /**
     * SecureAdminIP constructor.
     */
    private function __construct()
    {
        $this->getUserIp();
        $this->getHash();

        $this->plugin_name = get_file_data(__FILE__, ['Name' => 'Plugin Name'])['Name'];
        $this->whitelist = get_option(self::SAI_LIST);
        $this->external_whitelist_url = get_option(self::SAI_LIST_EXTERNAL_URL);

        add_action('login_init', [$this, 'check']);
        add_action('admin_init', [$this, 'check']);
        add_action('admin_init', [$this, 'adminSettings']);
        add_action('admin_menu', [$this, 'menu']);

        register_activation_hook(__FILE__, [$this, 'activation']);
        register_uninstall_hook(__FILE__, 'uninstall');

        add_filter(sprintf('plugin_action_links_%s', plugin_basename(__FILE__)), [$this, 'actionLinks']);
    }

    /**
     * @return SecureAdminIP
     */
    public static function getInstance()
    {
        if (!self::$instance instanceof self) {
            self::$instance = new self();
        }

        return self::$instance;
    }

    /**
     * @return bool
     */
    public function activation()
    {
        update_option(self::SAI_HASH, wp_generate_password());

        if (!$this->isUserIpWhitelisted()) {
            update_option(self::SAI_LIST, sprintf('%s%s%s', $this->user_ip, PHP_EOL, $this->whitelist));
        }

        return true;
    }

    /**
     * @return bool
     */
    public static function uninstall()
    {
        $options_list = [
            self::SAI_LIST,
            self::SAI_HASH,
            self::SAI_LIST_EXTERNAL_URL
        ];

        foreach ($options_list as $option) {
            delete_option($option);
        }

        delete_transient(self::SAI_LIST_EXTERNAL_CACHE);

        return true;
    }

    public function getUserIp()
    {
        $ip_sources = [
            'REMOTE_ADDR',
            'HTTP_CF_CONNECTING_IP',
            'HTTP_X_FORWARDED_FOR',
            'HTTP_CLIENT_IP'
        ];

        foreach ($ip_sources as $ip_source) {
            $ip = isset($_SERVER[$ip_source]) && $_SERVER[$ip_source] ? $_SERVER[$ip_source] : false;
            if ($ip) {
                $ip = explode(',', $ip);
                $this->user_ip = filter_var($ip[0], FILTER_VALIDATE_IP);
            }
        }

        if (!$this->user_ip) {
            wp_die(sprintf('<p><strong>%s:</strong> %s.</p>',
                __('Error', 'secure-admin-ip'),
                __('Access denied because your IP address has been not detected', 'secure-admin-ip')),
                'Forbidden',
                ['response' => 403, 'back_link' => 1]
            );
        }
    }

    public function getHash()
    {
        $this->hash_secret = md5(get_option(self::SAI_HASH));

        if (isset($_GET[self::SAI_HASH])) {
            $this->hash_get = filter_input(INPUT_GET, self::SAI_HASH, FILTER_SANITIZE_FULL_SPECIAL_CHARS);
        }

        if (isset($_COOKIE[self::SAI_HASH])) {
            $this->hash_cookie = filter_var($_COOKIE[self::SAI_HASH], FILTER_SANITIZE_FULL_SPECIAL_CHARS);
        }
    }

    public function check()
    {
        if ($this->hash_secret === $this->hash_get && $this->hash_secret !== $this->hash_cookie) {
            setcookie(self::SAI_HASH, $this->hash_secret, 0, '/');
        }

        if (!$this->isUserIpWhitelisted() && !$this->isUsedSecretHash() && !wp_doing_ajax()) {
            wp_die(sprintf('<p><strong>%s:</strong> %s %s %s.</p>',
                __('Error', 'secure-admin-ip'),
                __('Access denied because your IP address', 'secure-admin-ip'),
                $this->user_ip,
                __('is not on the whitelist', 'secure-admin-ip')), 'Forbidden',
                ['response' => 403, 'back_link' => 1]
            );
        }
    }

    /**
     * @param $ip
     * @param $external_whitelist
     * @return bool
     */
    private function isUserIpInWhitelist($ip, $external_whitelist)
    {
        $whitelist_array = (array)json_decode($external_whitelist, JSON_OBJECT_AS_ARRAY);
        $ips = array_column($whitelist_array, 'ip');

        return in_array($ip, $ips);
    }

    /**
     * @return bool
     */
    private function isUserIpWhitelisted()
    {
        $ip_whitelisted = false;

        if ($this->external_whitelist_url) {
            $external_whitelist = get_transient(self::SAI_LIST_EXTERNAL_CACHE);

            if (!$external_whitelist) {
                $external_whitelist = $this->getExternalIpWhitelist($this->external_whitelist_url);
            }

            if ($external_whitelist) {
                set_transient(self::SAI_LIST_EXTERNAL_CACHE, $external_whitelist, MINUTE_IN_SECONDS * 10);

                $ip_whitelisted = $this->isUserIpInWhitelist($this->user_ip, $external_whitelist);
            }
        }

        return strpos($this->whitelist, $this->user_ip) !== false ?: $ip_whitelisted;
    }

    /**
     * @return bool
     */
    private function isUsedSecretHash()
    {
        return $this->hash_get === $this->hash_secret || $this->hash_cookie === $this->hash_secret;
    }

    /**
     * @param $links
     * @return array|string[]
     */
    public function actionLinks($links)
    {
        return array_merge(['settings' => sprintf('<a href="%s%s">%s</a>', admin_url('options-general.php?page='), self::SAI_OPTIONS, __('Settings', 'secure-admin-ip'))], $links);
    }

    public function optionsPage()
    {
        echo sprintf('<div class="wrap"><h1>%s - %s</h1><form method="post" action="?page=%s">', $this->plugin_name, __('Settings', 'secure-admin-ip'), self::SAI_OPTIONS);
        settings_fields('secure_admin_ip_header_section');
        do_settings_sections(self::SAI_OPTIONS);
        submit_button();
        echo '</form></div>';
    }

    public function menu()
    {
        add_submenu_page('options-general.php', $this->plugin_name, $this->plugin_name, 'manage_options', self::SAI_OPTIONS, [$this, 'optionsPage']);
    }

    public function adminSettings()
    {
        $this->saveSettings();

        add_settings_section('secure_admin_ip_header_section', null, [$this, 'adminSection'], self::SAI_OPTIONS);

        add_settings_field(self::SAI_LIST, __('Whitelisted IP addresses', 'secure-admin-ip'), [$this, 'elementIpList'], self::SAI_OPTIONS, 'secure_admin_ip_header_section');
        add_settings_field(self::SAI_LIST_EXTERNAL_URL, __('External whitelist URL', 'secure-admin-ip'), [$this, 'elementExternalIpList'], self::SAI_OPTIONS, 'secure_admin_ip_header_section');

        register_setting('secure_admin_ip_header_section', self::SAI_LIST);
        register_setting('secure_admin_ip_header_section', self::SAI_LIST_EXTERNAL_URL);
    }

    public function adminSection()
    {
        echo sprintf('<div class="notice notice-warning"><h2>%s</h2><p>%s <b><a href="%s?%s=%s">%s</a></b>.<p>%s</p></div>',
            __('Important notice', 'secure-admin-ip'),
            __('There are 2 ways how to access into WordPress administration now - whitelisted IP address or this unique link:', 'secure-admin-ip'),
            wp_login_url(),
            self::SAI_HASH,
            md5(get_option(self::SAI_HASH)),
            __('Secret Admin URL', 'secure-admin-ip'),
            __('Your IP address is whitelisted and secret admin link generated every time at plugin activation!', 'secure-admin-ip')
        );
    }

    public function elementIpList()
    {
        echo sprintf('<textarea name="%1$s" id="%1$s" cols="50" rows="5">%2$s</textarea><p>%3$s</p>',
            self::SAI_LIST,
            $this->whitelist,
            __('It\'s up to you how to separate IP addresses.', 'secure-admin-ip')
        );
    }

    public function elementExternalIpList()
    {
        echo sprintf('<input type="text" name="%1$s" id="%1$s" class="regular-text" value="%2$s"><p>%3$s (JSON): <kbd>[{"ip":"1.1.1.1","description":"Michal"},{"ip":"2.2.2.2","description":"Novak"}]</kbd></p>',
            self::SAI_LIST_EXTERNAL_URL,
            $this->external_whitelist_url,
            __('Example of external whitelist file', 'secure-admin-ip')
        );
    }

    /**
     * @param $url
     * @return false|string
     */
    private function getExternalIpWhitelist($url)
    {
        $validated_url = wp_http_validate_url(esc_url_raw($url));

        if (!$validated_url) {
            error_log(sprintf('%s - %s: Invalid external URL (%s)', __FILE__, __FUNCTION__, $url));

            return false;
        } else {
            $request = wp_safe_remote_get($validated_url, ['sslverify' => false]);

            if (is_wp_error($request)) {
                error_log(sprintf('%s - %s: Unable to load whitelist from %s (%s)', __FILE__, __FUNCTION__, $validated_url, $request->get_error_message()));

                return false;
            }

            return wp_remote_retrieve_body($request);
        }
    }

    private function saveSettings()
    {
        $ip_on_whitelist = false;
        $ip_on_external_whitelist = false;

        $post_whitelist = filter_input(INPUT_POST, self::SAI_LIST, FILTER_SANITIZE_SPECIAL_CHARS);
        $post_external_whitelist_url = filter_input(INPUT_POST, self::SAI_LIST_EXTERNAL_URL, FILTER_SANITIZE_SPECIAL_CHARS);

        if ($post_whitelist !== null || $post_external_whitelist_url !== null) {
            if ($post_whitelist !== false && strpos($post_whitelist, $this->user_ip) !== false) {
                $ip_on_whitelist = true;
            }

            if ($post_external_whitelist_url !== false) {
                $external_whitelist = $this->getExternalIpWhitelist($post_external_whitelist_url);
                $is_ip_on_external_whitelist = $this->isUserIpInWhitelist($this->user_ip, $external_whitelist);

                if ($is_ip_on_external_whitelist) {
                    $ip_on_external_whitelist = true;
                }
            }

            if ($ip_on_whitelist || $ip_on_external_whitelist) {
                echo sprintf('<div class="notice notice-success"><p><strong>%s:</strong> %s</p></div>',
                    __('Done', 'secure-admin-ip'),
                    __('Settings saved successfully!', 'secure-admin-ip')
                );

                if ($post_whitelist !== false) {
                    $this->whitelist = $post_whitelist;
                    update_option(self::SAI_LIST, $post_whitelist);
                }

                if ($post_external_whitelist_url !== false) {
                    $this->external_whitelist_url = $post_external_whitelist_url;
                    update_option(self::SAI_LIST_EXTERNAL_URL, $post_external_whitelist_url);
                }
            } else {
                echo sprintf('<div class="notice notice-error"><p><strong>%s:</strong> %s "%s" %s</p></div>',
                    __('Error', 'secure-admin-ip'),
                    __('Not saved, because your IP address', 'secure-admin-ip'),
                    $this->user_ip,
                    __('not found on the new whitelist!', 'secure-admin-ip')
                );
            }
        }
    }
}

SecureAdminIP::getInstance();
