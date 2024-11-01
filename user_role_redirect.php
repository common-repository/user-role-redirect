<?php
/*
 * Plugin Name: User Role Redirect
 * Plugin URI: https://wordpress.org/plugins/user-role-redirect
 * Description: Redirect users to different locations after logging in. Define a set of rules for specific users, user with specific roles, users with specific capabilities. Please go to Settings > User Role Redirect to set rules.
 * Version: 1.0
 * Author: Evincedev
 * Text Domain: user-role-redirect
 * License URI: https://www.gnu.org/licenses/gpl-3.0.html 
 * Author URI: https://evincedev.com/
 */


global $wpdb;
global $evdpl_db_addresses;
global $evdpl_version;

/*
 *  Name of the database table that will hold group information and moderator rules
 */
$evdpl_db_addresses = $wpdb->prefix . 'login_redirects';
$evdpl_version = '1.0';

// doing this so we can pass current user logging out since it is no longer active after logout
if (!function_exists('wp_logout')) :

    /**
     * Log the current user out.
     *
     */
    function wp_logout() {
        $current_user = wp_get_current_user();
        wp_destroy_current_session();
        wp_clear_auth_cookie();
        wp_set_current_user(0);

        /**
         * Fires after a user is logged-out.
         *
         */
        do_action('wp_logout', $current_user);
    }

endif;

// Some helper functions, all "public static" in PHP5 land
class evdplRedirectFunctionCollection {

    static function evdpl_get_settings($setting = false) {
        $evdpl_settings = array();

        /*
         * Allow a POST or GET "redirect_to" variable to take precedence over settings within the plugin
         */
        $evdpl_settings['evdpl_allow_post_redirect_override'] = false;

        /*
         * Allow a POST or GET logout "redirect_to" variable to take precedence over settings within the plugin
         */
        $evdpl_settings['evdpl_allow_post_redirect_override_logout'] = false;

        $evdpl_settings_from_options_table = evdplRedirectFunctionCollection::evdpl_get_settings_from_options_table();

        /*
         * Merge the default settings with the settings form the database
         * Limit the settings in case there are ones from the database that are old
         */
        foreach ($evdpl_settings as $setting_name => $setting_value) {
            if (isset($evdpl_settings_from_options_table[$setting_name])) {
                $evdpl_settings[$setting_name] = $evdpl_settings_from_options_table[$setting_name];
            }
        }

        if (!$setting) {
            return $evdpl_settings;
        }

        if ($setting && isset($evdpl_settings[$setting])) {
            return $evdpl_settings[$setting];
        }

        return false;
    }

    static function evdpl_get_settings_from_options_table() {
        return get_option('evdpl_settings', array());
    }

    static function evdpl_set_setting($setting = false, $value = false) {
        if ($setting) {
            $current_settings = evdplRedirectFunctionCollection::evdpl_get_settings();
            if ($current_settings) {
                $current_settings[$setting] = $value;
                update_option('evdpl_settings', $current_settings);
            }
        }
    }

    /*
     * This function is necessary to support the use case where someone was previously logged in     */

    static function evdpl_redirect_current_user_can($capability, $current_user) {
        global $wpdb;

        $roles = get_option($wpdb->prefix . 'user_roles');
        $user_roles = $current_user->{$wpdb->prefix . 'capabilities'};
        $user_roles = array_keys($user_roles, true);
        $role = $user_roles[0];
        $capabilities = $roles[$role]['capabilities'];

        if (in_array($capability, array_keys($capabilities, true))) {
            // check array keys of capabilities for match against requested capability
            return true;
        }

        return false;
    }

    /*
     * A function to return the value mapped to a particular variable
     */

    static function evdpl_get_variable($variable, $user) {
        $variable_value = apply_filters('evdpl_replace_variable', false, $variable, $user);
        if (!$variable_value) {
            /*
             * Return the permalink of the post ID
             */
            if (0 === strpos($variable, 'postid-')) {
                $post_id = str_replace('postid-', '', $variable);
                $permalink = get_permalink($post_id);
                if ($permalink) {
                    $variable_value = $permalink;
                }
            } else {
                switch ($variable) {
                    /*
                     *  Returns the current user's username (only use this if you know they're logged in)
                     */
                    case 'username':
                        $variable_value = rawurlencode($user->user_login);
                        break;
                    /*
                     * Returns the current user's author slug aka nickname as used in URLs                    
                     * sanitize_title should not be required here since it was already done on insert
                     */
                    case 'userslug':
                        $variable_value = $user->user_nicename;
                        break;
                    /*
                     * Returns the URL of the WordPress files; see http://codex.wordpress.org/Function_Reference/network_site_url
                     */
                    case 'siteurl':
                        $variable_value = network_site_url();
                        break;
                    /*
                     * Returns the URL of the site, possibly different from where the WordPress files are; see http://codex.wordpress.org/Function_Reference/network_home_url
                     */
                    case 'homeurl':
                        $variable_value = network_home_url();
                        break;
                    /*
                     * Returns the login referrer in order to redirect back to the same page
                     * Note that this will not work if the referrer is the same as the login processor (otherwise in a standard setup you'd redirect to the login form)
                     */
                    case 'http_referer':
                        $http_referer_parts = parse_url($_SERVER['HTTP_REFERER']);
                        if ($_SERVER['REQUEST_URI'] != $http_referer_parts['path']) {
                            $variable_value = $_SERVER['HTTP_REFERER'];
                        } else {
                            $variable_value = '';
                        }
                        break;
                    default:
                        $variable_value = '';
                        break;
                }
            }
        }

        return $variable_value;
    }

    /*
     * Replaces the syntax [variable]variable_name[/variable] with whatever has been mapped to the variable_name in the evdpl_get_variable function
     */

    static function evdpl_replace_variable($string, $user) {
        preg_match_all("/\[variable\](.*?)\[\/variable\]/is", $string, $out);

        if (!empty($out[0])) {
            foreach ($out[0] as $instance => $full_match) {
                $replaced_variable = evdplRedirectFunctionCollection::evdpl_get_variable($out[1][$instance], $user);
                $string = str_replace($full_match, $replaced_variable, $string);
            }
        }

        return $string;
    }

    static function evdpl_trigger_allowed_host($url) {
        $url_parsed = parse_url($url);
        if (isset($url_parsed['host'])) {
            $evdpl_allowed_hosts[] = $url_parsed['host'];
            add_filter('allowed_redirect_hosts', function ($hosts) use ($evdpl_allowed_hosts) {
                return array_merge($hosts, $evdpl_allowed_hosts);
            });
        }
    }

}

/*
 * Functions specific to logout redirecting
 */

class evdplLogoutFunctionCollection {

    static function evdpl_logout_redirect($current_user) {
        $evdpl_allow_post_redirect_override_logout = evdplRedirectFunctionCollection::evdpl_get_settings('evdpl_allow_post_redirect_override_logout');

        $requested_redirect_to = !empty(esc_url($_REQUEST['redirect_to'])) ? esc_url($_REQUEST['redirect_to']) : false;

        if (!$requested_redirect_to || !$evdpl_allow_post_redirect_override_logout) {
            $evdpl_url = evdplLogoutFunctionCollection::evdpl_get_redirect_url($current_user, $requested_redirect_to);

            if ($evdpl_url) {
                wp_redirect($evdpl_url);
                die();
            }
        }
    }

    static function evdpl_logout_redirect_2($redirect_to, $requested_redirect_to, $current_user) {
        $evdpl_allow_post_redirect_override_logout = evdplRedirectFunctionCollection::evdpl_get_settings('evdpl_allow_post_redirect_override_logout');

        $requested_redirect_to = !empty($requested_redirect_to) ? $requested_redirect_to : false;

        if (!$requested_redirect_to || !$evdpl_allow_post_redirect_override_logout) {
            $evdpl_url = evdplLogoutFunctionCollection::evdpl_get_redirect_url($current_user, $requested_redirect_to);

            if ($evdpl_url) {
                evdplRedirectFunctionCollection::evdpl_trigger_allowed_host($evdpl_url);
                $redirect_to = $evdpl_url;
            }
        }

        return $redirect_to;
    }

    /*
     * Get the logout redirect URL according to defined rules
     * Functionality for user-, role-, and capability-specific redirect rules is available
     * Note that only the "all other users" redirect URL is currently implemented in the UI
     */

    static function evdpl_get_redirect_url($user, $requested_redirect_to) {
        global $wpdb, $evdpl_db_addresses;

        $redirect_to = false;

        // Check for an extended custom redirect rule
        $evdpl_custom_redirect = apply_filters('evdpl_before_user_logout', false, $requested_redirect_to, $user);

        if ($evdpl_custom_redirect) {
            return evdplRedirectFunctionCollection::evdpl_replace_variable($evdpl_custom_redirect, $user);
        }

        /*
         * Check for a redirect rule for this user
         */
        $evdpl_user = $wpdb->get_var('SELECT evdpl_url_logout FROM ' . $evdpl_db_addresses .
                ' WHERE evdpl_type = \'user\' AND evdpl_value = \'' . $user->user_login . '\' LIMIT 1');

        if ($evdpl_user) {
            return evdplRedirectFunctionCollection::evdpl_replace_variable($evdpl_user, $user);
        }

        /*
         * Check for an extended custom redirect rule
         */
        $evdpl_custom_redirect = apply_filters('evdpl_before_role_logout', false, $requested_redirect_to, $user);

        if ($evdpl_custom_redirect) {
            return evdplRedirectFunctionCollection::evdpl_replace_variable($evdpl_custom_redirect, $user);
        }

        /*
         * Check for a redirect rule that matches this user's role
         */
        $evdpl_roles = $wpdb->get_results('SELECT evdpl_value, evdpl_url_logout FROM ' . $evdpl_db_addresses .
                ' WHERE evdpl_type = \'role\'', OBJECT);

        if ($evdpl_roles) {
            foreach ($evdpl_roles as $evdpl_role) {
                if ('' != $evdpl_role->evdpl_url_logout && isset($user->{$wpdb->prefix . 'capabilities'}[$evdpl_role->evdpl_value])) {
                    return evdplRedirectFunctionCollection::evdpl_replace_variable($evdpl_role->evdpl_url_logout, $user);
                }
            }
        }

        /*
         * Check for an extended custom redirect rule
         */
        $evdpl_custom_redirect = apply_filters('evdpl_before_capability_logout', false, $requested_redirect_to, $user);
        if ($evdpl_custom_redirect) {
            return evdplRedirectFunctionCollection::evdpl_replace_variable($evdpl_custom_redirect, $user);
        }

        /*
         * Check for a redirect rule that matches this user's capability
         */
        $evdpl_levels = $wpdb->get_results('SELECT evdpl_value, evdpl_url_logout FROM ' . $evdpl_db_addresses .
                ' WHERE evdpl_type = \'level\' ORDER BY evdpl_order, evdpl_value', OBJECT);

        if ($evdpl_levels) {
            foreach ($evdpl_levels as $evdpl_level) {
                if ('' != $evdpl_level->evdpl_url_logout && evdplRedirectFunctionCollection::evdpl_redirect_current_user_can($evdpl_level->evdpl_value, $user)) {
                    return evdplRedirectFunctionCollection::evdpl_replace_variable($evdpl_level->evdpl_url_logout, $user);
                }
            }
        }

        /*
         * Check for an extended custom redirect rule
         */
        $evdpl_custom_redirect = apply_filters('evdpl_before_fallback_logout', false, $requested_redirect_to, $user);
        if ($evdpl_custom_redirect) {
            return evdplRedirectFunctionCollection::evdpl_replace_variable($evdpl_custom_redirect, $user);
        }

        /*
         * If none of the above matched, look for a rule to apply to all users
         */
        $evdpl_all = $wpdb->get_var('SELECT evdpl_url_logout FROM ' . $evdpl_db_addresses .
                ' WHERE evdpl_type = \'all\' LIMIT 1');

        if ($evdpl_all) {
            return evdplRedirectFunctionCollection::evdpl_replace_variable($evdpl_all, $user);
        }

        /*
         * No rules matched or existed, so just send them to the WordPress admin panel as usual
         */
        return $redirect_to;
    }

}

/*
 *  Functions for redirecting post-registration
 */

class evdplRedirectPostRegistration {

    static function evdpl_post_registration_wrapper($requested_redirect_to) {
        /*
          Some limitations:
          - Not yet implemented but possible: toggle whether to allow a GET or POST override of the redirect_to variable (currently it is "yes")
          - Not yet possible: Username-customized page, since the WordPress hook is implemented pre-registration, not post-registration
         */

        $evdpl_url = evdplRedirectPostRegistration::evdpl_get_registration_redirect_url($requested_redirect_to);
        if ($evdpl_url) {
            evdplRedirectFunctionCollection::evdpl_trigger_allowed_host($evdpl_url);

            return $evdpl_url;
        }

        return $requested_redirect_to;
    }

    // Looks up the redirect URL, if any
    static function evdpl_get_registration_redirect_url($requested_redirect_to) {
        global $wpdb, $evdpl_db_addresses;

        $redirect_to = false;

        $evdpl_all = $wpdb->get_var('SELECT evdpl_url FROM ' . $evdpl_db_addresses .
                ' WHERE evdpl_type = \'register\' LIMIT 1');

        if ($evdpl_all) {
            $redirect_to = evdplRedirectFunctionCollection::evdpl_replace_variable($evdpl_all, false);

            return $redirect_to;
        }

        // No rule exists
        return $redirect_to;
    }

}

function evdpl_redirect_wrapper($redirect_to, $requested_redirect_to, $user) {
    $evdpl_allow_post_redirect_override = evdplRedirectFunctionCollection::evdpl_get_settings('evdpl_allow_post_redirect_override');

    if (empty($user)) {
        $user = wp_get_current_user();
    }
    if (!isset($user->user_login))
        return $redirect_to;

    if ((admin_url() == $redirect_to && $evdpl_allow_post_redirect_override) || !$evdpl_allow_post_redirect_override) {
        $evdpl_url = evdpl_redirect_to_front_page($redirect_to, $requested_redirect_to, $user);
        if ($evdpl_url) {
            evdplRedirectFunctionCollection::evdpl_trigger_allowed_host($evdpl_url);

            return $evdpl_url;
        }
    }

    return $redirect_to;
}

/*
 * Woocommerce Login Redirect
 */

function evdpl_woocommerce_redirect_wrapper($redirect_to, $user) {
    $evdpl_allow_post_redirect_override = evdplRedirectFunctionCollection::evdpl_get_settings('evdpl_allow_post_redirect_override');

    if (!isset($user->user_login))
        return $redirect_to;

    $requested_redirect_to = '';
    if ((admin_url() == $redirect_to && $evdpl_allow_post_redirect_override) || !$evdpl_allow_post_redirect_override) {
        $evdpl_url = evdpl_redirect_to_front_page($redirect_to, $requested_redirect_to, $user);
        if ($evdpl_url) {
            evdplRedirectFunctionCollection::evdpl_trigger_allowed_host($evdpl_url);

            return $evdpl_url;
        }
    }

    return $redirect_to;
}

/*
 * Woocommerce Registration Redirect
 */

function evdpl_woocommerce_registration_redirect_wrapper($requested_redirect_to) {
    $evdpl_url = evdplRedirectPostRegistration::evdpl_get_registration_redirect_url($requested_redirect_to);
    if ($evdpl_url) {
        evdplRedirectFunctionCollection::evdpl_trigger_allowed_host($evdpl_url);

        return $evdpl_url;
    }

    return $requested_redirect_to;
}

function evdpl_redirect_to_front_page($redirect_to, $requested_redirect_to, $user) {
    global $wpdb, $evdpl_db_addresses;

    // Check for an extended custom redirect rule
    $evdpl_custom_redirect = apply_filters('evdpl_before_user', false, $redirect_to, $requested_redirect_to, $user);
    if ($evdpl_custom_redirect) {
        $redirect_to = evdplRedirectFunctionCollection::evdpl_replace_variable($evdpl_custom_redirect, $user);

        return $redirect_to;
    }

    // Check for a redirect rule for this user
    $evdpl_user = $wpdb->get_var('SELECT evdpl_url FROM ' . $evdpl_db_addresses .
            ' WHERE evdpl_type = \'user\' AND evdpl_value = \'' . $user->user_login . '\' LIMIT 1');

    if ($evdpl_user) {
        $redirect_to = evdplRedirectFunctionCollection::evdpl_replace_variable($evdpl_user, $user);

        return $redirect_to;
    }

    // Check for an extended custom redirect rule
    $evdpl_custom_redirect = apply_filters('evdpl_before_role', false, $redirect_to, $requested_redirect_to, $user);
    if ($evdpl_custom_redirect) {
        $redirect_to = evdplRedirectFunctionCollection::evdpl_replace_variable($evdpl_custom_redirect, $user);

        return $redirect_to;
    }

    // Check for a redirect rule that matches this user's role
    $evdpl_roles = $wpdb->get_results('SELECT evdpl_value, evdpl_url FROM ' . $evdpl_db_addresses .
            ' WHERE evdpl_type = \'role\'', OBJECT);

    if ($evdpl_roles) {
        foreach ($evdpl_roles as $evdpl_role) {
            if ('' != $evdpl_role->evdpl_url && isset($user->{$wpdb->prefix . 'capabilities'}[$evdpl_role->evdpl_value])) {
                $redirect_to = evdplRedirectFunctionCollection::evdpl_replace_variable($evdpl_role->evdpl_url, $user);

                return $redirect_to;
            }
        }
    }

    /*
     * Check for an extended custom redirect rule
     */
    $evdpl_custom_redirect = apply_filters('evdpl_before_capability', false, $redirect_to, $requested_redirect_to, $user);
    if ($evdpl_custom_redirect) {
        $redirect_to = evdplRedirectFunctionCollection::evdpl_replace_variable($evdpl_custom_redirect, $user);

        return $redirect_to;
    }

    /*
     * Check for a redirect rule that matches this user's capability
     */
    $evdpl_levels = $wpdb->get_results('SELECT evdpl_value, evdpl_url FROM ' . $evdpl_db_addresses .
            ' WHERE evdpl_type = \'level\' ORDER BY evdpl_order, evdpl_value', OBJECT);

    if ($evdpl_levels) {
        foreach ($evdpl_levels as $evdpl_level) {
            if ('' != $evdpl_level->evdpl_url && evdplRedirectFunctionCollection::evdpl_redirect_current_user_can($evdpl_level->evdpl_value, $user)) {
                $redirect_to = evdplRedirectFunctionCollection::evdpl_replace_variable($evdpl_level->evdpl_url, $user);

                return $redirect_to;
            }
        }
    }

    /*
     * Check for an extended custom redirect rule
     */
    $evdpl_custom_redirect = apply_filters('evdpl_before_fallback', false, $redirect_to, $requested_redirect_to, $user);
    if ($evdpl_custom_redirect) {
        $redirect_to = evdplRedirectFunctionCollection::evdpl_replace_variable($evdpl_custom_redirect, $user);

        return $redirect_to;
    }

    /*
     * If none of the above matched, look for a rule to apply to all users
     */
    $evdpl_all = $wpdb->get_var('SELECT evdpl_url FROM ' . $evdpl_db_addresses .
            ' WHERE evdpl_type = \'all\' LIMIT 1');

    if ($evdpl_all) {
        $redirect_to = evdplRedirectFunctionCollection::evdpl_replace_variable($evdpl_all, $user);

        return $redirect_to;
    }

    /*
     * No rules matched or existed, so just send them to the WordPress admin panel as usual
     */
    return $redirect_to;
}

/* Typically this function is used in templates, similarly to the wp_register function
 * It returns a link to the administration panel or the one that was custom defined
 * If no user is logged in, it returns the "Register" link
 */

function evdpl_register($before = '<li>', $after = '</li>', $give_echo = true) {
    global $current_user;

    if (!is_user_logged_in()) {
        if (get_option('users_can_register'))
            $link = $before . '<a href="' . site_url('wp-login.php?action=register', 'login') . '">' . __('Register', 'evdpl-login-redirect') . '</a>' . $after;
        else
            $link = '';
    } else {
        $link = $before . '<a href="' . evdpl_redirect_to_front_page('', '', $current_user) . '">' . __('Site Admin', 'evdpl-login-redirect') . '</a>' . $after;
        ;
    }

    if ($give_echo) {
        echo esc_html($link);
    } else {
        return esc_html($link);
    }
}

if (is_admin()) {

    /*
     * Returns all option HTML for all usernames in the system except for those supplied to it
     */

    function evdpl_returnusernames($exclude) {
        global $wpdb;

        $evdpl_returnusernames = '';

        /*
         * Build the "not in" part of the MySQL query
         */
        $exclude_users = "'" . implode("','", $exclude) . "'";

        $evdpl_userresults = $wpdb->get_results('SELECT user_login FROM ' . $wpdb->users . ' WHERE user_login NOT IN (' . $exclude_users . ') ORDER BY user_login', ARRAY_N);

        /*
         *  Built the option HTML
         */
        if ($evdpl_userresults) {
            foreach ($evdpl_userresults as $evdpl_userresult) {
                $evdpl_returnusernames .= '<option value="' . $evdpl_userresult[0] . '">' . $evdpl_userresult[0] . '</option>';
            }
        }

        return $evdpl_returnusernames;
    }

    /*
     * Returns all roles in the system
     */

    function evdpl_returnrolenames() {
        global $wp_roles;

        $evdpl_returnrolenames = array();
        foreach (array_keys($wp_roles->role_names) as $evdpl_rolename) {
            $evdpl_returnrolenames[$evdpl_rolename] = $evdpl_rolename;
        }

        return $evdpl_returnrolenames;
    }

    /*
     * Returns option HTML for all roles in the system, except for those supplied to it
     */

    function evdpl_returnroleoptions($exclude) {

        /*
         * Relies on a function that just returns the role names
         */
        $evdpl_rolenames = evdpl_returnrolenames($exclude);

        $evdpl_returnroleoptions = '';

        /*
         * Build the option HTML
         */
        if ($evdpl_rolenames) {
            foreach ($evdpl_rolenames as $evdpl_rolename) {
                if (!isset($exclude[$evdpl_rolename])) {
                    $evdpl_returnroleoptions .= '<option value="' . $evdpl_rolename . '">' . $evdpl_rolename . '</option>';
                }
            }
        }

        return $evdpl_returnroleoptions;
    }

    /*
     * Returns all level names in the system
     */

    function evdpl_returnlevelnames() {
        global $wp_roles;

        $evdpl_returnlevelnames = array();

        foreach ($wp_roles->roles as $wp_role) {
            $evdpl_returnlevelnames = array_unique((array_merge($evdpl_returnlevelnames, array_keys($wp_role['capabilities']))));
        }

        sort($evdpl_returnlevelnames);

        return $evdpl_returnlevelnames;
    }

    /*
     *  Returns option HTML for all levels in the system, except for those supplied to it
     */

    function evdpl_returnleveloptions($exclude) {

        // Relies on a function that just returns the level names
        $evdpl_levelnames = evdpl_returnlevelnames();

        $evdpl_returnleveloptions = '';

        // Build the option HTML
        foreach ($evdpl_levelnames as $evdpl_levelname) {
            if (!isset($exclude[$evdpl_levelname])) {
                $evdpl_returnleveloptions .= '<option value="' . $evdpl_levelname . '">' . $evdpl_levelname . '</option>';
            }
        }

        return $evdpl_returnleveloptions;
    }

    /*
     *  Wraps the return message in an informational div
     */

    function evdpl_format_return($innerMessage) {
        return '<div id="message" class="updated fade">' . $innerMessage . '</div>';
    }

    /*
     * Validates adds and edits to make sure that the user / role / level
     */

    function evdpl_validate_submission($typeValue, $type) {
        $success = true;
        $error_message = '';

        if ($type == 'user') {
            if (!username_exists($typeValue)) {
                $success = false;
                $error_message = '<p><strong>****' . __('ERROR: Non-existent username submitted ', 'evdpl-login-redirect') . '****</strong></p>';
            }
        } elseif ($type == 'role') {
            // Get a list of roles in the system so that we can verify that a valid role was submitted
            $evdpl_existing_rolenames = evdpl_returnrolenames();
            if (!isset($evdpl_existing_rolenames[$typeValue])) {
                $success = false;
                $error_message = '<p><strong>****' . __('ERROR: Non-existent role submitted ', 'evdpl-login-redirect') . '****</strong></p>';
            }
        } elseif ($type == 'level') {
            // Get a list of levels in the system so that we can verify that a valid level was submitted
            $evdpl_existing_levelnames = array_flip(evdpl_returnlevelnames());

            if (!isset($evdpl_existing_levelnames[$typeValue])) {
                $success = false;
                $error_message = '<p><strong>****' . __('ERROR: Non-existent level submitted ', 'evdpl-login-redirect') . '****</strong></p>';
            }
        }

        return array('success' => $success, 'error_message' => $error_message);
    }

    /*
     * Validates deletions by simply making sure that the entry isn't empty
     */

    function evdpl_validate_deletion($typeValue, $type) {
        $success = true;
        $error_message = '';

        if (trim($typeValue) == '') {
            $success = false;
            $error_message = '<p><strong>****' . sprintf(__('ERROR: Empty %s submitted ', 'evdpl-login-redirect'), $type) . '****</strong></p>';
        }

        return array('success' => $success, 'error_message' => $error_message);
    }

    /*
     * Processes adding a new redirect rule
     */

    function evdpl_submit_rule($typeValue, $address, $address_logout, $order = 0, $type) {
        global $wpdb, $evdpl_db_addresses;

        // Ensure that the request came from the back-end
        check_admin_referer('evdpl_' . $type . '_submit');

        $evdpl_process_submit = '';

        if ($typeValue && ($address || $address_logout)) {
            // Validation depending on the type
            $validation = evdpl_validate_submission($typeValue, $type);
            $evdpl_submit_success = $validation['success'];
            $evdpl_process_submit = $validation['error_message'];

            if ($evdpl_submit_success) {

                // Insert a new rule

                $order = abs(intval($order));
                if ($order > 99) {
                    $order = 0;
                }

                $evdpl_update_rule = $wpdb->insert($evdpl_db_addresses,
                        array(
                            'evdpl_url' => $address,
                            'evdpl_url_logout' => $address_logout,
                            'evdpl_type' => $type,
                            'evdpl_value' => $typeValue,
                            'evdpl_order' => $order
                        ),
                        array('%s', '%s', '%s', '%s', '%d')
                );

                if (!$evdpl_update_rule) {
                    $evdpl_submit_success = false;
                    $evdpl_process_submit = '<p><strong>****' . sprintf(__('ERROR: Unknown error adding %s-specific redirect for %s %s', 'evdpl-login-redirect'), $type, $type, $typeValue) . '****</strong></p>';
                }
            }

            if ($evdpl_submit_success) {
                $evdpl_process_submit = '<p>' . sprintf(__('Successfully added %s-specific redirect rule for %s', 'evdpl-login-redirect'), $type, $typeValue) . '</p>';
            }
        }

        return evdpl_format_return($evdpl_process_submit);
    }

    /*
     * Edits a redirect rule
     */

    function evdpl_edit_rule($typeValue, $address, $address_logout, $order = 0, $type) {
        global $wpdb, $evdpl_db_addresses;

        // Ensure that the request came from the back-end
        check_admin_referer('evdpl_' . $type . '_edit');

        if ($typeValue && ($address || $address_logout)) {
            // Validation depending on the type
            $validation = evdpl_validate_submission($typeValue, $type);
            $evdpl_submit_success = $validation['success'];
            $evdpl_process_submit = $validation['error_message'];

            if ($evdpl_submit_success) {
                // Edit the rule

                $order = abs(intval($order));
                if ($order > 99) {
                    $order = 0;
                }

                $evdpl_update_rule = $wpdb->update($evdpl_db_addresses,
                        array(
                            'evdpl_url' => $address,
                            'evdpl_url_logout' => $address_logout,
                            'evdpl_order' => $order
                        ),
                        array(
                            'evdpl_value' => $typeValue,
                            'evdpl_type' => $type
                        ),
                        array('%s', '%s', '%d'),
                        array('%s', '%s')
                );

                if (!$evdpl_update_rule) {
                    $evdpl_submit_success = false;
                    $evdpl_process_submit = '<p><strong>****' . sprintf(__('ERROR: Unknown error editing %s-specific redirect for %s %s', 'evdpl-login-redirect'), $type, $type, $typeValue) . '****</strong></p>';
                }
            }

            if ($evdpl_submit_success) {
                $evdpl_process_submit = '<p>' . sprintf(__('Successfully edited %s-specific redirect rule for %s', 'evdpl-login-redirect'), $type, $typeValue) . '</p>';
            }
        }

        return evdpl_format_return($evdpl_process_submit);
    }

    /*
     * Deletes a redirect rule
     */

    function evdpl_delete_rule($typeValue, $type) {
        global $wpdb, $evdpl_db_addresses;

        /*
         * Ensure that the request came from the back-end
         */
        check_admin_referer('evdpl_' . $type . '_edit');

        if ($typeValue) {
            /*
             * Validation depending on the type
             */
            $validation = evdpl_validate_deletion($typeValue, $type);
            $evdpl_submit_success = $validation['success'];
            $evdpl_process_submit = $validation['error_message'];

            if ($evdpl_submit_success) {
                $evdpl_update_rule = $wpdb->query("DELETE FROM `$evdpl_db_addresses` WHERE `evdpl_value` = '$typeValue' AND `evdpl_type` = '$type' LIMIT 1");

                if (!$evdpl_update_rule) {
                    $evdpl_submit_success = false;
                    $evdpl_process_submit = '<p><strong>****' . sprintf(__('ERROR: Unknown error deleting %s-specific redirect for %s %s', 'evdpl-login-redirect'), $type, $type, $typeValue) . '****</strong></p>';
                }
            }

            if ($evdpl_submit_success) {
                $evdpl_process_submit = '<p>' . sprintf(__('Successfully deleted %s-specific redirect rule for %s', 'evdpl-login-redirect'), $type, $typeValue) . '</p>';
            }
        }

        return evdpl_format_return($evdpl_process_submit);
    }

    function evdpl_submit_all($update_or_delete, $address, $address_logout) {
        global $wpdb, $evdpl_db_addresses;

        /*
         * Ensure that the request came from the back-end
         */
        check_admin_referer('evdpl_allupdatesubmit');

        $address = trim($address);
        $address_logout = trim($address_logout);

        $evdpl_process_submit = '<div id="message" class="updated fade">';

        $evdpl_process_close = '</div>';

        /*
         * Process the rule changes
         */
        if ($update_or_delete == 'delete') {
            $all_others_rule = $wpdb->get_row("SELECT * FROM $evdpl_db_addresses WHERE 'evdpl_type' = 'all");
            $update = $wpdb->update(
                    $evdpl_db_addresses,
                    array('evdpl_url' => '', 'evdpl_url_logout' => ''),
                    array('evdpl_type' => 'all')
            );

            if ($update === false) {
                $evdpl_process_submit .= '<p><strong>****' . __('ERROR: Unknown database problem removing URL for &#34;all other users&#34; ', 'evdpl-login-redirect') . '****</strong></p>';
            } else {
                $evdpl_process_submit .= '<p>' . __('Successfully removed URL for &#34;all other users&#34; ', 'evdpl-login-redirect') . '</p>';
            }
        } elseif ($update_or_delete == 'update') {
            $all_others_rule = $wpdb->get_row("SELECT * FROM $evdpl_db_addresses WHERE 'evdpl_type' = 'all");
            if ($all_others_rule) {
                $update = $wpdb->update(
                        $evdpl_db_addresses,
                        array('evdpl_url' => $address, 'evdpl_url_logout' => $address_logout),
                        array('evdpl_type' => 'all')
                );
            } else {
                $update = $wpdb->insert(
                        $evdpl_db_addresses,
                        array('evdpl_type' => 'all', 'evdpl_url' => $address, 'evdpl_url_logout' => $address_logout)
                );
            }

            if ($update === false) {
                $evdpl_process_submit .= '<p><strong>****' . __('ERROR: Unknown database problem updating URL for &#34;all other users&#34; ', 'evdpl-login-redirect') . '****</strong></p>';
            } else {
                $evdpl_process_submit .= '<p>' . __('Successfully updated URL for &#34;all other users&#34;', 'evdpl-login-redirect') . '</p>';
            }
        }

        $evdpl_process_submit .= $evdpl_process_close;

        return $evdpl_process_submit;
    }

    function evdpl_submit_register($update_or_delete, $address) {
        global $wpdb, $evdpl_db_addresses;

        check_admin_referer('evdpl_registerupdatesubmit');

        $address = trim($address);

        $evdpl_process_submit = '<div id="message" class="updated fade">';

        $evdpl_process_close = '</div>';

        /*
         * Process the rule changes
         */
        if ($update_or_delete == 'delete') {
            $update = $wpdb->update(
                    $evdpl_db_addresses,
                    array('evdpl_url' => ''),
                    array('evdpl_type' => 'register')
            );

            if ($update === false) {
                $evdpl_process_submit .= '<p><strong>****' . __('ERROR: Unknown database problem removing URL for &#34;post-registration&#34; ', 'evdpl-login-redirect') . '****</strong></p>';
            } else {
                $evdpl_process_submit .= '<p>' . __('Successfully removed URL for &#34;post-registration&#34; ', 'evdpl-login-redirect') . '</p>';
            }
        } elseif ($update_or_delete == 'update') {
            $update = $wpdb->update(
                    $evdpl_db_addresses,
                    array('evdpl_url' => $address),
                    array('evdpl_type' => 'register')
            );

            if ($update === false) {
                $evdpl_process_submit .= '<p><strong>****' . __('ERROR: Unknown database problem updating URL for &#34;post-registration&#34; ', 'evdpl-login-redirect') . '****</strong></p>';
            } else {
                $evdpl_process_submit .= '<p>' . __('Successfully updated URL for &#34;post-registration&#34;', 'evdpl-login-redirect') . '</p>';
            }
        }

        $evdpl_process_submit .= $evdpl_process_close;

        return $evdpl_process_submit;
    }

    /*
     * Process submitted information to update plugin settings
     */

    function evdpl_submit_settings() {
        check_admin_referer('settings');

        $evdpl_settings = evdplRedirectFunctionCollection::evdpl_get_settings();
        foreach ($evdpl_settings as $setting_name => $setting_value) {
            if (isset($_POST[$setting_name])) {
                $evdpl_settings[$setting_name] = sanitize_text_field($_POST[$setting_name]);
            }
        }
        update_option('evdpl_settings', $evdpl_settings);
        $evdpl_process_submit = '<div id="message" class="updated fade">';
        $evdpl_process_submit .= '<p>' . __('Successfully updated plugin settings', 'evdpl-login-redirect') . '</p>';
        $evdpl_process_submit .= '</div>';

        return $evdpl_process_submit;
    }

    /*
     * Settings > User Role Redirect redirects menu page
     */

    function evdpl_optionsmenu() {
        global $wpdb, $evdpl_db_addresses;

        $evdpl_process_submit = '';

        if (!empty($_POST)) {
            // Process submitted information to update redirect rules
            if (isset($_POST['evdpl_username_submit'])) {
                $evdpl_process_submit = evdpl_submit_rule(sanitize_text_field($_POST['evdpl_username']), sanitize_text_field($_POST['evdpl_username_address']), sanitize_text_field($_POST['evdpl_username_logout']), 0, 'user');
            } elseif (isset($_POST['evdpl_username_edit'])) {
                $evdpl_process_submit = evdpl_edit_rule(sanitize_text_field($_POST['evdpl_username']), sanitize_text_field($_POST['evdpl_username_address']), sanitize_text_field($_POST['evdpl_username_logout']), 0, 'user');
            } elseif (isset($_POST['evdpl_username_delete'])) {
                $evdpl_process_submit = evdpl_delete_rule(sanitize_text_field($_POST['evdpl_username']), 'user');
            } elseif (isset($_POST['evdpl_role_submit'])) {
                $evdpl_process_submit = evdpl_submit_rule(sanitize_text_field($_POST['evdpl_role']), sanitize_text_field($_POST['evdpl_role_address']), sanitize_text_field($_POST['evdpl_role_logout']), 0, 'role');
            } elseif (isset($_POST['evdpl_role_edit'])) {
                $evdpl_process_submit = evdpl_edit_rule(sanitize_text_field($_POST['evdpl_role']), sanitize_text_field($_POST['evdpl_role_address']), sanitize_text_field($_POST['evdpl_role_logout']), 0, 'role');
            } elseif (isset($_POST['evdpl_role_delete'])) {
                $evdpl_process_submit = evdpl_delete_rule(sanitize_text_field($_POST['evdpl_role']), 'role');
            } elseif (isset($_POST['evdpl_level_submit'])) {
                $evdpl_process_submit = evdpl_submit_rule(esc_attr($_POST['evdpl_level']), sanitize_text_field($_POST['evdpl_level_address']), sanitize_text_field($_POST['evdpl_level_logout']), sanitize_text_field($_POST['evdpl_level_order']), 'level');
            } elseif (isset($_POST['evdpl_level_edit'])) {
                $evdpl_process_submit = evdpl_edit_rule(sanitize_text_field($_POST['evdpl_level']), sanitize_text_field($_POST['evdpl_level_address']), sanitize_text_field($_POST['evdpl_level_logout']), sanitize_text_field($_POST['evdpl_level_order']), 'level');
            } elseif (isset($_POST['evdpl_level_delete'])) {
                $evdpl_process_submit = evdpl_delete_rule(sanitize_text_field($_POST['evdpl_level']), 'level');
            } elseif (isset($_POST['evdpl_allupdatesubmit'])) {
                $evdpl_process_submit = evdpl_submit_all('update', sanitize_text_field($_POST['evdpl_all']), sanitize_text_field($_POST['evdpl_all_logout']));
            } elseif (isset($_POST['evdpl_alldeletesubmit'])) {
                $evdpl_process_submit = evdpl_submit_all('delete', sanitize_text_field($_POST['evdpl_all']), sanitize_text_field($_POST['evdpl_all_logout']));
            } elseif (isset($_POST['evdpl_registerupdatesubmit'])) {
                $evdpl_process_submit = evdpl_submit_register('update', sanitize_text_field($_POST['evdpl_register']));
            } elseif (isset($_POST['evdpl_registerdeletesubmit'])) {
                $evdpl_process_submit = evdpl_submit_register('delete', sanitize_text_field($_POST['evdpl_register']));
            } elseif (isset($_POST['evdpl_settingssubmit'])) {
                $evdpl_process_submit = evdpl_submit_settings();
            }

            // Settings that can be updated
            $evdpl_settings = evdplRedirectFunctionCollection::evdpl_get_settings();
        }

        /*
         * Get the existing rules
         */
        $evdpl_rules = $wpdb->get_results('SELECT evdpl_type, evdpl_value, evdpl_url, evdpl_url_logout, evdpl_order FROM ' . $evdpl_db_addresses . ' ORDER BY evdpl_type, evdpl_order, evdpl_value', ARRAY_N);

        $evdpl_usernamevalues = '';
        $evdpl_rolevalues = '';
        $evdpl_levelvalues = '';
        $evdpl_usernames_existing = array();
        $evdpl_roles_existing = array();
        $evdpl_levels_existing = array();

        if ($evdpl_rules) {

            $i = 0;
            $i_user = 0;
            $i_role = 0;
            $i_level = 0;

            while ($i < count($evdpl_rules)) {

                list($evdpl_type, $evdpl_value, $evdpl_url, $evdpl_url_logout, $evdpl_order) = $evdpl_rules[$i];

                // Specific users
                if ($evdpl_type == 'user') {
                    $evdpl_usernamevalues .= '<form name="evdpl_username_edit_form[' . $i_user . ']" action="?page=' . basename(__FILE__) . '" method="post">';
                    $evdpl_usernamevalues .= '<tr>';
                    $evdpl_usernamevalues .= '<td class="row-heading"><p><input type="hidden" name="evdpl_username" value="' . htmlspecialchars(esc_attr($evdpl_value)) . '" /> ' . esc_attr($evdpl_value) . '</p></td>';
                    $evdpl_usernamevalues .= '<td>';
                    $evdpl_usernamevalues .= '<p><span class="input--title">' . __('Redirect to URL After Login', 'evdpl-login-redirect') . '</span><br /><input type="text" size="90" maxlength="500" name="evdpl_username_address" value="' . htmlspecialchars(esc_url($evdpl_url)) . '" /></p>';
                    $evdpl_usernamevalues .= '<p><span class="input--title">' . __('Redirect to URL After Logout', 'evdpl-login-redirect') . '</span><br /><input type="text" size="60" maxlength="500" name="evdpl_username_logout" value="' . htmlspecialchars(esc_url($evdpl_url_logout)) . '" /></p>';
                    $evdpl_usernamevalues .= '</td>';
                    $evdpl_usernamevalues .= '<td><p><br />';
                    $evdpl_usernamevalues .= '<input class="button button-primary" name="evdpl_username_edit" type="submit" value="' . __('Update', 'evdpl-login-redirect') . '" /> <input type="submit" class="button" name="evdpl_username_delete" value="' . __('Delete', 'evdpl-login-redirect') . '" />';
                    $evdpl_usernamevalues .= wp_nonce_field('evdpl_user_edit', '_wpnonce', true, false);
                    $evdpl_usernamevalues .= '</p class="widefat-btn"></td>';
                    $evdpl_usernamevalues .= '</tr>';
                    $evdpl_usernamevalues .= '</form>';

                    $evdpl_usernames_existing[] = esc_attr($evdpl_value);

                    ++$i_user;
                } elseif ($evdpl_type == 'role') {
                    $evdpl_rolevalues .= '<form name="evdpl_role_edit_form[' . $i_role . ']" action="?page=' . basename(__FILE__) . '" method="post">';
                    $evdpl_rolevalues .= '<tr>';
                    $evdpl_rolevalues .= '<td class="row-heading"><p><input type="hidden" name="evdpl_role" value="' . htmlspecialchars(esc_attr($evdpl_value)) . '" /> ' . esc_attr($evdpl_value) . '</p></td>';
                    $evdpl_rolevalues .= '<td>';
                    $evdpl_rolevalues .= '<p><span class="input--title">' . __('Redirect to URL After Login', 'evdpl-login-redirect') . '</span><br /><input type="text" size="90" maxlength="500" name="evdpl_role_address" value="' . htmlspecialchars(esc_url($evdpl_url)) . '" /></p>';
                    $evdpl_rolevalues .= '<p><span class="input--title">' . __('Redirect to URL After Logout', 'evdpl-login-redirect') . '</span><br /><input type="text" size="60" maxlength="500" name="evdpl_role_logout" value="' . htmlspecialchars(esc_url($evdpl_url_logout)) . '" /></p>';
                    $evdpl_rolevalues .= '</td>';
                    $evdpl_rolevalues .= '<td><p class="widefat-btn"><br />';
                    $evdpl_rolevalues .= '<input class="button button-primary" name="evdpl_role_edit" type="submit" value="' . __('Update', 'evdpl-login-redirect') . '" /> <input type="submit" class="button" name="evdpl_role_delete" value="' . __('Delete', 'evdpl-login-redirect') . '" />';
                    $evdpl_rolevalues .= wp_nonce_field('evdpl_role_edit', '_wpnonce', true, false);
                    $evdpl_rolevalues .= '</p></td>';
                    $evdpl_rolevalues .= '</tr>';
                    $evdpl_rolevalues .= '</form>';

                    $evdpl_roles_existing[$evdpl_value] = '';

                    ++$i_role;
                } elseif ($evdpl_type == 'level') {
                    $evdpl_levelvalues .= '<tr>';
                    $evdpl_levelvalues .= '<form name="evdpl_level_edit_form[' . $i_level . ']" action="?page=' . basename(__FILE__) . '" method="post">';
                    $evdpl_levelvalues .= '<td class="row-heading"><p><input type="hidden" name="evdpl_level" value="' . htmlspecialchars(esc_attr($evdpl_value)) . '" /> ' . esc_attr($evdpl_value) . '</p></td>';
                    $evdpl_levelvalues .= '<td>';
                    $evdpl_levelvalues .= '<p><span class="input--title">' . __('Redirect to URL After Login', 'evdpl-login-redirect') . '</span><br /><input type="text" size="90" maxlength="500" name="evdpl_level_address" value="' . htmlspecialchars(esc_url($evdpl_url)) . '" /></p>';
                    $evdpl_levelvalues .= '<p><span class="input--title">' . __('Redirect to URL After Logout', 'evdpl-login-redirect') . '</span><br /><input type="text" size="60" maxlength="500" name="evdpl_level_logout" value="' . htmlspecialchars(esc_url($evdpl_url_logout)) . '" /></p>';
                    $evdpl_levelvalues .= '</td>';
                    $evdpl_levelvalues .= '<td><p><span class="input--title">' . __('Order', 'evdpl-login-redirect') . '</span><br /><input name="evdpl_level_order" type="text" size="2" maxlength="2" value="' . $evdpl_order . '" class="evdpl_level_order saved_order"/></td>';
                    $evdpl_levelvalues .= '<td><p class="widefat-btn"><br />';
                    $evdpl_levelvalues .= '<input class="button button-primary" name="evdpl_level_edit" type="submit" value="' . __('Update', 'evdpl-login-redirect') . '" /><input type="submit" class="button" name="evdpl_level_delete" value="' . __('Delete', 'evdpl-login-redirect') . '" />';
                    $evdpl_levelvalues .= wp_nonce_field('evdpl_level_edit', '_wpnonce', true, false);
                    $evdpl_levelvalues .= '</p></td>';
                    $evdpl_levelvalues .= '</form>';
                    $evdpl_levelvalues .= '</tr>';

                    $evdpl_levels_existing[$evdpl_value] = '';

                    ++$i_level;
                } elseif ($evdpl_type == 'all') {
                    $evdpl_allvalue = esc_url($evdpl_url);
                    $evdpl_allvalue_logout = esc_url($evdpl_url_logout);
                } elseif ($evdpl_type == 'register') {
                    $evdpl_registervalue = esc_url($evdpl_url);
                }
                ++$i;
            }
        }
        ?>
        <div class="wrap">
            <h2><?php _e('Manage redirect rules', 'evdpl-login-redirect'); ?></h2>
            <?php print $evdpl_process_submit; ?>
            <p><?php _e('Define custom URLs to which different users, users with specific roles, users with specific levels, and all other users will be redirected upon login.', 'evdpl-login-redirect'); ?></p>
            <p><?php _e('Define a custom URL to which all users will be redirected upon logout', 'evdpl-login-redirect'); ?></p>

            <div class="section-pd specific--section">
                <h3><?php _e('Specific users', 'evdpl-login-redirect'); ?></h3>            
                <form name="evdpl_username_add_form" action="<?php print '?page=' . basename(__FILE__); ?>" method="post">                        
                    <table>                            
                        <tr>                            
                            <td class="row-heading">                        
                                <?php _e('Add:', 'evdpl-login-redirect'); ?>                         
                            </td>                        
                            <td>                        
                                <select name="evdpl_username">                            
                                    <option value="-1"><?php _e('Select a username', 'evdpl-login-redirect'); ?></option>                                
                                    <?php print evdpl_returnusernames($evdpl_usernames_existing); ?>                                    
                                </select>                                
                            </td>                            
                        </tr>                            
                        <tr>                                
                            <td class="row-heading"><?php _e('URL:', 'evdpl-login-redirect'); ?></td>                                
                            <td><input type="text" size="90" maxlength="500" name="evdpl_username_address"/></td>                            
                        </tr>                            
                        <tr>                                
                            <td class="row-heading"><?php _e('Logout URL:', 'evdpl-login-redirect'); ?></td>                                
                            <td><input type="text" size="90" maxlength="500" name="evdpl_username_logout"/></td>                            
                        </tr>
                        <tr>
                            <td></td>                                
                            <td>                                    
                                <p class="btn">                                        
                                    <input type="submit" class="button button-primary" name="evdpl_username_submit" value="<?php _e('Add username rule', 'evdpl-login-redirect'); ?>"/>                                        
                                    <?php wp_nonce_field('evdpl_user_submit'); ?>                                    
                                </p>                                
                            </td>                            
                        </tr>                        
                    </table>
                </form>
            </div>
            <?php
            if ($evdpl_usernamevalues) {
                print '<table class="widefat">';
                print $evdpl_usernamevalues;
                print '</table>';
            }
            ?>
            <hr />

            <div class="section-pd specific--section">
                <h3><?php _e('Specific roles', 'evdpl-login-redirect'); ?></h3>
                <form name="evdpl_role_add_form" action="<?php print '?page=' . basename(__FILE__); ?>" method="post">
                    <table>
                        <tr>
                            <td class="row-heading"><?php _e('Add:', 'evdpl-login-redirect'); ?></td>
                            <td>
                                <select name="evdpl_role">
                                    <option value="-1"><?php _e('Select a role', 'evdpl-login-redirect'); ?></option>
                                    <?php print evdpl_returnroleoptions($evdpl_roles_existing); ?>
                                </select>
                            </td>
                        </tr>
                        <tr>
                            <td class="row-heading"><?php _e('URL:', 'evdpl-login-redirect'); ?></td>
                            <td><input type="text" size="90" maxlength="500" name="evdpl_role_address"/></td>
                        </tr>
                        <tr>
                            <td class="row-heading"><?php _e('Logout URL:', 'evdpl-login-redirect'); ?></td>
                            <td><input type="text" size="90" maxlength="500" name="evdpl_role_logout"/></td>
                        </tr>
                        <tr>
                            <td></td>
                            <td>
                                <p class="btn">
                                    <input type="submit" class="button button-primary" name="evdpl_role_submit" value="<?php _e('Add role rule', 'evdpl-login-redirect'); ?>"/>
                                    <?php wp_nonce_field('evdpl_role_submit'); ?>
                                </p>
                            </td>
                        </tr>
                    </table>
                </form>
            </div>
            <?php
            if ($evdpl_rolevalues) {
                print '<table class="widefat">';
                print $evdpl_rolevalues;
                print '</table>';
            }
            ?>            
            <hr />
            
            <div class="section-pd specific--section">
                <h3><?php _e('Specific levels', 'evdpl-login-redirect'); ?></h3>
                <form name="evdpl_level_add_form" id="evdpl_level_add_form" action="<?php print '?page=' . basename(__FILE__); ?>" method="post">
                    <table>
                        <tr>
                            <td class="row-heading"><?php _e('Add:', 'evdpl-login-redirect'); ?></td>
                            <td>
                                <select name="evdpl_level">
                                    <option value="-1"><?php _e('Select a level', 'evdpl-login-redirect'); ?></option>
                                    <?php print evdpl_returnleveloptions($evdpl_levels_existing); ?>
                                </select>
                            </td>
                        </tr>
                        <tr>
                            <td class="row-heading"><?php _e('Order:', 'evdpl-login-redirect'); ?></td>
                            <td><input type="text" size="2" maxlength="2" name="evdpl_level_order" class="evdpl_level_order"/></td>
                        </tr>
                        <tr>
                            <td class="row-heading"><?php _e('URL:', 'evdpl-login-redirect'); ?></td>
                            <td><input type="text" size="90" maxlength="500" name="evdpl_level_address"/></td>
                        </tr>
                        <tr>
                            <td class="row-heading"><?php _e('Logout URL:', 'evdpl-login-redirect'); ?></td>
                            <td><input type="text" size="90" maxlength="500" name="evdpl_level_logout"/></td>
                        </tr>
                        <tr>
                            <td></td>
                            <td>
                                <p class="btn">
                                    <input type="submit" class="button button-primary" name="evdpl_level_submit" value="<?php _e('Add level rule', 'evdpl-login-redirect'); ?>"/>
                                    <?php wp_nonce_field('evdpl_level_submit'); ?>
                                </p>
                            </td>
                        </tr>
                    </table>
                </form>
            </div>
            <script type="text/javascript">
                jQuery(document).ready(function ($) {
                    $('.evdpl_level_order').change(function () {
                        var thisForm = this;
                        $('.order_error').remove();
                        jQuery.ajax({
                            url: '<?php echo admin_url('admin-ajax.php'); ?>',
                            type: 'post',
                            data: {
                                action: 'evdpl_check_if_order_exists',
                                order: $(this).val(),
                            },
                            success: function (response) {
                                if (response.success == false) {
                                    $('<span style="color: red;" class="order_error"> ' + response.data + '</span>').insertAfter(thisForm);
                                }
                            }
                        });

                    });
                });
            </script>
            <?php
            if ($evdpl_levelvalues) {
                print '<table class="widefat">';
                print $evdpl_levelvalues;
                print '</table>';
            }
            ?>  
            <hr />

            <div class="section-pd specific--section">
                <h3><?php _e('All other users', 'evdpl-login-redirect'); ?></h3>
                <form name="evdpl_allform" method="post">
                    <table>
                        <tr>
                            <td class="row-heading"><?php _e('URL:', 'evdpl-login-redirect') ?></td>
                            <td><input type="text" size="90" maxlength="500" name="evdpl_all" value="<?php print htmlspecialchars($evdpl_allvalue); ?>"/></td>
                        </tr>
                        <tr>
                            <td class="row-heading"><?php _e('Logout URL:', 'evdpl-login-redirect') ?></td>
                            <td><input type="text" size="90" maxlength="500" name="evdpl_all_logout" value="<?php print htmlspecialchars($evdpl_allvalue_logout); ?>"/></td>
                        </tr>
                        <tr>
                            <td></td>
                            <td>
                                <p class="btn">
                                    <input type="submit" class="button button-primary" name="evdpl_allupdatesubmit" value="<?php _e('Update', 'evdpl-login-redirect'); ?>"/>
                                    <input type="submit" class="button" name="evdpl_alldeletesubmit" value="<?php _e('Delete', 'evdpl-login-redirect'); ?>"/>
                                    <?php wp_nonce_field('evdpl_allupdatesubmit'); ?>
                                </p>
                            </td>
                        </tr>
                    </table>
                </form>
            </div>
            <hr/>

            <div class="section-pd specific--section">
                <h3><?php _e('Post-registration', 'evdpl-login-redirect'); ?></h3>
                <form name="evdpl_registerform" method="post">
                    <table>
                        <tr>
                            <td class="row-heading"><?php _e('URL:', 'evdpl-login-redirect') ?></td>
                            <td><input type="text" size="90" maxlength="500" name="evdpl_register" value="<?php print htmlspecialchars($evdpl_registervalue); ?>"/></td>
                        </tr>
                        <tr>
                            <td></td>
                            <td>
                                <p class="btn">
                                    <input type="submit" class="button button-primary" name="evdpl_registerupdatesubmit" value="<?php _e('Update', 'evdpl-login-redirect'); ?>"/>
                                    <input type="submit" class="button" name="evdpl_registerdeletesubmit" value="<?php _e('Delete', 'evdpl-login-redirect'); ?>"/>
                                    <?php wp_nonce_field('evdpl_registerupdatesubmit'); ?>
                                </p>
                            </td>
                        </tr>
                    </table>
                </form>
            </div>

            <hr/>
        </div>
        <?php
    }

    /*
     * close evdpl_optionsmenu()
     */

    /*
     * Add and remove database tables when installing and uninstalling
     */

    function evdpl_install() {
        global $wpdb, $evdpl_db_addresses, $evdpl_version;

        /*
         * Add the table to hold group information and moderator rules
         */
        if ($evdpl_db_addresses != $wpdb->get_var("SHOW TABLES LIKE '$evdpl_db_addresses'")) {
            $sql = "CREATE TABLE $evdpl_db_addresses (
            `evdpl_type` enum('user','role','level','all','register') NOT NULL,
            `evdpl_value` varchar(191) NULL default NULL,
            `evdpl_url` LONGTEXT NULL default NULL,
            `evdpl_url_logout` LONGTEXT NULL default NULL,
            `evdpl_order` int(2) NOT NULL default '0',
            UNIQUE KEY `evdpl_type` (`evdpl_type`,`evdpl_value`)
            )";

            $wpdb->query($sql);

            /*
             * Insert the "all" redirect entry
             */
            $wpdb->insert($evdpl_db_addresses,
                    array('evdpl_type' => 'all')
            );

            // Insert the "on-register" redirect entry
            $wpdb->insert($evdpl_db_addresses,
                    array('evdpl_type' => 'register')
            );

            /*
             *  Set the version number in the database
             */
            add_option('evdpl_version', $evdpl_version, '', 'no');
        }
    }

    function evdpl_uninstall() {
        global $wpdb, $evdpl_db_addresses;

        // Remove the table we created
        if ($evdpl_db_addresses == $wpdb->get_var('SHOW TABLES LIKE \'' . $evdpl_db_addresses . '\'')) {
            $sql = 'DROP TABLE ' . $evdpl_db_addresses;
            $wpdb->query($sql);
        }

        delete_option('evdpl_version');
        delete_option('evdpl_settings');
    }

    function evdpl_addoptionsmenu() {
        add_options_page('User Role Redirect', 'User Role Redirect', 'manage_categories', 'user_role_redirect.php', 'evdpl_optionsmenu');
    }

    add_action('admin_menu', 'evdpl_addoptionsmenu', 1);
}

/*
 *  Executes when plugin is activated
 */

function evdpl_activate_plugin($networkwide) {

    global $wpdb, $evdpl_db_addresses;

    if (function_exists('is_multisite') && is_multisite() && $networkwide) {
        $blogs = $wpdb->get_col("SELECT blog_id FROM $wpdb->blogs");
        foreach ($blogs as $blog) {
            switch_to_blog($blog);
            $evdpl_db_addresses = $wpdb->prefix . 'login_redirects';
            evdpl_install();
            restore_current_blog();
        }
    } else {
        evdpl_install();
    }
}

/*
 * Executes when plugin is deleted
 */

function evdpl_uninstall_plugin() {
    global $wpdb, $evdpl_db_addresses;
    if (function_exists('is_multisite') && is_multisite()) {
        $blogs = $wpdb->get_col("SELECT blog_id FROM $wpdb->blogs");
        foreach ($blogs as $blog) {
            switch_to_blog($blog);
            $evdpl_db_addresses = $wpdb->prefix . 'login_redirects';
            evdpl_uninstall();
            restore_current_blog();
        }
    } else {
        evdpl_uninstall();
    }
}

/**
 * Add a link to the settings on the Plugins screen.
 */
function add_settings_link($links, $file) {

    if ($file === 'user-role-redirect/user_role_redirect.php' && current_user_can('manage_options')) {

        if (current_filter() === 'plugin_action_links') {

            $url = esc_url(add_query_arg(
                            'page',
                            'user_role_redirect.php',
                            get_admin_url() . 'options-general.php'
                    )
            );
        }

        // Prevent warnings in PHP 7.0+ when a plugin uses this filter incorrectly.
        $links = (array) $links;
        $links[] = sprintf('<a href="%s">%s</a>', $url, 'Settings');
    }

    return $links;
}

/*
 *  Executes when a site's initialization routine should be executed.
 */

function evdpl_site_added($blog) {
    //
    global $wpdb, $evdpl_db_addresses;

    if (!is_int($blog)) {
        $blog = $blog->id;
    }

    switch_to_blog($blog);
    $evdpl_db_addresses = $wpdb->prefix . 'login_redirects';
    evdpl_install();
    restore_current_blog();
}

function evdpl_drop_tables($tables) {
    global $wpdb;
    $tables[] = $wpdb->prefix . 'login_redirects';

    return $tables;
}

function user_role_redirect_scripts(){
    wp_enqueue_style('user-role-css',plugins_url('', __FILE__).'/assets/css/style.css');
}

register_activation_hook(__FILE__, 'evdpl_activate_plugin');
register_uninstall_hook(__FILE__, 'evdpl_uninstall_plugin');
add_filter( 'plugin_action_links', 'add_settings_link', 10, 2 );
add_filter('wpmu_drop_tables', 'evdpl_drop_tables');
add_action('activate_blog', 'evdpl_site_added');
add_action('admin_enqueue_scripts','user_role_redirect_scripts');

function evdpl_check_if_order_exists() {
    $inputorder = sanitize_text_field['order'];
    global $wpdb;
    $table = $wpdb->prefix . "login_redirects";
    $orders = $wpdb->get_results("SELECT evdpl_order,evdpl_value FROM $table WHERE evdpl_type = 'level'");
    $redirect_orders = array();
    foreach ($orders as $order) {
        $redirect_orders[] = $order->evdpl_order;
    }
    if (in_array($inputorder, $redirect_orders)) {
        echo wp_send_json_error('You are using the same order which you have used before this may conflict in redirection');
    } else {
        echo wp_send_json_success();
    }
    die();
}

add_action('wp_ajax_evdpl_check_if_order_exists', 'evdpl_check_if_order_exists');
add_action('wp_ajax_nopriv_evdpl_check_if_order_exists', 'evdpl_check_if_order_exists');

// wpmu_new_blog has been deprecated in 5.1 and replaced by wp_insert_site.
global $wp_version;
if (version_compare($wp_version, '5.1', '<')) {
    add_action('wpmu_new_blog', 'evdpl_site_added');
} else {
    add_action('wp_initialize_site', 'evdpl_site_added', 99);
}

/*
 * Login Redirect Rule
 */
add_filter('login_redirect', 'evdpl_redirect_wrapper', 999999999, 3);
add_filter('woocommerce_login_redirect', 'evdpl_woocommerce_redirect_wrapper', 10, 2);
/*
 * Registration Redirect Rule
 */
add_filter('registration_redirect', array('evdplRedirectPostRegistration', 'evdpl_post_registration_wrapper'), 10, 2);
add_filter('woocommerce_registration_redirect', 'evdpl_woocommerce_registration_redirect_wrapper', 999999999, 1);
/*
 * Logout Redirect Rule
 */
add_action('wp_logout', array('evdplLogoutFunctionCollection', 'evdpl_logout_redirect'), 1);
add_filter('logout_redirect', array('evdplLogoutFunctionCollection', 'evdpl_logout_redirect_2'), 999999999, 3);
