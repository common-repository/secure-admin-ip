=== Secure Admin IP ===
Contributors: Minor
Tags: login, protect, ip, admin, secure, whitelist
Requires at least: 4.6
Tested up to: 6.0
Stable tag: 2.0
Requires PHP: 5.6
License: GPLv3
License URI: http://www.gnu.org/licenses/gpl-3.0.html
Donate link: https://www.paypal.me/NovaMi

Simply restrict login to your WordPress for the specific IP addresses or users with secret link.

== Description ==
Simple plugin to secure your WordPress admin interface thanks to IP whitelisting. Only IP addressess on the whitelist (external whitelist supported) have an access into admin interface.

Another possibility how to access WordPress administration is thanks to secret admin link (you still need to insert correct user login and password).

Your IP address is whitelisted and secret admin link generated every time at plugin activation!

== Installation ==
1. Upload the plugin files to the '/wp-content/plugins/secure-admin-ip' directory, or install the plugin through WordPress Plugins Search: Plugins -> Add new.

2. Click on the Activate button.

3. Done! WordPress admin interface is restricted to your IP address!

4. Go to Settings -> Secure Admin IP where you can add another IP address or set External whitelist URL and see secret admin link.

== Frequently Asked Questions ==
= Why to install this plugin? =
No ads and any other needless changes in the WordPress. This plugin is primary created for my own websites - make money is not the reason why I created it.

= How to disable this plugin? =
Just use standard Plugin overview page in WordPress admin section and deactivate it or rename plugin folder /wp-content/plugins/secure-admin-ip over FTP access.

= How to separate more IP addresses? =
It's up to you! You can use new line, dash, comma, ...

= How to use external whitelist? =
Just create new file (JSON format) and host it on public URL. Example: [{"ip":"1.1.1.1","description":"Michal"},{"ip":"2.2.2.2","description":"Novak"}].

Cache is used so don't need to afraid about a lot of requests on that file (server load).

= What happen if I save my incorrect IP address? =
Save settings fail if your current IP address will not be found on new whitelist.

== Screenshots ==
1. Options page - Settings page

== Changelog ==
= 2.0 =
* Bugfix: More reliable.

= 1.9 =
* Change: IP detection - If there is IP list separated by comma, like sometimes in HTTP_X_FORWARDED_FOR, first IP address is taken.

= 1.8 =
* New: Added protection to avoid save settings if your current IP address will not be found on new whitelist.

= 1.7 =
* New: External whitelist support!

= 1.6 =
* Change: Uses standard cookie instead of session because of better compatibility.

= 1.5 =
* Bugfix: Fixed IP address detection on servers with PHP FastCGI settings.

= 1.4 =
* Change: IP address detection extended - proxy servers and shared internet connection.
* Change: Previous whitelist is not discarded on plugin reactivation.

= 1.3 =
* New: Not possible to show login form If the IP address is not on the whitelist - brute-force attack protection.
* New: Uses session instead of cookie for the purpose to login via secret link - it's more secure.

= 1.2 =
* Bugfix: Secret hash is generated and your current IP address is whitelisted at plugin activation.
* New: Important! All whitelisted IP addresses are removed at plugin activation! Only your current IP address is whitelisted automatically.

= 1.1 =
* Bugfix: Notice error regarding not initialized vars.

= 1.0 =
* New: Initial release!
