<?php
// This file is part of Moodle - http://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

/**
 * English language strings.
 *
 * @package auth_cnoauth
 * @author Martin Liao <liaohanzhen@163.com>
 * 
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 * @copyright (C) 2021
 */

defined('MOODLE_INTERNAL') || die();

$string['pluginname'] = 'CN OpenID Connect';
$string['auth_cnoauthdescription'] = 'The CN OpenID Connect plugin provides single-sign-on functionality using configurable identity providers.';

$string['cfg_authendpoint_key'] = 'Authorization Endpoint';
$string['cfg_authendpoint_desc'] = 'The URI of the Authorization endpoint from your identity provider to use.';
$string['cfg_autoappend_key'] = 'Auto-Append';
$string['cfg_autoappend_desc'] = 'Automatically append this string when logging in users using the "Resource Owner Password Credentials" authentication method. This is useful when your identity provider requires a common domain, but don\'t want to require users to type it in when logging in. For example, if the full CN OpenID Connect user is "james@example.com" and you enter "@example.com" here, the user will only have to enter "james" as their username. <br /><b>Note:</b> In the case where conflicting usernames exist - i.e. a Moodle user exists wth the same name, the priority of the authentication plugin is used to determine which user wins out.';
$string['cfg_clientid_key'] = 'Client ID';
$string['cfg_clientid_desc'] = 'Your registered Client ID on the identity provider';
$string['cfg_clientsecret_key'] = 'Client Secret';
$string['cfg_clientsecret_desc'] = 'Your registered Client Secret on the identity provider. On some providers, it is also referred to as a key.';
$string['cfg_domainhint_key'] = 'Domain Hint';
$string['cfg_domainhint_desc'] = 'When using the "Authorization Code" authentication method, pass this value as the "domain_hint" parameter. "domain_hint" is used by some CN OpenID Connect providers to make the login process easier for users. Check with your provider to see whether they support this parameter.';
$string['cfg_err_invalidauthendpoint'] = 'Invalid Authorization Endpoint';
$string['cfg_err_invaluserinfoendpoint'] = 'Invalid Token Endpoint';
$string['cfg_err_invaliduserinfoendpoint'] = 'Invalid Userinfo Endpoint';
$string['cfg_err_invalidclientid'] = 'Invalid client ID';
$string['cfg_err_invalidclientsecret'] = 'Invalid client secret';
$string['cfg_forceredirect_key'] = 'Force redirect';
$string['cfg_forceredirect_desc'] = 'If enabled, will skip the login index page and redirect to the CN OpenID Connect page. Can be bypassed with ?noredirect=1 URL param';
$string['cfg_icon_key'] = 'Icon';
$string['cfg_icon_desc'] = 'An icon to display next to the provider name on the login page.';
$string['cfg_iconalt_wechat'] = 'Wechat icon';
$string['cfg_iconalt_o365'] = 'Microsoft 365 icon';
$string['cfg_iconalt_locked'] = 'Locked icon';
$string['cfg_iconalt_lock'] = 'Lock icon';
$string['cfg_iconalt_go'] = 'Green circle';
$string['cfg_iconalt_stop'] = 'Red circle';
$string['cfg_iconalt_user'] = 'User icon';
$string['cfg_iconalt_user2'] = 'User icon alternate';
$string['cfg_iconalt_key'] = 'Key icon';
$string['cfg_iconalt_group'] = 'Group icon';
$string['cfg_iconalt_group2'] = 'Group icon alternate';
$string['cfg_iconalt_mnet'] = 'MNET icon';
$string['cfg_iconalt_userlock'] = 'User with lock icon';
$string['cfg_iconalt_plus'] = 'Plus icon';
$string['cfg_iconalt_check'] = 'Checkmark icon';
$string['cfg_iconalt_rightarrow'] = 'Right-facing arrow icon';
$string['cfg_customicon_key'] = 'Custom Icon';
$string['cfg_customicon_desc'] = 'If you\'d like to use your own icon, upload it here. This overrides any icon chosen above. <br /><br /><b>Notes on using custom icons:</b><ul><li>This image will <b>not</b> be resized on the login page, so we recommend uploading an image no bigger than 35x35 pixels.</li><li>If you have uploaded a custom icon and want to go back to one of the stock icons, click the custom icon in the box above, then click "Delete", then click "OK", then click "Save Changes" at the bottom of this form. The selected stock icon will now appear on the Moodle login page.</li></ul>';
$string['cfg_debugmode_key'] = 'Record debug messages';
$string['cfg_debugmode_desc'] = 'If enabled, information will be logged to the Moodle log that can help in identifying problems.';
$string['cfg_loginflow_key'] = 'Authentication Method';
$string['cfg_loginflow_authcode'] = 'Authorization Code Flow (recommended)';
$string['cfg_loginflow_authcode_desc'] = 'Using this flow, the user clicks the name of the identity provider (See "Provider Name" above) on the Moodle login page and is redirected to the provider to log in. Once successfully logged in, the user is redirected back to Moodle where the Moodle login takes place transparently. This is the most standardized, secure way for the user log in.';
$string['cfg_loginflow_rocreds'] = 'Resource Owner Password Credentials Grant';
$string['cfg_loginflow_rocreds_desc'] = 'Using this flow, the user enters their username and password into the Moodle login form like they would with a manual login. This will authorize the user with the identity provider, but will not create a session on the identity provider\'s site. For example, if using Microsoft 365 with CN OpenID Connect, the user will be logged in to Moodle but not the Microsoft 365 web applications. Using the authorization request is recommended if you want users to be logged in to both Moodle and the identity provider.  Note that not all identity providers support this flow. This option should only be used when other authorization grant types are not available.';
$string['cfg_cnoauthresource_key'] = 'Resource';
$string['cfg_cnoauthresource_desc'] = 'The CN OpenID Connect resource for which to send the request.';
$string['cfg_cnoauthscope_key'] = 'Scope';
$string['cfg_cnoauthscope_desc'] = 'The cnoauth Scope to use.';
$string['cfg_opname_key'] = 'Provider Name';
$string['cfg_opname_desc'] = 'This is an end-user-facing label that identifies the type of credentials the user must use to login. This label is used throughout the user-facing portions of this plugin to identify your provider.';
$string['cfg_redirecturi_key'] = 'Redirect URI';
$string['cfg_redirecturi_desc'] = 'This is the URI to register as the "Redirect URI". Your CN OpenID Connect identity provider should ask for this when registering Moodle as a client. <br /><b>NOTE:</b> You must enter this in your CN OpenID Connect provider *exactly* as it appears here. Any difference will prevent logins using CN OpenID Connect.';
$string['cfg_tokenendpoint_key'] = 'Token Endpoint';
$string['cfg_tokenendpoint_desc'] = 'The URI of the token endpoint from your identity provider to use.';
$string['cfg_userinfoendpoint_key'] = 'Userinfo Endpoint';
$string['cfg_userinfoendpoint_desc'] = 'The URI of the userinfo endpoint from your identity provider to use.';
$string['cfg_userrestrictions_key'] = 'User Restrictions';
$string['cfg_userrestrictions_desc'] = 'Only allow users to log in that meet certain restrictions. <br /><b>How to use user restrictions: </b> <ul><li>Enter a <a href="https://en.wikipedia.org/wiki/Regular_expression">regular expression</a> pattern that matches the usernames of users you want to allow.</li><li>Enter one pattern per line</li><li>If you enter multiple patterns a user will be allowed if they match ANY of the patterns.</li><li>The character "/" should be escaped with "\".</li><li>If you don\'t enter any restrictions above, all users that can log in to the CN OpenID Connect provider will be accepted by Moodle.</li><li>Any user that does not match any entered pattern(s) will be prevented from logging in using CN OpenID Connect.</li></ul>';
$string['cfg_userrestrictionscasesensitive_key'] = 'User Restrictions Case Sensitive';
$string['cfg_userrestrictioncasesensitive_desc'] = 'This controls if the "/i" option in regular expression is used in the user restriction match.<br/>If enabled, all user restriction checks will be performed as with case sensitive. Note if this is disabled, any patterns on letter cases will be ignored.';
$string['cfg_signoffintegration_key'] = 'Single sign off';
$string['cfg_signoffintegration_desc'] = 'If enabled, when a Moodle user using cnoauth authentication method signs off from Moodle, Moodle will attempt to log the user off from Office 365 as well.

Note the URL of Moodle site ({$a}) needs to be added as a redirect URI in the Azure app created for Moodle Office 365 integration.';
$string['cfg_logoutendpoint_key'] = 'Logout Endpoint';
$string['cfg_logoutendpoint_desc'] = 'The URI of the logout endpoint from your identity provider to use.';
$string['cfg_tools'] = 'Tools';
$string['cfg_cleanupcnoauthtokens_key'] = 'Cleanup CN OpenID Connect Tokens';
$string['cfg_cleanupcnoauthtokens_desc'] = 'If your users are experiencing problems logging in using their Microsoft 365 account, trying cleaning up CN OpenID Connect tokens. This removes stray and incomplete tokens that can cause errors. WARNING: This may interrupt logins in-process, so it\'s best to do this during downtime.';

$string['event_debug'] = 'Debug message';

$string['task_cleanup_cnoauth_state_and_token'] = 'Clean up cnoauth state and invalid token';

$string['errorauthdisconnectemptypassword'] = 'Password cannot be empty';
$string['errorauthdisconnectemptyusername'] = 'Username cannot be empty';
$string['errorauthdisconnectusernameexists'] = 'That username is already taken. Please choose a different one.';
$string['errorauthdisconnectnewmethod'] = 'Use Login Method';
$string['errorauthdisconnectinvalidmethod'] = 'Invalid login method received.';
$string['errorauthdisconnectifmanual'] = 'If using the manual login method, enter credentials below.';
$string['errorauthdisconnectinvalidmethod'] = 'Invalid login method received.';
$string['errorauthgeneral'] = 'There was a problem logging you in. Please contact your administrator for assistance.';
$string['errorauthinvaliduserinfo'] = 'Invalid userinfo received.';
$string['errorauthloginfailednouser'] = 'Invalid login: User not found in Moodle. If this site has the "authpreventaccountcreation" setting enabled, this may mean you need an administrator to create an account for you first.';
$string['errorauthnoauthcode'] = 'No authorization code was received from the identity server. The error logs may have more information.';
$string['errorauthnocreds'] = 'Please configure CN OpenID Connect client credentials.';
$string['errorauthnoendpoints'] = 'Please configure CN OpenID Connect server endpoints.';
$string['errorauthnohttpclient'] = 'Please set an HTTP client.';
$string['errorauthnouserinfo'] = 'CN OpenID Connect userinfo not received.';
$string['errorauthunknownstate'] = 'Unknown state.';
$string['errorauthuseralreadyconnected'] = 'You\'re already connected to a different CN OpenID Connect user.';
$string['errorauthuserconnectedtodifferent'] = 'The CN OpenID Connect user that authenticated is already connected to a Moodle user.';
$string['errorbadloginflow'] = 'Invalid authentication type specified. Note: If you are receiving this after a recent installation or upgrade, please clear your Moodle cache.';
$string['errorjwtbadpayload'] = 'Could not read JWT payload.';
$string['errorjwtcouldnotreadheader'] = 'Could not read JWT header';
$string['errorjwtempty'] = 'Empty or non-string JWT received.';
$string['errorjwtinvalidheader'] = 'Invalid JWT header';
$string['errorjwtmalformed'] = 'Malformed JWT received.';
$string['errorjwtunsupportedalg'] = 'JWS Alg or JWE not supported';
$string['errorlogintoconnectedaccount'] = 'This Microsoft 365 user is connected to a Moodle account, but CN OpenID Connect login is not enabled for this Moodle account. Please log in to the Moodle account using the account\'s defined authentication method to use Microsoft 365 features';
$string['errorcnoauthnotenabled'] = 'The CN OpenID Connect authentication plugin is not enabled.';
$string['errornodisconnectionauthmethod'] = 'Cannot disconnect because there is no enabled authentication plugin to fall back to. (either user\'s previous login method or the manual login method).';
$string['errorcnoauthclientinvalidendpoint'] = 'Invalid Endpoint URI received.';
$string['errorcnoauthclientnocreds'] = 'Please set client credentials with setcreds';
$string['errorcnoauthclientnoauthendpoint'] = 'No authorization endpoint set. Please set with $this->setendpoints';
$string['errorcnoauthclientnotokenendpoint'] = 'No token endpoint set. Please set with $this->setendpoints';
$string['errorcnoauthclientinsecuretokenendpoint'] = 'The token endpoint must be using SSL/TLS for this.';
$string['errorcnoauthclientnouserinfoendpoint'] = 'No userinfo endpoint set. Please set with $this->setendpoints';
$string['errorcnoauthclientinsecureuserinfoendpoint'] = 'The userinfo endpoint must be using SSL/TLS for this.';
$string['errorrestricted'] = 'This site has restrictions in place on the users that can log in with CN OpenID Connect. These restrictions currently prevent you from completing this login attempt.';
$string['errorucpinvalidaction'] = 'Invalid action received.';
$string['errorcnoauthcall'] = 'Error in CN OpenID Connect. Please check logs for more information.';
$string['errorcnoauthcall_message'] = 'Error in CN OpenID Connect: {$a}';
$string['errorinvalidredirect_message'] = 'The URL you are trying to redirect to does not exist.';

$string['eventuserauthed'] = 'User Authorized with CN OpenID Connect';
$string['eventusercreated'] = 'User created with CN OpenID Connect';
$string['eventuserconnected'] = 'User connected to CN OpenID Connect';
$string['eventuserloggedin'] = 'User Logged In with CN OpenID Connect';
$string['eventuserdisconnected'] = 'User disconnected from CN OpenID Connect';

$string['cnoauth:manageconnection'] = 'Allow CN OpenID Connection and Disconnection';
$string['cnoauth:manageconnectionconnect'] = 'Allow CN OpenID Connection';
$string['cnoauth:manageconnectiondisconnect'] = 'Allow CN OpenID Disconnection';

$string['privacy:metadata:auth_cnoauth'] = 'CN OpenID Connect Authentication';
$string['privacy:metadata:auth_cnoauth_prevlogin'] = 'Previous login methods to undo Microsoft 365 connections';
$string['privacy:metadata:auth_cnoauth_prevlogin:userid'] = 'The ID of the Moodle user';
$string['privacy:metadata:auth_cnoauth_prevlogin:method'] = 'The previous login method';
$string['privacy:metadata:auth_cnoauth_prevlogin:password'] = 'The previous (encrypted) user password field.';
$string['privacy:metadata:auth_cnoauth_token'] = 'CN OpenID Connect tokens';
$string['privacy:metadata:auth_cnoauth_token:cnoauthuniqid'] = 'The cnoauth unique user identifier.';
$string['privacy:metadata:auth_cnoauth_token:username'] = 'The username of the Moodle user';
$string['privacy:metadata:auth_cnoauth_token:userid'] = 'The user ID of the Moodle user';
$string['privacy:metadata:auth_cnoauth_token:cnoauthusername'] = 'The username of the cnoauth user';
$string['privacy:metadata:auth_cnoauth_token:scope'] = 'The scope of the token';
$string['privacy:metadata:auth_cnoauth_token:tokenresource'] = 'The resource of the token';
$string['privacy:metadata:auth_cnoauth_token:authcode'] = 'The auth code for the token';
$string['privacy:metadata:auth_cnoauth_token:token'] = 'The token';
$string['privacy:metadata:auth_cnoauth_token:expiry'] = 'The token expiry';
$string['privacy:metadata:auth_cnoauth_token:refreshtoken'] = 'The refresh token';
$string['privacy:metadata:auth_cnoauth_token:userinfo'] = 'The ID token';

// In the following strings, $a refers to a customizable name for the identity manager. For example, this could be
// "Microsoft 365", "CN OpenID Connect", etc.
$string['ucp_general_intro'] = 'Here you can manage your connection to {$a}. If enabled, you will be able to use your {$a} account to log in to Moodle instead of a separate username and password. Once connected, you\'ll no longer have to remember a username and password for Moodle, all log-ins will be handled by {$a}.';
$string['ucp_login_start'] = 'Start using {$a} to log in to Moodle';
$string['ucp_login_start_desc'] = 'This will switch your account to use {$a} to log in to Moodle. Once enabled, you will log in using your {$a} credentials - your current Moodle username and password will not work. You can disconnect your account at any time and return to logging in normally.';
$string['ucp_login_stop'] = 'Stop using {$a} to log in to Moodle';
$string['ucp_login_stop_desc'] = 'You are currently using {$a} to log in to Moodle. Clicking "Stop using {$a} login" will disconnect your Moodle account from {$a}. You will no longer be able to log in to Moodle with your {$a} account. You\'ll be asked to create a username and password, and from then on you will then be able to log in to Moodle directly.';
$string['ucp_login_status'] = '{$a} login is:';
$string['ucp_status_enabled'] = 'Enabled';
$string['ucp_status_disabled'] = 'Disabled';
$string['ucp_disconnect_title'] = '{$a} Disconnection';
$string['ucp_disconnect_details'] = 'This will disconnect your Moodle account from {$a}. You\'ll need to create a username and password to log in to Moodle.';
$string['ucp_title'] = '{$a} Management';
$string['ucp_o365accountconnected'] = 'This Microsoft 365 account is already connected with another Moodle account.';

$string['cleanup_cnoauth_tokens'] = 'Cleanup CN OpenID Connect tokens';
$string['unmatched'] = 'Unmatched';
$string['delete_token'] = 'Delete token';
$string['mismatched'] = 'Mismatched';
$string['na'] = 'n/a';
$string['mismatched_details'] = 'Token record contains username "{$a->tokenusername}"; matched Moodle user has username "{$a->moodleusername}".';
$string['delete_token_and_reference'] = 'Delete token and reference';
$string['table_token_id'] = 'Token record ID';
$string['table_cnoauth_username'] = 'cnoauth username';
$string['table_token_unique_id'] = 'cnoauth unique ID';
$string['table_matching_status'] = 'Matching status';
$string['table_matching_details'] = 'Details';
$string['table_action'] = 'Action';
$string['token_deleted'] = 'Token was deleted successfully';
$string['no_token_to_cleanup'] = 'There are no cnoauth token to cleanup.';

$string['errorusermatched'] = 'The Microsoft 365 account "{$a->aadupn}" is already matched with Moodle user "{$a->username}". To complete the connection, please log in as that Moodle user first and follow the instructions in the Microsoft block.';
