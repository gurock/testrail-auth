<?php

/**
 * This is a TestRail authentication script to integrate TestRail with
 * Windows Active Directory services to implement single sign-on.
 *
 * Copyright Gurock Software GmbH. All rights reserved.
 * http://www.gurock.com/ - contact@gurock.com
 *
 **********************************************************************
 *
 * Learn more about TestRail authentication scripts in general and
 * this implementation in particular, please visit the following
 * website:
 *
 * http://docs.gurock.com/testrail-integration/auth-introduction
 *
 **********************************************************************
 *
 * The following constants must be configured before using this API:
 *
 * AUTH_HOST	       The fully qualified domain name of the active
 *                     directory server
 *
 *                     Example: ad1.directory.example.com
 *
 * AUTH_PORT           The LDAP port of the directory server. This is
 *                     usually 389.
 *
 * AUTH_DN             The base LDAP Distinguished Name to find and
 *                     authenticate users against. This MUST include at
 *                     least the top OU, CN and/or DC entries. This
 *                     usually includes the domain and organization name
 *                     or the Users group.
 *
 *                     Example 1: CN=Users,DC=directory,DC=example,DC=com
 *                     Example 2: OU=Example Inc,DC=directory,DC=example,DC=com
 *
 *                     You can also specify specific user groups if you
 *                     only want to allow specific users to authenticate
 *                     with TestRail.
 *
 * AUTH_DOMAIN         The domain name used by Windows (this is the name
 *                     often used as a prefix for user names, such as
 *                     directory\bob)
 *
 *                     Example: directory
 *
 * AUTH_CREATE_ACCOUNT This configuration setting specifies if TestRail
 *                     should automatically create new user accounts in
 *                     TestRail if a user could be successfully
 *                     authenticated. This is a great way to create all
 *                     the necessary user accounts in your organization
 *                     without creating TestRail accounts manually.
 *                     Simply set this option to true and send all users
 *                     an email with TestRail's web address. The accounts
 *                     for users will automatically be created when they
 *                     first login.
 *
 * AUTH_FALLBACK       Allow users to continue login with their TestRail
 *                     credentials in addition to the Active Directory
 *                     login. If enabled, TestRail tries to authenticate
 *                     the user with her TestRail credentials if the AD
 *                     authentication fails and an email address is entered.
 *
 * AUTH_MEMBERSHIP     (Optionally) verifies if a user is member of the
 *                     security group(s). Must be a regular expression
 *                     that is checked against all memberOf values. If one
 *                     of the entries matches, the user is authenticated.
 *                     If none of the memberOf values match, access is
 *                     denied.
 *
 *                     Example: /^CN=My Group,/
 *
 * AUTH_USER_ATTRIBUTE Attribute to search when looking up users, for example
 *                     sAMAccountName or userPrincipalName.
 */

define('AUTH_HOST', 'ad1.directory.example.com');
define('AUTH_PORT', 389);
define('AUTH_DN', 'CN=Users,DC=directory,DC=example,DC=com');
define('AUTH_DOMAIN', 'directory');
define('AUTH_CREATE_ACCOUNT', false);
define('AUTH_FALLBACK', true);
define('AUTH_MEMBERSHIP', '');
define('AUTH_USER_ATTRIBUTE', 'sAMAccountName');

function _ad_throw_error($handle, $prefix = null)
{
	throw new AuthException(($prefix ? $prefix . ': ' : '') .
		ldap_error($handle));
}

function _ad_get_property($row, $prop)
{
	return isset($row[$prop][0]) ? $row[$prop][0] : null;
}

function _ad_lookup_user($handle, $name)
{
	// The account name can be given as 'domain\login', 'login@domain'
	// or just 'login'. We require just the login part for creating
	// the search, so we need to remove the domain part here, if any.

    if(AUTH_USER_ATTRIBUTE === 'userPrincipalName')
    {
        $login = $name;
    }
    else
    {
        $ix = strpos($name, '\\'); // Check for 'domain\login'
        if ($ix !== false)
        {
            $login = substr($name, $ix + 1);
        }
        else
        {
            $ix = strpos($name, '@'); // Check for 'login@domain'
            if ($ix !== false)
            {
                $login = substr($name, 0, $ix);
            }
            else
            {
                $login = $name; // Just 'login'
            }
        }
    }

	$login = ldap_escape($login, null, LDAP_ESCAPE_FILTER);

	// Initiate a search for the given active directory account to
	// find out the display name and email of the user (which are
	// required to lookup the TestRail user in the database or create
	// a new TestRail account).

	$search = @ldap_search(
		$handle,
		AUTH_DN,
		sprintf('(%s=%s)', AUTH_USER_ATTRIBUTE, $login),
		array('displayname', 'mail', 'memberOf')
	);

	if (!$search)
	{
		_ad_throw_error($handle, 'Search');
	}

	// Get the records for our search and extract the information
	// we need to lookup the user (display name and email).

	$records = ldap_get_entries($handle, $search);
	if (!$records || !isset($records['count']))
	{
		throw new AuthException('Received invalid search result.');
	}

	$count = (int) $records['count'];
	if ($count != 1)
	{
		throw new AuthException(
			'Could not find user object in Active Directory.');
	}

	$row = $records[0];

	// We found the user record, check the group membership if
	// required
	if (AUTH_MEMBERSHIP)
	{
		if (!isset($row['memberof']))
		{
			throw new AuthException(
				'User is not a member of required security group ' .
				'(no memberships defined for user).'
			);
		}

		$memberof = $row['memberof'];
		if (!isset($memberof['count']))
		{
			throw new AuthException(
				'Could not verify group membership (no membership count).'
			);
		}

		$found = false;
		for ($i = 0; $i < $memberof['count']; $i++)
		{
			if (!isset($memberof[$i]))
			{
				throw new AuthException(
					'Could not verify group membership (missing entry).'
				);
			}

			if (preg_match(AUTH_MEMBERSHIP, $memberof[$i]))
			{
				$found = true;
				break;
			}
		}

		if (!$found)
		{
			throw new AuthException(
				'User is not a member of required security group.'
			);
		}
	}

	return array(
		'name' => _ad_get_property($row, 'displayname'),
		'email' => _ad_get_property($row, 'mail')
	);
}

function _ad_authenticate($name, $password)
{
	if (!function_exists('ldap_connect'))
	{
		throw new AuthException(
			'LDAP functionality not available. ' .
			'Please install the LDAP module for PHP.'
		);
	}

	// We allow to to specify the domain account as 'domain\login',
	// 'login@domain' or just 'login'. But since the active directory
	// requires the domain part, we add it here if necessary.

	if (strpos($name, '\\') === false)
	{
		if (strpos($name, '@') === false)
		{
			$name = AUTH_DOMAIN . '\\' . $name;
		}
	}

	$handle = @ldap_connect(AUTH_HOST, AUTH_PORT);
	if (!$handle)
	{
		_ad_throw_error($handle, 'Connect');
	}

	ldap_set_option($handle, LDAP_OPT_PROTOCOL_VERSION, 3);
	ldap_set_option($handle, LDAP_OPT_REFERRALS, 0);

	// Bind to LDAP directory. This does the actual connection attempt
	// and can fail if the configured server is not reachable.
	if (!@ldap_bind($handle, $name, $password))
	{
		_ad_throw_error($handle, 'Bind');
	}

	$user = _ad_lookup_user($handle, $name);
	@ldap_unbind($handle);

	$result = new AuthResultSuccess($user['email']);
	$result->name = $user['name'];
	$result->create_account = AUTH_CREATE_ACCOUNT;
	return $result;
}

/**
 * Authenticate User
 *
 * Custom auth function for authenticating a TestRail user against an
 * Active Directory server. Returns a TestRail AuthResult object or
 * throws an exception in case of an error (connection, for example).
 */
function authenticate_user($name, $password)
{
	try
	{
		return _ad_authenticate($name, $password);
	}
	catch (Exception $e)
	{
		if (AUTH_FALLBACK)
		{
			if (check::email($name))
			{
				return new AuthResultFallback();
			}
		}
		throw $e;
	}
}

// ldap_escape was added with PHP 5.6 but is not available with older
// PHP versions. The author of ldap_escape posted a version for older
// PHP versions on StackOverflow:
//
// http://stackoverflow.com/questions/8560874/php-ldap-add-function-to-escape-ldap-special-characters-in-dn-syntax
//
// The code is made available by the author under the creative commons
// (cc by-sa 3.0) license, and included below for compatibility with
// older PHP versions.
//
// http://creativecommons.org/licenses/by-sa/3.0/

if (!function_exists('ldap_escape')) {
	define('LDAP_ESCAPE_FILTER', 0x01);
	define('LDAP_ESCAPE_DN',     0x02);

	/**
	 * @param string $subject The subject string
	 * @param string $ignore Set of characters to leave untouched
	 * @param int $flags Any combination of LDAP_ESCAPE_* flags to indicate the
	 *                   set(s) of characters to escape.
	 * @return string
	 */
	function ldap_escape($subject, $ignore = '', $flags = 0)
	{
		static $charMaps = array(
			LDAP_ESCAPE_FILTER => array('\\', '*', '(', ')', "\x00"),
			LDAP_ESCAPE_DN     => array('\\', ',', '=', '+', '<', '>', ';', '"', '#'),
		);

		// Pre-process the char maps on first call
		if (!isset($charMaps[0])) {
			$charMaps[0] = array();
			for ($i = 0; $i < 256; $i++) {
				$charMaps[0][chr($i)] = sprintf('\\%02x', $i);;
			}

			for ($i = 0, $l = count($charMaps[LDAP_ESCAPE_FILTER]); $i < $l; $i++) {
				$chr = $charMaps[LDAP_ESCAPE_FILTER][$i];
				unset($charMaps[LDAP_ESCAPE_FILTER][$i]);
				$charMaps[LDAP_ESCAPE_FILTER][$chr] = $charMaps[0][$chr];
			}

			for ($i = 0, $l = count($charMaps[LDAP_ESCAPE_DN]); $i < $l; $i++) {
				$chr = $charMaps[LDAP_ESCAPE_DN][$i];
				unset($charMaps[LDAP_ESCAPE_DN][$i]);
				$charMaps[LDAP_ESCAPE_DN][$chr] = $charMaps[0][$chr];
			}
		}

		// Create the base char map to escape
		$flags = (int)$flags;
		$charMap = array();
		if ($flags & LDAP_ESCAPE_FILTER) {
			$charMap += $charMaps[LDAP_ESCAPE_FILTER];
		}
		if ($flags & LDAP_ESCAPE_DN) {
			$charMap += $charMaps[LDAP_ESCAPE_DN];
		}
		if (!$charMap) {
			$charMap = $charMaps[0];
		}

		// Remove any chars to ignore from the list
		$ignore = (string)$ignore;
		for ($i = 0, $l = strlen($ignore); $i < $l; $i++) {
			unset($charMap[$ignore[$i]]);
		}

		// Do the main replacement
		$result = strtr($subject, $charMap);

		// Encode leading/trailing spaces if LDAP_ESCAPE_DN is passed
		if ($flags & LDAP_ESCAPE_DN) {
			if ($result[0] === ' ') {
				$result = '\\20' . substr($result, 1);
			}
			if ($result[strlen($result) - 1] === ' ') {
				$result = substr($result, 0, -1) . '\\20';
			}
		}

		return $result;
	}
}
