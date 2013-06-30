<?php

/**
 * This is a TestRail authentication script to integrate TestRail with
 * LDAP services to implement single sign-on.
 *
 * Copyright 2011 Gurock Software GmbH. All rights reserved.
 * http://www.gurock.com - contact@gurock.com
 *
 **********************************************************************
 *
 * Learn more about TestRail authentication scripts in general and
 * this implementation in particular, please visit the following
 * website:
 *
 * http://code.gurock.com/p/testrail-auth/
 *
 **********************************************************************
 *
 * The following constants must be configured before using this API:
 *
 * AUTH_HOST           The fully qualified domain name of the LDAP
 *                     directory server
 *
 *                     Example: ldap://ldap.example.com
 *
 * AUTH_PORT           The LDAP port of the directory server. This is
 *                     usually 389.
 *
 * AUTH_BIND_DN        The LDAP distinguished name of the user account
 *                     used t query a user object from the directory.
 *
 * AUTH_BIND_PASSWORD  The password of the user account used to query
 *                     a user object from the directory.
 *
 *                     If both settings, AUTH_BIND_DN as well as
 *                     AUTH_BIND_PASSWORD, are left blank, TestRail
 *                     will try to use anonymous authentication.
 * 
 * AUTH_DN             The base LDAP distinguished name to find and
 *                     authenticate users against. This must include at
 *                     least the top OU, CN and/or DC entries. This
 *                     usually includes the organization name and an
 *                     organizational unit (OU).
 *
 *                     Example 1: OU=people,DC=example,DC=com
 *                     Example 2: DC=example,DC=com
 *
 * AUTH_FILTER         The filter expression that is used to find and 
 *                     retrieve the directory object of the user who
 *                     is authenticated. The expression has to follow the
 *                     common LDAP filter syntax.
 *
 *                     When performing the search, the placeholder %name% will
 *                     be replaced with the username that was entered on
 *                     TestRail's login page.
 *
 *                     Example: (&(uid=%name%)(objectClass=posixAccount))
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
 *                     credentials in addition to the LDAP Directory
 *                     login. If enabled, TestRail tries to authenticate 
 *                     the user with her TestRail credentials if an email
 *                     address is entered. If a username is entered, TestRail
 *                     authenticates the user against LDAP Directory.
 *
 * AUTH_NAME_ATTRIBUTE The name of the attribute that stores the user's
 *                     full name. This attribute is used when a new 
 *                     TestRail user account is created.
 *
 * AUTH_MAIL_ATTRIBUTE The name of the attribute that stores the user's
 *                     email address. This attribute is used to link
 *                     LDAP user records to TestRail user accounts.
 */ 

define('AUTH_HOST', 'ldap://ldap.example.com');
define('AUTH_PORT', 389);
define('AUTH_BIND_DN', '');
define('AUTH_BIND_PASSWORD', '');
define('AUTH_DN', 'OU=people,DC=example,DC=com');
define('AUTH_FILTER', '(uid=%name%)');
define('AUTH_FALLBACK', true);
define('AUTH_CREATE_ACCOUNT', false);
define('AUTH_NAME_ATTRIBUTE', 'displayname');
define('AUTH_MAIL_ATTRIBUTE', 'mail');
 
function authenticate_user($name, $password)
{
	if (AUTH_FALLBACK)
	{
		if (check::email($name))
		{
			return new AuthResultFallback();
		}		
	}

	if (!function_exists('ldap_connect'))
	{
		throw new AuthException('LDAP functionality not available. ' .
			'Please install the LDAP module for PHP.');
	}
	
	// First try to find the user record of the user
	try 
	{
		$ldap_user = _ldap_get_user_data($name);
	}
	catch (Exception $e)
	{
		throw new AuthException(
			sprintf(
				'%s (failed to retrieve user object)',
				$e->getMessage()
			)
		);
	}
	
	// Try to authenticate against LDAP with the found DN and
	// entered password
	$dn = _ldap_get_single_value($ldap_user, 'dn');
	try
	{
		$handle = _ldap_open_connection(
				AUTH_HOST,
				AUTH_PORT,
				$dn,
				$password
			);
		_ldap_close_connection($handle);
	}
	catch (Exception $e)
	{
		throw new AuthException(
			'Could not validate LDAP user, please check user name and password.');
	}

	// Read the user attributes and return the successful authentication
	// result to TestRail
	$mail = _ldap_get_single_value($ldap_user, AUTH_MAIL_ATTRIBUTE);
	$display_name = _ldap_get_single_value($ldap_user, AUTH_NAME_ATTRIBUTE);
	
	$result = new AuthResultSuccess($mail);
	$result->name = $display_name;
	$result->create_account = AUTH_CREATE_ACCOUNT;
	return $result;
}

function _ldap_get_user_data($name)
{
	$handle = _ldap_open_connection(AUTH_HOST, AUTH_PORT,
		AUTH_BIND_DN, AUTH_BIND_PASSWORD);
	try
	{
		$search = @ldap_search(
			$handle,
			AUTH_DN,
			preg_replace('/%name%/', $name, AUTH_FILTER),
			array(AUTH_NAME_ATTRIBUTE, AUTH_MAIL_ATTRIBUTE, 'dn')
		);

		if (!$search)
		{
			_ldap_throw_error($handle, 'Search');
		}
		
		$records = ldap_get_entries($handle, $search);			
		if (!$records || !isset($records['count']))
		{
			throw new AuthException(
				'Received invalid search result.');
		}
		
		$count = (int) $records['count'];
		if ($count != 1)
		{
			throw new AuthException(
				'Could not find user object in LDAP Directory.');
		}
		
		$row = $records[0];
	}
	catch (Exception $e)
	{
		_ldap_close_connection($handle);
		throw $e;
	}
	_ldap_close_connection($handle);
	
	return $row;
}

function _ldap_open_connection($host, $port, $dn, $password)
{
	$handle = @ldap_connect($host, $port);

	if (!$handle)
	{
		_ldap_throw_error($handle, 'Connect');
	}
	
	ldap_set_option($handle, LDAP_OPT_PROTOCOL_VERSION, 3);
	
	// Bind to LDAP directory. This does the actual connection attempt
	// and can fail if the configured server is not reachable.
	if (($dn <> '') && ($password <> '')) 
	{
		if (!@ldap_bind($handle, $dn, $password))
		{
			_ldap_throw_error($handle, 'Bind');
		}
	} 
	// Try anonymous login
	elseif (!@ldap_bind($handle))
	{
		_ldap_throw_error($handle, 'Bind');
	}
	
	return $handle;
}

function _ldap_close_connection($handle)
{
	@ldap_unbind($handle);
}

function _ldap_get_single_value($data, $attribute)
{
	$attributeData = $data[$attribute];
	if (is_array($attributeData))
	{
		return $attributeData[0];
	}
	else
	{
		return $attributeData;
	}
}

function _ldap_throw_error($handle, $prefix = null)
{
	throw new AuthException(($prefix ? $prefix . ': ' : '') .
		ldap_error($handle));
}
