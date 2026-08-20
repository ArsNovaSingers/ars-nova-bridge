<?php
/**
 * Plugin Name: Ars Nova Bridge
 * Description: Exposes theme_mods (Kadence / Customizer settings), read-only options, read-only theme source files, and read-only plugin source files over the REST API so the Ars Nova WordPress connector can read and write theme settings by command. Admin-only. Credentials are masked on read.
 * Version: 1.3.0
 * Author: Ars Nova (Jonathan)
 * Requires at least: 5.6
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit; // No direct access.
}

/** Keep in step with the `Version:` header above and the release tag. */
define( 'ANS_BRIDGE_VERSION', '1.3.0' );

/**
 * ---------------------------------------------------------------------------
 * CREDENTIAL MASKING (added 1.3.0)
 * ---------------------------------------------------------------------------
 *
 * WHY THIS EXISTS
 *
 * The /option route below was written as a diagnostics helper and returned
 * get_option() verbatim. On 2026-08-18 a plain read of the WooCommerce
 * payment-gateway settings returned this site's LIVE STRIPE SECRET KEY in
 * cleartext to a caller that had asked for nothing of the sort. The caller
 * wanted one unrelated field; it got a payment credential.
 *
 * That incident was written up, and the ticketing bridge's Mailchimp endpoint
 * was built to not repeat it - its docblock cites this very failure. But the
 * route that actually leaked was never fixed. It was still returning raw
 * option values on 2026-08-20, when this was found again during a defect
 * review. Two years of good intentions in a comment do not mask a key.
 *
 * WHAT IT DOES
 *
 * Values are walked recursively and any leaf whose KEY looks like a
 * credential is masked. Separately, any string whose VALUE has the shape of a
 * known credential (Stripe sk_/rk_, Google AIza, GitHub ghp_, Slack xox*) is
 * masked even when its key looks innocent - defence in depth for secrets
 * stored under a bland name.
 *
 * Masking is never silent. The response carries a `masked` array listing the
 * dot-paths that were withheld, so a caller can tell the difference between
 * "this field is empty" and "this field was hidden from you".
 *
 * There is deliberately no override parameter. An endpoint with a
 * ?show_secrets=1 escape hatch is an endpoint that leaks secrets. If a human
 * genuinely needs a raw credential, they read it in wp-admin.
 */

/**
 * Key names that identify a credential. Matched case-insensitively against
 * each array key, and against the option name itself for scalar values.
 *
 * @return string Regex.
 */
function ans_bridge_secret_key_pattern() {
	return '/(secret|password|passwd|_pwd\b|api[_\-]?key|apikey|access[_\-]?token|refresh[_\-]?token|auth[_\-]?token|bearer|private[_\-]?key|client[_\-]?secret|credential|webhook|signing|_salt\b|^salt$|licen[cs]e[_\-]?key|_key$|^key$)/i';
}

/**
 * Value shapes that are credentials regardless of what they are called.
 *
 * @return string Regex.
 */
function ans_bridge_secret_value_pattern() {
	return '/^(sk_live_|sk_test_|rk_live_|rk_test_|whsec_|pk_live_|AIza[0-9A-Za-z\-_]{10,}|ghp_|gho_|ghs_|github_pat_|xox[abprs]-|ya29\.|-----BEGIN [A-Z ]*PRIVATE KEY)/';
}

/**
 * Mask a credential for display: enough to recognise, not enough to use.
 *
 * @param mixed $value Raw value.
 * @return string
 */
function ans_bridge_mask( $value ) {
	if ( is_array( $value ) || is_object( $value ) ) {
		return '[masked]';
	}
	$value = (string) $value;
	$len   = strlen( $value );
	if ( 0 === $len ) {
		return '';
	}
	if ( $len <= 8 ) {
		return str_repeat( '*', $len );
	}
	return str_repeat( '*', $len - 4 ) . substr( $value, -4 );
}

/**
 * Should this key/value pair be masked?
 *
 * @param string $key   Array key (or option name at the top level).
 * @param mixed  $value Value at that key.
 * @return bool
 */
function ans_bridge_is_secret( $key, $value ) {
	if ( '' !== (string) $key && preg_match( ans_bridge_secret_key_pattern(), (string) $key ) ) {
		return true;
	}
	if ( is_string( $value ) && '' !== $value && preg_match( ans_bridge_secret_value_pattern(), $value ) ) {
		return true;
	}
	return false;
}

/**
 * Walk a value, masking anything that looks like a credential.
 *
 * @param mixed  $value  Value to sanitise.
 * @param string $path   Dot-path of $value, for the report.
 * @param array  $masked Collected dot-paths, by reference.
 * @param int    $depth  Recursion guard.
 * @return mixed Sanitised copy.
 */
function ans_bridge_scrub( $value, $path, &$masked, $depth = 0 ) {
	if ( $depth > 12 ) {
		return '[too deep]';
	}

	if ( is_object( $value ) ) {
		$value = get_object_vars( $value );
	}

	if ( is_array( $value ) ) {
		$out = array();
		foreach ( $value as $k => $v ) {
			$child = ( '' === $path ) ? (string) $k : $path . '.' . $k;
			if ( ans_bridge_is_secret( $k, $v ) ) {
				$out[ $k ]  = ans_bridge_mask( $v );
				$masked[]   = $child;
				continue;
			}
			$out[ $k ] = ans_bridge_scrub( $v, $child, $masked, $depth + 1 );
		}
		return $out;
	}

	return $value;
}

add_action( 'rest_api_init', function () {

	// Only users who can edit theme options (admins) may use these routes.
	$permission = function () {
		return current_user_can( 'edit_theme_options' );
	};

	/**
	 * GET /wp-json/ars-nova/v1/theme-mods
	 * Returns every theme_mod for the active theme, plus theme identity.
	 */
	register_rest_route( 'ars-nova/v1', '/theme-mods', array(
		'methods'             => 'GET',
		'permission_callback' => $permission,
		'callback'            => function ( WP_REST_Request $req ) {
			$theme = wp_get_theme();
			$mods  = get_theme_mods();
			if ( ! is_array( $mods ) ) {
				$mods = array();
			}
			$masked = array();
			$mods   = ans_bridge_scrub( $mods, '', $masked );
			return new WP_REST_Response( array(
				'theme'      => $theme->get_stylesheet(),
				'theme_name' => $theme->get( 'Name' ),
				'count'      => count( $mods ),
				'mods'       => $mods,
				'masked'     => $masked,
			), 200 );
		},
	) );

	/**
	 * POST /wp-json/ars-nova/v1/theme-mods
	 * Body: { "mods": { "<key>": <value>, ... }, "remove": ["<key>", ...] }
	 * Sets and/or removes named theme_mods, then returns the full updated set.
	 */
	register_rest_route( 'ars-nova/v1', '/theme-mods', array(
		'methods'             => 'POST',
		'permission_callback' => $permission,
		'callback'            => function ( WP_REST_Request $req ) {
			$body = $req->get_json_params();
			if ( ! is_array( $body ) ) {
				$body = array();
			}

			$set    = ( isset( $body['mods'] ) && is_array( $body['mods'] ) ) ? $body['mods'] : array();
			$remove = ( isset( $body['remove'] ) && is_array( $body['remove'] ) ) ? $body['remove'] : array();

			if ( empty( $set ) && empty( $remove ) ) {
				return new WP_Error(
					'no_changes',
					'Provide "mods" (object of key:value) and/or "remove" (array of keys).',
					array( 'status' => 400 )
				);
			}

			$changed = array();
			foreach ( $set as $key => $value ) {
				set_theme_mod( $key, $value );
				$changed[ $key ] = $value;
			}

			$removed = array();
			foreach ( $remove as $key ) {
				remove_theme_mod( $key );
				$removed[] = $key;
			}

			$masked = array();
			$mods   = ans_bridge_scrub( get_theme_mods(), '', $masked );

			return new WP_REST_Response( array(
				'ok'      => true,
				'changed' => $changed,
				'removed' => $removed,
				'mods'    => $mods,
				'masked'  => $masked,
			), 200 );
		},
	) );

	/**
	 * GET /wp-json/ars-nova/v1/option?name=<option_name>
	 * Read-only fetch of a single wp_options row (diagnostics).
	 *
	 * Credentials are masked - see the docblock at the top of this file, and
	 * the 2026-08-18 Stripe secret-key incident that is the reason for it.
	 */
	register_rest_route( 'ars-nova/v1', '/option', array(
		'methods'             => 'GET',
		'permission_callback' => $permission,
		'callback'            => function ( WP_REST_Request $req ) {
			$name = sanitize_text_field( (string) $req->get_param( 'name' ) );
			if ( '' === $name ) {
				return new WP_Error( 'missing_name', 'Pass ?name=option_name', array( 'status' => 400 ) );
			}

			$value  = get_option( $name, null );
			$masked = array();

			// A scalar option whose NAME is credential-shaped is masked whole.
			if ( ! is_array( $value ) && ! is_object( $value ) && ans_bridge_is_secret( $name, $value ) ) {
				$value    = ans_bridge_mask( $value );
				$masked[] = $name;
			} else {
				$value = ans_bridge_scrub( $value, '', $masked );
			}

			return new WP_REST_Response( array(
				'name'   => $name,
				'value'  => $value,
				'masked' => $masked,
				'note'   => empty( $masked )
					? 'No credential-shaped fields found.'
					: 'Credential-shaped fields were masked. Read them in wp-admin if genuinely required; this endpoint has no override by design.',
			), 200 );
		},
	) );

	/**
	 * Shared implementation for the sandboxed source-file readers below.
	 *
	 * $root is an absolute directory. The requested path is resolved with
	 * realpath() and must still sit inside $root afterwards, which is what
	 * stops ../ traversal. Directory -> listing. File -> contents, capped.
	 */
	$read_sandboxed = function ( $root, $rel, $label ) {
		$root = realpath( $root );
		if ( false === $root ) {
			return new WP_Error( 'no_root', ucfirst( $label ) . ' root not found.', array( 'status' => 500 ) );
		}

		$rel    = ltrim( str_replace( '\\', '/', (string) $rel ), '/' );
		$target = realpath( $root . ( '' === $rel ? '' : '/' . $rel ) );

		// Sandbox: resolved path must stay inside the root directory.
		if ( false === $target || 0 !== strpos( $target, $root ) ) {
			return new WP_Error( 'bad_path', 'Path is outside the ' . $label . ' directory.', array( 'status' => 400 ) );
		}

		if ( is_dir( $target ) ) {
			$entries = array();
			foreach ( scandir( $target ) as $entry ) {
				if ( '.' === $entry || '..' === $entry ) {
					continue;
				}
				$full      = $target . '/' . $entry;
				$entries[] = array(
					'name' => $entry,
					'type' => is_dir( $full ) ? 'dir' : 'file',
					'size' => is_file( $full ) ? filesize( $full ) : null,
				);
			}
			return new WP_REST_Response( array(
				'path'    => $rel,
				'type'    => 'dir',
				'entries' => $entries,
			), 200 );
		}

		if ( is_file( $target ) ) {
			$size = filesize( $target );
			if ( $size > 500000 ) {
				return new WP_Error( 'too_large', 'File is ' . $size . ' bytes (cap 500 KB). Read a more specific file.', array( 'status' => 413 ) );
			}
			return new WP_REST_Response( array(
				'path'     => $rel,
				'type'     => 'file',
				'size'     => $size,
				'contents' => file_get_contents( $target ),
			), 200 );
		}

		return new WP_Error( 'not_found', 'No such file or directory.', array( 'status' => 404 ) );
	};

	/**
	 * GET /wp-json/ars-nova/v1/theme-file?path=<relpath>
	 * Read-only access to theme source files, sandboxed to wp-content/themes.
	 * - If <relpath> is a directory (or omitted), returns a directory listing.
	 * - If <relpath> is a file, returns its contents (capped at 500 KB).
	 */
	register_rest_route( 'ars-nova/v1', '/theme-file', array(
		'methods'             => 'GET',
		'permission_callback' => $permission,
		'callback'            => function ( WP_REST_Request $req ) use ( $read_sandboxed ) {
			return $read_sandboxed( get_theme_root(), $req->get_param( 'path' ), 'themes' );
		},
	) );

	/**
	 * GET /wp-json/ars-nova/v1/plugin-file?path=<relpath>
	 * Read-only access to plugin source files, sandboxed to wp-content/plugins.
	 *
	 * Added in 1.2.0. Why: there was no way to read a DEPLOYED plugin's source,
	 * which is how plugin code drifts out of version control unnoticed. On
	 * 2026-08-13, ars-nova-ops was found running 1.1.0 on both environments
	 * while GitHub still held 1.0.0 - meaning the newer source existed only on
	 * the servers, and editing that plugin from the repo would have destroyed
	 * it. This route makes "what is actually running?" answerable.
	 *
	 * Read-only by design: there is no write counterpart, and adding one is
	 * not the intent. Independent of DISALLOW_FILE_EDIT, which governs editing
	 * through wp-admin; this never writes.
	 *
	 * Gated on activate_plugins rather than edit_theme_options - plugin source
	 * is a higher bar than theme settings.
	 *
	 * NOTE (1.3.0): this route returns source verbatim and is NOT scrubbed.
	 * Source files are code, not credentials, and masking them would defeat
	 * the "what is actually running?" purpose. Secrets belong in wp-config or
	 * an encrypted option, never in plugin source - if a credential ever shows
	 * up here, the leak is that it was committed, not that this route read it.
	 */
	register_rest_route( 'ars-nova/v1', '/plugin-file', array(
		'methods'             => 'GET',
		'permission_callback' => function () {
			return current_user_can( 'activate_plugins' );
		},
		'callback'            => function ( WP_REST_Request $req ) use ( $read_sandboxed ) {
			$root = defined( 'WP_PLUGIN_DIR' ) ? WP_PLUGIN_DIR : WP_CONTENT_DIR . '/plugins';
			return $read_sandboxed( $root, $req->get_param( 'path' ), 'plugins' );
		},
	) );

} );
