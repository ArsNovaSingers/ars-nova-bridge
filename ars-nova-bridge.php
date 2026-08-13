<?php
/**
 * Plugin Name: Ars Nova Bridge
 * Description: Exposes theme_mods (Kadence / Customizer settings), read-only options, read-only theme source files, and read-only plugin source files over the REST API so the Ars Nova WordPress connector can read and write theme settings by command. Admin-only.
 * Version: 1.2.0
 * Author: Ars Nova (Jonathan)
 * Requires at least: 5.6
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit; // No direct access.
}

/** Keep in step with the `Version:` header above and the release tag. */
define( 'ANS_BRIDGE_VERSION', '1.2.0' );

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
			return new WP_REST_Response( array(
				'theme'      => $theme->get_stylesheet(),
				'theme_name' => $theme->get( 'Name' ),
				'count'      => count( $mods ),
				'mods'       => $mods,
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

			return new WP_REST_Response( array(
				'ok'      => true,
				'changed' => $changed,
				'removed' => $removed,
				'mods'    => get_theme_mods(),
			), 200 );
		},
	) );

	/**
	 * GET /wp-json/ars-nova/v1/option?name=<option_name>
	 * Read-only fetch of a single wp_options row (diagnostics).
	 */
	register_rest_route( 'ars-nova/v1', '/option', array(
		'methods'             => 'GET',
		'permission_callback' => $permission,
		'callback'            => function ( WP_REST_Request $req ) {
			$name = sanitize_text_field( (string) $req->get_param( 'name' ) );
			if ( '' === $name ) {
				return new WP_Error( 'missing_name', 'Pass ?name=option_name', array( 'status' => 400 ) );
			}
			return new WP_REST_Response( array(
				'name'  => $name,
				'value' => get_option( $name, null ),
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
