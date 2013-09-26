/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*-
 *
 * Copyright (C) 2009-2010 Richard Hughes <richard@hughsie.com>
 *
 * Licensed under the GNU General Public License Version 2
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/**
 * SECTION:mcm-device
 * @short_description: Color managed device object
 *
 * This object represents a device that can be colour managed.
 */

#include "config.h"

#include <glib-object.h>

#include "mcm-device.h"
#include "mcm-profile.h"
#include "mcm-utils.h"

#include "egg-debug.h"

static void     mcm_device_finalize	(GObject     *object);

#define MCM_DEVICE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), MCM_TYPE_DEVICE, McmDevicePrivate))

/**
 * McmDevicePrivate:
 *
 * Private #McmDevice data
 **/
struct _McmDevicePrivate
{
	gboolean		 connected;
	gboolean		 virtual;
	gboolean		 saved;
	gfloat			 gamma;
	gfloat			 brightness;
	gfloat			 contrast;
	McmDeviceKind		 kind;
	gchar			*id;
	gchar			*serial;
	gchar			*manufacturer;
	gchar			*model;
	GPtrArray		*profiles;
	gchar			*title;
	GSettings		*settings;
	McmColorspace		 colorspace;
	guint			 changed_id;
	glong			 modified_time;
};

enum {
	PROP_0,
	PROP_KIND,
	PROP_ID,
	PROP_CONNECTED,
	PROP_VIRTUAL,
	PROP_SAVED,
	PROP_SERIAL,
	PROP_MODEL,
	PROP_MANUFACTURER,
	PROP_GAMMA,
	PROP_BRIGHTNESS,
	PROP_CONTRAST,
	PROP_PROFILES,
	PROP_TITLE,
	PROP_COLORSPACE,
	PROP_LAST
};

enum {
	SIGNAL_CHANGED,
	SIGNAL_LAST
};

static guint signals[SIGNAL_LAST] = { 0 };

G_DEFINE_TYPE (McmDevice, mcm_device, G_TYPE_OBJECT)

#define MCM_DEVICE_CHANGED_SUPRESS_TIMEOUT	10	/* ms */

/**
 * mcm_device_changed_cb:
 **/
static gboolean
mcm_device_changed_cb (McmDevice *device)
{
	/* emit a signal */
	egg_debug ("emit changed: %s", mcm_device_get_id (device));
	g_signal_emit (device, signals[SIGNAL_CHANGED], 0);
	device->priv->changed_id = 0;
	return FALSE;
}

/**
 * mcm_device_changed:
 **/
static void
mcm_device_changed (McmDevice *device)
{
	static GStaticMutex mutex = G_STATIC_MUTEX_INIT;

	/* lock */
	g_static_mutex_lock (&mutex);

	/* already queued, so ignoring */
	if (device->priv->changed_id != 0)
		goto out;

	/* adding to queue */
	device->priv->changed_id = g_timeout_add_full (G_PRIORITY_DEFAULT_IDLE,
						       MCM_DEVICE_CHANGED_SUPRESS_TIMEOUT,
						       (GSourceFunc) mcm_device_changed_cb,
						       g_object_ref (device),
						       (GDestroyNotify) g_object_unref);
#if GLIB_CHECK_VERSION(2,25,8)
	g_source_set_name_by_id (device->priv->changed_id, "[McmDevice] device changed");
#endif
out:
	/* unlock */
	g_static_mutex_unlock (&mutex);
}

/**
 * mcm_device_kind_from_string:
 **/
McmDeviceKind
mcm_device_kind_from_string (const gchar *kind)
{
	if (g_strcmp0 (kind, "display") == 0)
		return MCM_DEVICE_KIND_DISPLAY;
	if (g_strcmp0 (kind, "scanner") == 0)
		return MCM_DEVICE_KIND_SCANNER;
	if (g_strcmp0 (kind, "printer") == 0)
		return MCM_DEVICE_KIND_PRINTER;
	if (g_strcmp0 (kind, "camera") == 0)
		return MCM_DEVICE_KIND_CAMERA;
	return MCM_DEVICE_KIND_UNKNOWN;
}

/**
 * mcm_device_kind_to_string:
 **/
const gchar *
mcm_device_kind_to_string (McmDeviceKind kind)
{
	if (kind == MCM_DEVICE_KIND_DISPLAY)
		return "display";
	if (kind == MCM_DEVICE_KIND_SCANNER)
		return "scanner";
	if (kind == MCM_DEVICE_KIND_PRINTER)
		return "printer";
	if (kind == MCM_DEVICE_KIND_CAMERA)
		return "camera";
	return "unknown";
}

/**
 * mcm_device_load_from_default_profile:
 **/
static gboolean
mcm_device_load_from_default_profile (McmDevice *device, GError **error)
{
	gboolean ret = TRUE;
	McmProfile *profile;
	McmDevicePrivate *priv = device->priv;

	g_return_val_if_fail (MCM_IS_DEVICE (device), FALSE);

	/* no profile to load */
	if (priv->profiles->len == 0)
		goto out;

	/* if the profile was deleted */
	profile = g_ptr_array_index (priv->profiles, 0);
	ret = g_file_test (mcm_profile_get_filename (profile), G_FILE_TEST_EXISTS);
	if (!ret) {
		egg_warning ("the file was deleted and can't be loaded: %s", mcm_profile_get_filename (profile));
		/* this is not fatal */
		ret = TRUE;
		goto out;
 	}
out:
	return ret;
}

/**
 * mcm_device_get_kind:
 **/
McmDeviceKind
mcm_device_get_kind (McmDevice *device)
{
	g_return_val_if_fail (MCM_IS_DEVICE (device), MCM_DEVICE_KIND_UNKNOWN);
	return device->priv->kind;
}

/**
 * mcm_device_set_kind:
 **/
void
mcm_device_set_kind (McmDevice *device, McmDeviceKind kind)
{
	g_return_if_fail (MCM_IS_DEVICE (device));
	if (device->priv->kind != kind) {
		device->priv->kind = kind;
		mcm_device_changed (device);
	}
}

/**
 * mcm_device_get_connected:
 **/
gboolean
mcm_device_get_connected (McmDevice *device)
{
	g_return_val_if_fail (MCM_IS_DEVICE (device), FALSE);
	return device->priv->connected;
}

/**
 * mcm_device_set_connected:
 **/
void
mcm_device_set_connected (McmDevice *device, gboolean connected)
{
	g_return_if_fail (MCM_IS_DEVICE (device));
	if (device->priv->connected != connected) {
		device->priv->connected = connected;
		mcm_device_changed (device);
	}
}

/**
 * mcm_device_get_virtual:
 **/
gboolean
mcm_device_get_virtual (McmDevice *device)
{
	g_return_val_if_fail (MCM_IS_DEVICE (device), FALSE);
	return device->priv->virtual;
}

/**
 * mcm_device_set_virtual:
 **/
void
mcm_device_set_virtual (McmDevice *device, gboolean virtual)
{
	g_return_if_fail (MCM_IS_DEVICE (device));
	device->priv->virtual = virtual;
	mcm_device_changed (device);
}

/**
 * mcm_device_get_saved:
 **/
gboolean
mcm_device_get_saved (McmDevice *device)
{
	g_return_val_if_fail (MCM_IS_DEVICE (device), FALSE);
	return device->priv->saved;
}

/**
 * mcm_device_set_saved:
 **/
void
mcm_device_set_saved (McmDevice *device, gboolean saved)
{
	g_return_if_fail (MCM_IS_DEVICE (device));
	device->priv->saved = saved;
	mcm_device_changed (device);
}

/**
 * mcm_device_get_gamma:
 **/
gfloat
mcm_device_get_gamma (McmDevice *device)
{
	g_return_val_if_fail (MCM_IS_DEVICE (device), 0.0f);
	return device->priv->gamma;
}

/**
 * mcm_device_set_gamma:
 **/
void
mcm_device_set_gamma (McmDevice *device, gfloat gamma)
{
	g_return_if_fail (MCM_IS_DEVICE (device));
	device->priv->gamma = gamma;
	mcm_device_changed (device);
}

/**
 * mcm_device_get_brightness:
 **/
gfloat
mcm_device_get_brightness (McmDevice *device)
{
	g_return_val_if_fail (MCM_IS_DEVICE (device), 0.0f);
	return device->priv->brightness;
}

/**
 * mcm_device_set_brightness:
 **/
void
mcm_device_set_brightness (McmDevice *device, gfloat brightness)
{
	g_return_if_fail (MCM_IS_DEVICE (device));
	device->priv->brightness = brightness;
	mcm_device_changed (device);
}

/**
 * mcm_device_get_contrast:
 **/
gfloat
mcm_device_get_contrast (McmDevice *device)
{
	g_return_val_if_fail (MCM_IS_DEVICE (device), 0.0f);
	return device->priv->contrast;
}

/**
 * mcm_device_set_contrast:
 **/
void
mcm_device_set_contrast (McmDevice *device, gfloat contrast)
{
	g_return_if_fail (MCM_IS_DEVICE (device));
	device->priv->contrast = contrast;
	mcm_device_changed (device);
}

/**
 * mcm_device_get_colorspace:
 **/
McmColorspace
mcm_device_get_colorspace (McmDevice *device)
{
	g_return_val_if_fail (MCM_IS_DEVICE (device), MCM_COLORSPACE_UNKNOWN);
	return device->priv->colorspace;
}

/**
 * mcm_device_set_colorspace:
 **/
void
mcm_device_set_colorspace (McmDevice *device, McmColorspace colorspace)
{
	g_return_if_fail (MCM_IS_DEVICE (device));
	device->priv->colorspace = colorspace;
	mcm_device_changed (device);
}

/**
 * mcm_device_get_id:
 **/
const gchar *
mcm_device_get_id (McmDevice *device)
{
	g_return_val_if_fail (MCM_IS_DEVICE (device), NULL);
	return device->priv->id;
}

/**
 * mcm_device_set_id:
 **/
void
mcm_device_set_id (McmDevice *device, const gchar *id)
{
	g_return_if_fail (MCM_IS_DEVICE (device));
	g_free (device->priv->id);
	device->priv->id = g_strdup (id);
	mcm_device_changed (device);
}

/**
 * mcm_device_get_serial:
 **/
const gchar *
mcm_device_get_serial (McmDevice *device)
{
	g_return_val_if_fail (MCM_IS_DEVICE (device), NULL);
	return device->priv->serial;
}

/**
 * mcm_device_set_serial:
 **/
void
mcm_device_set_serial (McmDevice *device, const gchar *serial)
{
	g_return_if_fail (MCM_IS_DEVICE (device));
	g_free (device->priv->serial);
	device->priv->serial = g_strdup (serial);
	mcm_device_changed (device);
}

/**
 * mcm_device_get_manufacturer:
 **/
const gchar *
mcm_device_get_manufacturer (McmDevice *device)
{
	g_return_val_if_fail (MCM_IS_DEVICE (device), NULL);
	return device->priv->manufacturer;
}

/**
 * mcm_device_set_manufacturer:
 **/
void
mcm_device_set_manufacturer (McmDevice *device, const gchar *manufacturer)
{
	g_return_if_fail (MCM_IS_DEVICE (device));
	g_free (device->priv->manufacturer);
	device->priv->manufacturer = g_strdup (manufacturer);
	mcm_device_changed (device);
}

/**
 * mcm_device_get_model:
 **/
const gchar *
mcm_device_get_model (McmDevice *device)
{
	g_return_val_if_fail (MCM_IS_DEVICE (device), NULL);
	return device->priv->model;
}

/**
 * mcm_device_set_model:
 **/
void
mcm_device_set_model (McmDevice *device, const gchar *model)
{
	g_return_if_fail (MCM_IS_DEVICE (device));
	g_free (device->priv->model);
	device->priv->model = g_strdup (model);
	mcm_device_changed (device);
}

/**
 * mcm_device_get_title:
 **/
const gchar *
mcm_device_get_title (McmDevice *device)
{
	g_return_val_if_fail (MCM_IS_DEVICE (device), NULL);
	return device->priv->title;
}

/**
 * mcm_device_set_title:
 **/
void
mcm_device_set_title (McmDevice *device, const gchar *title)
{
	g_return_if_fail (MCM_IS_DEVICE (device));
	g_free (device->priv->title);
	device->priv->title = g_strdup (title);
	mcm_device_changed (device);
}

/**
 * mcm_device_get_profiles:
 *
 * Return value: the profiles. Free with g_ptr_array_unref()
 **/
GPtrArray *
mcm_device_get_profiles (McmDevice *device)
{
	g_return_val_if_fail (MCM_IS_DEVICE (device), NULL);
	return g_ptr_array_ref (device->priv->profiles);
}

/**
 * mcm_device_set_profiles:
 **/
void
mcm_device_set_profiles (McmDevice *device, GPtrArray *profiles)
{
	g_return_if_fail (MCM_IS_DEVICE (device));
	g_return_if_fail (profiles != NULL);

	g_ptr_array_unref (device->priv->profiles);
	device->priv->profiles = g_ptr_array_ref (profiles);
	mcm_device_changed (device);
}

/**
 * mcm_device_get_default_profile_filename:
 **/
const gchar *
mcm_device_get_default_profile_filename (McmDevice *device)
{
	McmProfile *profile;
	g_return_val_if_fail (MCM_IS_DEVICE (device), NULL);
	if (device->priv->profiles->len == 0)
		return NULL;
	profile = g_ptr_array_index (device->priv->profiles, 0);
	return mcm_profile_get_filename (profile);
}

/**
 * mcm_device_get_default_profile:
 **/
McmProfile *
mcm_device_get_default_profile (McmDevice *device)
{
	McmProfile *profile;
	g_return_val_if_fail (MCM_IS_DEVICE (device), NULL);
	if (device->priv->profiles->len == 0)
		return NULL;
	profile = g_ptr_array_index (device->priv->profiles, 0);
	return profile;
}

/**
 * mcm_device_set_default_profile_filename:
 **/
void
mcm_device_set_default_profile_filename (McmDevice *device, const gchar *profile_filename)
{
	McmProfile *profile;
	GPtrArray *array;
	gboolean ret;
	GFile *file;
	GError *error = NULL;

	g_return_if_fail (MCM_IS_DEVICE (device));

	/* create new list */
	array = g_ptr_array_new_with_free_func ((GDestroyNotify) g_object_unref);
	profile = mcm_profile_default_new ();

	/* TODO: parse here? */
	file = g_file_new_for_path (profile_filename);
	ret = mcm_profile_parse (profile, file, &error);
	if (!ret) {
		egg_warning ("failed to parse: %s", error->message);
		g_error_free (error);
		goto out;
	}

	/* FIXME: don't just nuke the list */
	g_ptr_array_add (array, g_object_ref (profile));
	mcm_device_set_profiles (device, array);
out:
	g_ptr_array_unref (array);
	g_object_unref (profile);
	g_object_unref (file);
}

/**
 * mcm_device_get_modified_time:
 **/
glong
mcm_device_get_modified_time (McmDevice *device)
{
	g_return_val_if_fail (MCM_IS_DEVICE (device), 0);
	return device->priv->modified_time;
}

/**
 * mcm_device_load:
 **/
gboolean
mcm_device_load (McmDevice *device, GError **error)
{
	gboolean ret;
	GKeyFile *file = NULL;
	GError *error_local = NULL;
	gchar *filename = NULL;
	GTimeVal timeval;
	gchar *iso_date = NULL;
	gchar **profile_filenames = NULL;
	guint i;
	McmProfile *profile;
	GFile *file_tmp;
	McmDevicePrivate *priv = device->priv;

	g_return_val_if_fail (MCM_IS_DEVICE (device), FALSE);
	g_return_val_if_fail (priv->id != NULL, FALSE);

	/* get default config */
	filename = mcm_utils_get_default_config_location ();

	/* check we have a config, or is this first start */
	ret = g_file_test (filename, G_FILE_TEST_EXISTS);
	if (!ret) {
		/* we have no profile to load from */
		ret = TRUE;
		goto out;
	}

	/* load existing file */
	file = g_key_file_new ();
	ret = g_key_file_load_from_file (file, filename, G_KEY_FILE_NONE, &error_local);
	if (!ret) {
		/* not fatal */
		egg_warning ("failed to load from file: %s", error_local->message);
		g_error_free (error_local);
		ret = TRUE;
		goto out;
	}

	/* has key */
	ret = g_key_file_has_group (file, priv->id);
	if (!ret) {
		/* not fatal */
		egg_debug ("failed to find saved parameters for %s", priv->id);
		ret = TRUE;
		goto out;
	}

	/* we are backed by a keyfile */
	mcm_device_set_saved (device, TRUE);

	/* load data */
	g_ptr_array_set_size (priv->profiles, 0);

	/* parse filenames to object, skipping entries that fail to parse */
	profile_filenames = g_key_file_get_string_list (file, priv->id, "profile", NULL, NULL);
	if (profile_filenames != NULL) {
		for (i=0; profile_filenames[i] != NULL; i++) {
			file_tmp = g_file_new_for_path (profile_filenames[i]);
			profile = mcm_profile_default_new ();
			ret = mcm_profile_parse (profile, file_tmp, &error_local);
			if (ret) {
				g_ptr_array_add (priv->profiles, g_object_ref (profile));
			} else {
				egg_warning ("failed to parse %s: %s", profile_filenames[i], error_local->message);
				g_clear_error (&error_local);
			}
			g_object_unref (profile);
			g_object_unref (file_tmp);
		}
	}

	if (priv->serial == NULL)
		priv->serial = g_key_file_get_string (file, priv->id, "serial", NULL);
	if (priv->model == NULL)
		priv->model = g_key_file_get_string (file, priv->id, "model", NULL);
	if (priv->manufacturer == NULL)
		priv->manufacturer = g_key_file_get_string (file, priv->id, "manufacturer", NULL);
	priv->gamma = g_key_file_get_double (file, priv->id, "gamma", &error_local);
	if (error_local != NULL) {
		priv->gamma = g_settings_get_double (priv->settings, MCM_SETTINGS_DEFAULT_GAMMA);
		if (priv->gamma < 0.1f)
			priv->gamma = 1.0f;
		g_clear_error (&error_local);
	}
	priv->brightness = g_key_file_get_double (file, priv->id, "brightness", &error_local);
	if (error_local != NULL) {
		priv->brightness = 0.0f;
		g_clear_error (&error_local);
	}
	priv->contrast = g_key_file_get_double (file, priv->id, "contrast", &error_local);
	if (error_local != NULL) {
		priv->contrast = 100.0f;
		g_clear_error (&error_local);
	}

	/* get modified time */
	iso_date = g_key_file_get_string (file, priv->id, "modified", NULL);
	if (iso_date != NULL) {
		ret = g_time_val_from_iso8601 (iso_date, &timeval);
		if (!ret) {
			egg_warning ("failed to parse: %s", iso_date);
			g_get_current_time (&timeval);
		}
	} else {
		/* just use the current time */
		g_get_current_time (&timeval);
	}
	priv->modified_time = timeval.tv_sec;

	/* load this */
	ret = mcm_device_load_from_default_profile (device, &error_local);
	if (!ret) {

		/* just print a warning, this is not fatal */
		egg_warning ("failed to load profile %s", error_local->message);
		g_error_free (error_local);

		/* recover as the file might have been corrupted */
		g_ptr_array_set_size (priv->profiles, 0);
		ret = TRUE;
	}
out:
	g_strfreev (profile_filenames);
	g_free (iso_date);
	g_free (filename);
	if (file != NULL)
		g_key_file_free (file);
	return ret;
}

/**
 * mcm_device_save:
 **/
gboolean
mcm_device_save (McmDevice *device, GError **error)
{
	GKeyFile *keyfile = NULL;
	guint i;
	gboolean ret;
	gchar *data = NULL;
	gchar *dirname;
	GFile *file = NULL;
	gchar *filename = NULL;
	gchar *timespec = NULL;
	gchar **profile_filenames;
	gchar *config_data = NULL;
	gchar **config_items = NULL;
	GError *error_local = NULL;
	GTimeVal timeval;
	McmProfile *profile;
	McmDevicePrivate *priv = device->priv;
	McmDeviceClass *klass = MCM_DEVICE_GET_CLASS (device);

	g_return_val_if_fail (MCM_IS_DEVICE (device), FALSE);
	g_return_val_if_fail (priv->id != NULL, FALSE);

	/* get default config */
	filename = mcm_utils_get_default_config_location ();

	/* directory exists? */
	dirname = g_path_get_dirname (filename);
	ret = g_file_test (dirname, G_FILE_TEST_IS_DIR);
	if (!ret) {
		file = g_file_new_for_path (dirname);
		ret = g_file_make_directory_with_parents (file, NULL, &error_local);
		if (!ret) {
			g_set_error (error, 1, 0, "failed to create config directory: %s", error_local->message);
			g_error_free (error_local);
			goto out;
		}
	}

	/* if not ever created, then just create a dummy file */
	ret = g_file_test (filename, G_FILE_TEST_EXISTS);
	if (!ret) {
		ret = g_file_set_contents (filename, "#created today", -1, &error_local);
		if (!ret) {
			g_set_error (error, 1, 0, "failed to create dummy header: %s", error_local->message);
			g_error_free (error_local);
			goto out;
		}
	}

	/* load existing file */
	keyfile = g_key_file_new ();
	ret = g_key_file_load_from_file (keyfile, filename, G_KEY_FILE_NONE, &error_local);
	if (!ret) {
		/* empty or corrupt */
		if (error_local->code == G_KEY_FILE_ERROR_PARSE) {
			/* ignore */
			g_clear_error (&error_local);
		} else {
			g_set_error (error, 1, 0, "failed to load existing config: %s", error_local->message);
			g_error_free (error_local);
			goto out;
		}
	}

	/* get current date and time */
	g_get_current_time (&timeval);
	timespec = g_time_val_to_iso8601 (&timeval);

	/* the device does not have a created date and time */
	ret = g_key_file_has_key (keyfile, priv->id, "created", NULL);
	if (!ret)
		g_key_file_set_string (keyfile, priv->id, "created", timespec);

	/* add modified date */
	g_key_file_set_string (keyfile, priv->id, "modified", timespec);

	/* save data */
	if (priv->profiles->len == 0)
		g_key_file_remove_key (keyfile, priv->id, "profile", NULL);
	else {
		profile_filenames = g_new0 (gchar *, priv->profiles->len + 1);
		for (i=0; i<priv->profiles->len; i++) {
			profile = g_ptr_array_index (priv->profiles, i);
			profile_filenames[i] = g_strdup (mcm_profile_get_filename (profile));
		}
		g_key_file_set_string_list (keyfile, priv->id, "profile",
					    (const gchar * const*) profile_filenames,
					    priv->profiles->len);
		g_strfreev (profile_filenames);
	}

	/* save device specific data */
	if (priv->serial == NULL)
		g_key_file_remove_key (keyfile, priv->id, "serial", NULL);
	else
		g_key_file_set_string (keyfile, priv->id, "serial", priv->serial);
	if (priv->model == NULL)
		g_key_file_remove_key (keyfile, priv->id, "model", NULL);
	else
		g_key_file_set_string (keyfile, priv->id, "model", priv->model);
	if (priv->manufacturer == NULL)
		g_key_file_remove_key (keyfile, priv->id, "manufacturer", NULL);
	else
		g_key_file_set_string (keyfile, priv->id, "manufacturer", priv->manufacturer);

	/* only save gamma if not the default */
	if (priv->gamma > 0.99 && priv->gamma < 1.01)
		g_key_file_remove_key (keyfile, priv->id, "gamma", NULL);
	else
		g_key_file_set_double (keyfile, priv->id, "gamma", priv->gamma);

	/* only save brightness if not the default */
	if (priv->brightness > -0.01 && priv->brightness < 0.01)
		g_key_file_remove_key (keyfile, priv->id, "brightness", NULL);
	else
		g_key_file_set_double (keyfile, priv->id, "brightness", priv->brightness);

	/* only save contrast if not the default */
	if (priv->contrast > 99.9 && priv->contrast < 100.1)
		g_key_file_remove_key (keyfile, priv->id, "contrast", NULL);
	else
		g_key_file_set_double (keyfile, priv->id, "contrast", priv->contrast);

	/* save other properties we'll need if we add this device offline */
	if (priv->title != NULL)
		g_key_file_set_string (keyfile, priv->id, "title", priv->title);
	g_key_file_set_string (keyfile, priv->id, "type", mcm_device_kind_to_string (priv->kind));

	/* add colorspace */
	g_key_file_set_string (keyfile, priv->id, "colorspace", mcm_colorspace_to_string (priv->colorspace));

	/* add virtual */
	if (priv->virtual)
		g_key_file_set_boolean (keyfile, priv->id, "virtual", TRUE);

	/* get extra, device specific config data */
	if (klass->get_config_data != NULL) {
		config_data = klass->get_config_data (device);
		config_items = g_strsplit (config_data, "=", 2);
		if (g_strv_length (config_items) != 2) {
			ret = FALSE;
			g_set_error (error, 1, 0, "failed to get device specific config data for: %s", priv->id);
			goto out;
		}

		/* save unstructured data to the keyfile */
		g_key_file_set_string (keyfile, priv->id, config_items[0], config_items[1]);
	}

	/* convert to string */
	data = g_key_file_to_data (keyfile, NULL, &error_local);
	if (data == NULL) {
		ret = FALSE;
		g_set_error (error, 1, 0, "failed to convert config: %s", error_local->message);
		g_error_free (error_local);
		goto out;
	}

	/* save contents */
	ret = g_file_set_contents (filename, data, -1, &error_local);
	if (!ret) {
		g_set_error (error, 1, 0, "failed to save config: %s", error_local->message);
		g_error_free (error_local);
		goto out;
	}

	/* update status */
	mcm_device_set_saved (device, TRUE);
out:
	g_strfreev (config_items);
	g_free (config_data);
	g_free (timespec);
	g_free (data);
	g_free (filename);
	g_free (dirname);
	if (file != NULL)
		g_object_unref (file);
	if (keyfile != NULL)
		g_key_file_free (keyfile);
	return ret;
}

/**
 * mcm_device_apply:
 **/
gboolean
mcm_device_apply (McmDevice *device, GError **error)
{
	gboolean ret = TRUE;
	McmDeviceClass *klass = MCM_DEVICE_GET_CLASS (device);

	/* no support */
	if (klass->apply == NULL) {
		egg_debug ("no klass support for %s", device->priv->id);
		goto out;
	}

	/* run the callback */
	ret = klass->apply (device, error);
out:
	return ret;
}

/**
 * mcm_device_get_property:
 **/
static void
mcm_device_get_property (GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
	McmDevice *device = MCM_DEVICE (object);
	McmDevicePrivate *priv = device->priv;

	switch (prop_id) {
	case PROP_KIND:
		g_value_set_uint (value, priv->kind);
		break;
	case PROP_ID:
		g_value_set_string (value, priv->id);
		break;
	case PROP_CONNECTED:
		g_value_set_boolean (value, priv->connected);
		break;
	case PROP_VIRTUAL:
		g_value_set_boolean (value, priv->virtual);
		break;
	case PROP_SAVED:
		g_value_set_boolean (value, priv->saved);
		break;
	case PROP_SERIAL:
		g_value_set_string (value, priv->serial);
		break;
	case PROP_MODEL:
		g_value_set_string (value, priv->model);
		break;
	case PROP_MANUFACTURER:
		g_value_set_string (value, priv->manufacturer);
		break;
	case PROP_GAMMA:
		g_value_set_float (value, priv->gamma);
		break;
	case PROP_BRIGHTNESS:
		g_value_set_float (value, priv->brightness);
		break;
	case PROP_CONTRAST:
		g_value_set_float (value, priv->contrast);
		break;
	case PROP_PROFILES:
		g_value_set_pointer (value, priv->profiles);
 		break;
	case PROP_TITLE:
		g_value_set_string (value, priv->title);
		break;
	case PROP_COLORSPACE:
		g_value_set_uint (value, priv->colorspace);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/**
 * mcm_device_set_property:
 **/
static void
mcm_device_set_property (GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec)
{
	McmDevice *device = MCM_DEVICE (object);

	switch (prop_id) {
	case PROP_KIND:
		mcm_device_set_kind (device, g_value_get_uint (value));
		break;
	case PROP_ID:
		mcm_device_set_id (device, g_value_get_string (value));
		break;
	case PROP_CONNECTED:
		mcm_device_set_connected (device, g_value_get_boolean (value));
		break;
	case PROP_VIRTUAL:
		mcm_device_set_virtual (device, g_value_get_boolean (value));
		break;
	case PROP_SAVED:
		mcm_device_set_saved (device, g_value_get_boolean (value));
		break;
	case PROP_SERIAL:
		mcm_device_set_serial (device, g_value_get_string (value));
		break;
	case PROP_MODEL:
		mcm_device_set_model (device, g_value_get_string (value));
		break;
	case PROP_MANUFACTURER:
		mcm_device_set_manufacturer (device, g_value_get_string (value));
		break;
	case PROP_TITLE:
		mcm_device_set_title (device, g_value_get_string (value));
		break;
	case PROP_PROFILES:
		mcm_device_set_profiles (device, g_value_get_pointer (value));
		break;
	case PROP_GAMMA:
		mcm_device_set_gamma (device, g_value_get_float (value));
		break;
	case PROP_BRIGHTNESS:
		mcm_device_set_brightness (device, g_value_get_float (value));
		break;
	case PROP_CONTRAST:
		mcm_device_set_contrast (device, g_value_get_float (value));
		break;
	case PROP_COLORSPACE:
		mcm_device_set_colorspace (device, g_value_get_uint (value));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/**
 * mcm_device_class_init:
 **/
static void
mcm_device_class_init (McmDeviceClass *klass)
{
	GParamSpec *pspec;
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	object_class->finalize = mcm_device_finalize;
	object_class->get_property = mcm_device_get_property;
	object_class->set_property = mcm_device_set_property;

	/**
	 * McmDevice:kind:
	 */
	pspec = g_param_spec_uint ("kind", NULL, NULL,
				   0, G_MAXUINT, 0,
				   G_PARAM_READWRITE);
	g_object_class_install_property (object_class, PROP_KIND, pspec);

	/**
	 * McmDevice:id:
	 */
	pspec = g_param_spec_string ("id", NULL, NULL,
				     NULL,
				     G_PARAM_READWRITE);
	g_object_class_install_property (object_class, PROP_ID, pspec);

	/**
	 * McmDevice:connected:
	 */
	pspec = g_param_spec_boolean ("connected", NULL, NULL,
				      FALSE,
				      G_PARAM_READWRITE);
	g_object_class_install_property (object_class, PROP_CONNECTED, pspec);

	/**
	 * McmDevice:virtual:
	 */
	pspec = g_param_spec_boolean ("virtual", NULL, NULL,
				      FALSE,
				      G_PARAM_READWRITE);
	g_object_class_install_property (object_class, PROP_VIRTUAL, pspec);

	/**
	 * McmDevice:saved:
	 */
	pspec = g_param_spec_boolean ("saved", NULL, NULL,
				      FALSE,
				      G_PARAM_READWRITE);
	g_object_class_install_property (object_class, PROP_SAVED, pspec);

	/**
	 * McmCalibrate:serial:
	 */
	pspec = g_param_spec_string ("serial", NULL, NULL,
				     NULL,
				     G_PARAM_READWRITE);
	g_object_class_install_property (object_class, PROP_SERIAL, pspec);

	/**
	 * McmCalibrate:model:
	 */
	pspec = g_param_spec_string ("model", NULL, NULL,
				     NULL,
				     G_PARAM_READWRITE);
	g_object_class_install_property (object_class, PROP_MODEL, pspec);

	/**
	 * McmCalibrate:manufacturer:
	 */
	pspec = g_param_spec_string ("manufacturer", NULL, NULL,
				     NULL,
				     G_PARAM_READWRITE);
	g_object_class_install_property (object_class, PROP_MANUFACTURER, pspec);

	/**
	 * McmDevice:gamma:
	 */
	pspec = g_param_spec_float ("gamma", NULL, NULL,
				    0.0, G_MAXFLOAT, 1.01,
				    G_PARAM_READWRITE);
	g_object_class_install_property (object_class, PROP_GAMMA, pspec);

	/**
	 * McmDevice:brightness:
	 */
	pspec = g_param_spec_float ("brightness", NULL, NULL,
				    0.0, G_MAXFLOAT, 1.02,
				    G_PARAM_READWRITE);
	g_object_class_install_property (object_class, PROP_BRIGHTNESS, pspec);

	/**
	 * McmDevice:contrast:
	 */
	pspec = g_param_spec_float ("contrast", NULL, NULL,
				    0.0, G_MAXFLOAT, 1.03,
				    G_PARAM_READWRITE);
	g_object_class_install_property (object_class, PROP_CONTRAST, pspec);

	/**
	 * McmDevice:profiles:
	 */
	pspec = g_param_spec_pointer ("profiles", NULL, NULL,
				      G_PARAM_READWRITE);
	g_object_class_install_property (object_class, PROP_PROFILES, pspec);

	/**
	 * McmDevice:title:
	 */
	pspec = g_param_spec_string ("title", NULL, NULL,
				     NULL,
				     G_PARAM_READWRITE);
	g_object_class_install_property (object_class, PROP_TITLE, pspec);

	/**
	 * McmDevice:colorspace:
	 */
	pspec = g_param_spec_uint ("colorspace", NULL, NULL,
				   0, MCM_COLORSPACE_LAST, MCM_COLORSPACE_UNKNOWN,
				   G_PARAM_READWRITE);
	g_object_class_install_property (object_class, PROP_COLORSPACE, pspec);

	/**
	 * McmDevice::changed:
	 **/
	signals[SIGNAL_CHANGED] =
		g_signal_new ("changed",
			      G_TYPE_FROM_CLASS (object_class), G_SIGNAL_RUN_LAST,
			      G_STRUCT_OFFSET (McmDeviceClass, changed),
			      NULL, NULL, g_cclosure_marshal_VOID__VOID,
			      G_TYPE_NONE, 0);

	g_type_class_add_private (klass, sizeof (McmDevicePrivate));
}

/**
 * mcm_device_init:
 **/
static void
mcm_device_init (McmDevice *device)
{
	device->priv = MCM_DEVICE_GET_PRIVATE (device);
	device->priv->changed_id = 0;
	device->priv->id = NULL;
	device->priv->saved = FALSE;
	device->priv->connected = FALSE;
	device->priv->virtual = FALSE;
	device->priv->serial = NULL;
	device->priv->manufacturer = NULL;
	device->priv->model = NULL;
	device->priv->profiles = g_ptr_array_new_with_free_func ((GDestroyNotify) g_object_unref);
	device->priv->modified_time = 0;
	device->priv->settings = g_settings_new (MCM_SETTINGS_SCHEMA);
	device->priv->gamma = g_settings_get_double (device->priv->settings, MCM_SETTINGS_DEFAULT_GAMMA);
	if (device->priv->gamma < 0.01)
		device->priv->gamma = 1.0f;
	device->priv->brightness = 0.0f;
	device->priv->contrast = 100.f;
	device->priv->colorspace = MCM_COLORSPACE_UNKNOWN;
}

/**
 * mcm_device_finalize:
 **/
static void
mcm_device_finalize (GObject *object)
{
	McmDevice *device = MCM_DEVICE (object);
	McmDevicePrivate *priv = device->priv;

	/* remove any pending signal */
	if (priv->changed_id != 0)
		g_source_remove (priv->changed_id);

	g_free (priv->title);
	g_free (priv->id);
	g_free (priv->serial);
	g_free (priv->manufacturer);
	g_free (priv->model);
	g_ptr_array_unref (priv->profiles);
	g_object_unref (priv->settings);

	G_OBJECT_CLASS (mcm_device_parent_class)->finalize (object);
}

