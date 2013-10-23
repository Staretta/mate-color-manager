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

#include "config.h"

#include <glib/gi18n.h>
#include <gtk/gtk.h>
#include <math.h>
#include <glib/gstdio.h>
#include <gudev/gudev.h>
#include <libmate-desktop/mate-rr.h>
#include <locale.h>
#include <canberra-gtk.h>

#include "egg-debug.h"

#include "mcm-cell-renderer-profile.h"
#include "mcm-calibrate-argyll.h"
#include "mcm-cie-widget.h"
#include "mcm-client.h"
#include "mcm-colorimeter.h"
#include "mcm-device-xrandr.h"
#include "mcm-device-virtual.h"
#include "mcm-exif.h"
#include "mcm-profile.h"
#include "mcm-profile-store.h"
#include "mcm-trc-widget.h"
#include "mcm-utils.h"
#include "mcm-xyz.h"

typedef struct {
	GtkBuilder	*builder;
	GtkApplication	*application;
	GtkListStore	*list_store_devices;
	GtkListStore	*list_store_profiles;
	GtkListStore	*list_store_assign;
	McmDevice	*current_device;
	McmProfileStore	*profile_store;
	McmClient	*mcm_client;
	McmColorimeter	*colorimeter;
	gboolean	 setting_up_device;
	GtkWidget	*info_bar_loading;
	GtkWidget	*info_bar_vcgt;
	GtkWidget	*info_bar_profiles;
	GtkWidget	*cie_widget;
	GtkWidget	*trc_widget;
	GtkWidget	*vcgt_widget;
	GSettings	*settings;
} McmPrefsData;

enum {
	MCM_DEVICES_COLUMN_ID,
	MCM_DEVICES_COLUMN_SORT,
	MCM_DEVICES_COLUMN_ICON,
	MCM_DEVICES_COLUMN_TITLE,
	MCM_DEVICES_COLUMN_LAST
};

enum {
	MCM_PROFILES_COLUMN_ID,
	MCM_PROFILES_COLUMN_SORT,
	MCM_PROFILES_COLUMN_ICON,
	MCM_PROFILES_COLUMN_PROFILE,
	MCM_PROFILES_COLUMN_LAST
};

enum {
	MCM_ASSIGN_COLUMN_SORT,
	MCM_ASSIGN_COLUMN_PROFILE,
	MCM_ASSIGN_COLUMN_IS_DEFAULT,
	MCM_ASSIGN_COLUMN_LAST
};

enum {
	MCM_PREFS_COMBO_COLUMN_TEXT,
	MCM_PREFS_COMBO_COLUMN_PROFILE,
	MCM_PREFS_COMBO_COLUMN_TYPE,
	MCM_PREFS_COMBO_COLUMN_SORTABLE,
	MCM_PREFS_COMBO_COLUMN_LAST
};

typedef enum {
	MCM_PREFS_ENTRY_TYPE_PROFILE,
	MCM_PREFS_ENTRY_TYPE_IMPORT,
	MCM_PREFS_ENTRY_TYPE_LAST
} McmPrefsEntryType;

static void mcm_prefs_devices_treeview_clicked_cb (GtkTreeSelection *selection, McmPrefsData *prefsdata);
static void mcm_prefs_profile_store_changed_cb (McmProfileStore *profile_store, McmPrefsData *prefsdata);

#define MCM_PREFS_TREEVIEW_MAIN_WIDTH		350 /* px */
#define MCM_PREFS_TREEVIEW_PROFILES_WIDTH	450 /* px */

/**
 * mcm_prefs_error_dialog:
 **/
static void
mcm_prefs_error_dialog (McmPrefsData *prefsdata, const gchar *title, const gchar *message)
{
	GtkWindow *window;
	GtkWidget *dialog;

	window = GTK_WINDOW(gtk_builder_get_object (prefsdata->builder, "dialog_prefs"));
	dialog = gtk_message_dialog_new (window, GTK_DIALOG_MODAL, GTK_MESSAGE_ERROR, GTK_BUTTONS_CLOSE, "%s", title);
	gtk_window_set_icon_name (GTK_WINDOW (dialog), MCM_STOCK_ICON);
	gtk_message_dialog_format_secondary_text (GTK_MESSAGE_DIALOG (dialog), "%s", message);
	gtk_dialog_run (GTK_DIALOG (dialog));
	gtk_widget_destroy (dialog);
}

/**
 * mcm_prefs_close_cb:
 **/
static void
mcm_prefs_close_cb (GtkWidget *widget, McmPrefsData *prefsdata)
{
	gtk_application_quit (prefsdata->application);
}

/**
 * mcm_prefs_set_default:
 **/
static gboolean
mcm_prefs_set_default (McmPrefsData *prefsdata, McmDevice *device)
{
	GError *error = NULL;
	gboolean ret = FALSE;
	gchar *cmdline = NULL;
	const gchar *filename;
	const gchar *id;
	gchar *install_cmd = NULL;

	/* nothing set */
	id = mcm_device_get_id (device);
	filename = mcm_device_get_default_profile_filename (device);
	if (filename == NULL) {
		egg_debug ("no filename for %s", id);
		goto out;
	}

	/* run using PolicyKit */
	install_cmd = g_build_filename (SBINDIR, "mcm-install-system-wide", NULL);
	cmdline = g_strdup_printf ("pkexec %s --id %s \"%s\"", install_cmd, id, filename);
	egg_debug ("running: %s", cmdline);
	ret = g_spawn_command_line_sync (cmdline, NULL, NULL, NULL, &error);
	if (!ret) {
		/* TRANSLATORS: could not save for all users */
		mcm_prefs_error_dialog (prefsdata, _("Failed to save defaults for all users"), error->message);
		g_error_free (error);
		goto out;
	}
out:
	g_free (install_cmd);
	g_free (cmdline);
	return ret;
}

/**
 * mcm_prefs_combobox_add_profile:
 **/
static void
mcm_prefs_combobox_add_profile (GtkWidget *widget, McmProfile *profile, McmPrefsEntryType entry_type, GtkTreeIter *iter)
{
	GtkTreeModel *model;
	GtkTreeIter iter_tmp;
	const gchar *description;
	gchar *sortable;

	/* iter is optional */
	if (iter == NULL)
		iter = &iter_tmp;

	/* use description */
	if (entry_type == MCM_PREFS_ENTRY_TYPE_IMPORT) {
		/* TRANSLATORS: this is where the user can click and import a profile */
		description = _("Other profile…");
		sortable = g_strdup ("9");
	} else {
		description = mcm_profile_get_description (profile);
		sortable = g_strdup_printf ("5%s", description);
	}

	/* also add profile */
	model = gtk_combo_box_get_model (GTK_COMBO_BOX(widget));
	gtk_list_store_append (GTK_LIST_STORE(model), iter);
	gtk_list_store_set (GTK_LIST_STORE(model), iter,
			    MCM_PREFS_COMBO_COLUMN_TEXT, description,
			    MCM_PREFS_COMBO_COLUMN_PROFILE, profile,
			    MCM_PREFS_COMBO_COLUMN_TYPE, entry_type,
			    MCM_PREFS_COMBO_COLUMN_SORTABLE, sortable,
			    -1);
	g_free (sortable);
}

/**
 * mcm_prefs_default_cb:
 **/
static void
mcm_prefs_default_cb (GtkWidget *widget, McmPrefsData *prefsdata)
{
	GPtrArray *array = NULL;
	McmDevice *device;
	McmDeviceKind kind;
	gboolean ret;
	guint i;

	/* set for each output */
	array = mcm_client_get_devices (prefsdata->mcm_client);
	for (i=0; i<array->len; i++) {
		device = g_ptr_array_index (array, i);

		/* not a xrandr panel */
		kind = mcm_device_get_kind (device);
		if (kind != MCM_DEVICE_KIND_DISPLAY)
			continue;

		/* set for this device */
		ret = mcm_prefs_set_default (prefsdata, device);
		if (!ret)
			break;
	}
	g_ptr_array_unref (array);
}

/**
 * mcm_prefs_help_cb:
 **/
static void
mcm_prefs_help_cb (GtkWidget *widget, McmPrefsData *prefsdata)
{
	mcm_mate_help ("preferences");
}

/**
 * mcm_prefs_delete_event_cb:
 **/
static gboolean
mcm_prefs_delete_event_cb (GtkWidget *widget, GdkEvent *event, McmPrefsData *prefsdata)
{
	mcm_prefs_close_cb (widget, prefsdata);
	return FALSE;
}

/**
 * mcm_prefs_calibrate_display:
 **/
static gboolean
mcm_prefs_calibrate_display (McmPrefsData *prefsdata, McmCalibrate *calibrate)
{
	gboolean ret = FALSE;
	gboolean ret_tmp;
	GError *error = NULL;
	GtkWindow *window;

	/* no device */
	if (prefsdata->current_device == NULL)
		goto out;

	/* set properties from the device */
	ret = mcm_calibrate_set_from_device (calibrate, prefsdata->current_device, &error);
	if (!ret) {
		egg_warning ("failed to calibrate: %s", error->message);
		g_error_free (error);
		goto out;
	}

	/* run each task in order */
	window = GTK_WINDOW(gtk_builder_get_object (prefsdata->builder, "dialog_prefs"));
	ret = mcm_calibrate_display (calibrate, window, &error);
	if (!ret) {
		egg_warning ("failed to calibrate: %s", error->message);
		g_error_free (error);
		goto out;
	}
out:
	/* need to set the gamma back to the default after calibration */
	error = NULL;
	ret_tmp = mcm_device_apply (prefsdata->current_device, &error);
	if (!ret_tmp) {
		egg_warning ("failed to apply profile: %s", error->message);
		g_error_free (error);
	}
	return ret;
}

/**
 * mcm_prefs_calibrate_device:
 **/
static gboolean
mcm_prefs_calibrate_device (McmPrefsData *prefsdata, McmCalibrate *calibrate)
{
	gboolean ret = FALSE;
	GError *error = NULL;
	GtkWindow *window;

	/* set defaults from device */
	ret = mcm_calibrate_set_from_device (calibrate, prefsdata->current_device, &error);
	if (!ret) {
		egg_warning ("failed to calibrate: %s", error->message);
		g_error_free (error);
		goto out;
	}

	/* do each step */
	window = GTK_WINDOW(gtk_builder_get_object (prefsdata->builder, "dialog_prefs"));
	ret = mcm_calibrate_device (calibrate, window, &error);
	if (!ret) {
		if (error->code != MCM_CALIBRATE_ERROR_USER_ABORT) {
			/* TRANSLATORS: could not calibrate */
			mcm_prefs_error_dialog (prefsdata, _("Failed to calibrate device"), error->message);
		} else {
			egg_warning ("failed to calibrate: %s", error->message);
		}
		g_error_free (error);
		goto out;
	}
out:
	return ret;
}

/**
 * mcm_prefs_calibrate_printer:
 **/
static gboolean
mcm_prefs_calibrate_printer (McmPrefsData *prefsdata, McmCalibrate *calibrate)
{
	gboolean ret = FALSE;
	GError *error = NULL;
	GtkWindow *window;

	/* set defaults from device */
	ret = mcm_calibrate_set_from_device (calibrate, prefsdata->current_device, &error);
	if (!ret) {
		egg_warning ("failed to calibrate: %s", error->message);
		g_error_free (error);
		goto out;
	}

	/* do each step */
	window = GTK_WINDOW(gtk_builder_get_object (prefsdata->builder, "dialog_prefs"));
	ret = mcm_calibrate_printer (calibrate, window, &error);
	if (!ret) {
		if (error->code != MCM_CALIBRATE_ERROR_USER_ABORT) {
			/* TRANSLATORS: could not calibrate */
			mcm_prefs_error_dialog (prefsdata, _("Failed to calibrate printer"), error->message);
		} else {
			egg_warning ("failed to calibrate: %s", error->message);
		}
		g_error_free (error);
		goto out;
	}
out:
	return ret;
}

/**
 * mcm_prefs_profile_kind_to_icon_name:
 **/
static const gchar *
mcm_prefs_profile_kind_to_icon_name (McmProfileKind kind)
{
	if (kind == MCM_PROFILE_KIND_DISPLAY_DEVICE)
		return "video-display";
	if (kind == MCM_PROFILE_KIND_INPUT_DEVICE)
		return "scanner";
	if (kind == MCM_PROFILE_KIND_OUTPUT_DEVICE)
		return "printer";
	if (kind == MCM_PROFILE_KIND_COLORSPACE_CONVERSION)
		return "view-refresh";
	return "image-missing";
}

/**
 * mcm_prefs_profile_get_sort_string:
 **/
static const gchar *
mcm_prefs_profile_get_sort_string (McmProfileKind kind)
{
	if (kind == MCM_PROFILE_KIND_DISPLAY_DEVICE)
		return "1";
	if (kind == MCM_PROFILE_KIND_INPUT_DEVICE)
		return "2";
	if (kind == MCM_PROFILE_KIND_OUTPUT_DEVICE)
		return "3";
	return "4";
}

/**
 * mcm_prefs_update_profile_list:
 **/
static void
mcm_prefs_update_profile_list (McmPrefsData *prefsdata)
{
	GtkTreeIter iter;
	const gchar *description;
	const gchar *icon_name;
	McmProfileKind profile_kind = MCM_PROFILE_KIND_UNKNOWN;
	McmProfile *profile;
	guint i;
	const gchar *filename = NULL;
	gchar *sort = NULL;
	GPtrArray *profile_array = NULL;

	egg_debug ("updating profile list");

	/* get new list */
	profile_array = mcm_profile_store_get_array (prefsdata->profile_store);

	/* clear existing list */
	gtk_list_store_clear (prefsdata->list_store_profiles);

	/* update each list */
	for (i=0; i<profile_array->len; i++) {
		profile = g_ptr_array_index (profile_array, i);

		profile_kind = mcm_profile_get_kind (profile);
		icon_name = mcm_prefs_profile_kind_to_icon_name (profile_kind);
		gtk_list_store_append (prefsdata->list_store_profiles, &iter);
		description = mcm_profile_get_description (profile);
		sort = g_strdup_printf ("%s%s",
					mcm_prefs_profile_get_sort_string (profile_kind),
					description);
		filename = mcm_profile_get_filename (profile);
		egg_debug ("add %s to profiles list", filename);
		gtk_list_store_set (prefsdata->list_store_profiles, &iter,
				    MCM_PROFILES_COLUMN_ID, filename,
				    MCM_PROFILES_COLUMN_SORT, sort,
				    MCM_PROFILES_COLUMN_ICON, icon_name,
				    MCM_PROFILES_COLUMN_PROFILE, profile,
				    -1);

		g_free (sort);
	}
	if (profile_array != NULL)
		g_ptr_array_unref (profile_array);
}

/**
 * mcm_prefs_profile_delete_cb:
 **/
static void
mcm_prefs_profile_delete_cb (GtkWidget *widget, McmPrefsData *prefsdata)
{
	GtkWidget *dialog;
	GtkResponseType response;
	GtkWindow *window;
	gint retval;
	const gchar *filename;
	McmProfile *profile;
	GtkTreeSelection *selection;
	GtkTreeModel *model;
	GtkTreeIter iter;

	/* ask the user to confirm */
	window = GTK_WINDOW(gtk_builder_get_object (prefsdata->builder, "dialog_prefs"));
	dialog = gtk_message_dialog_new (window, GTK_DIALOG_DESTROY_WITH_PARENT, GTK_MESSAGE_QUESTION, GTK_BUTTONS_CANCEL,
					 /* TRANSLATORS: title, usually we can tell based on the EDID data or output name */
					 _("Permanently delete profile?"));
	gtk_message_dialog_format_secondary_text (GTK_MESSAGE_DIALOG (dialog),
						  /* TRANSLATORS: dialog message */
						  _("Are you sure you want to remove this profile from your system permanently?"));
	gtk_window_set_icon_name (GTK_WINDOW (dialog), MCM_STOCK_ICON);
	/* TRANSLATORS: button, delete a profile */
	gtk_dialog_add_button (GTK_DIALOG (dialog), _("Delete"), GTK_RESPONSE_YES);
	response = gtk_dialog_run (GTK_DIALOG (dialog));
	gtk_widget_destroy (dialog);
	if (response != GTK_RESPONSE_YES)
		goto out;

	/* get the selected row */
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "treeview_profiles"));
	selection = gtk_tree_view_get_selection (GTK_TREE_VIEW (widget));
	if (!gtk_tree_selection_get_selected (selection, &model, &iter)) {
		egg_debug ("no row selected");
		goto out;
	}

	/* get profile */
	gtk_tree_model_get (model, &iter,
			    MCM_PROFILES_COLUMN_PROFILE, &profile,
			    -1);

	/* try to remove file */
	filename = mcm_profile_get_filename (profile);
	retval = g_unlink (filename);
	if (retval != 0)
		goto out;
out:
	return;
}

/**
 * mcm_prefs_file_chooser_get_icc_profile:
 **/
static GFile *
mcm_prefs_file_chooser_get_icc_profile (McmPrefsData *prefsdata)
{
	GtkWindow *window;
	GtkWidget *dialog;
	GFile *file = NULL;
	GtkFileFilter *filter;

	/* create new dialog */
	window = GTK_WINDOW(gtk_builder_get_object (prefsdata->builder, "dialog_prefs"));
	/* TRANSLATORS: dialog for file->open dialog */
	dialog = gtk_file_chooser_dialog_new (_("Select ICC Profile File"), window,
					       GTK_FILE_CHOOSER_ACTION_OPEN,
					       GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
					       _("Import"), GTK_RESPONSE_ACCEPT,
					      NULL);
	gtk_window_set_icon_name (GTK_WINDOW (dialog), MCM_STOCK_ICON);
	gtk_file_chooser_set_current_folder (GTK_FILE_CHOOSER(dialog), g_get_home_dir ());
	gtk_file_chooser_set_create_folders (GTK_FILE_CHOOSER(dialog), FALSE);
	gtk_file_chooser_set_local_only (GTK_FILE_CHOOSER(dialog), FALSE);

	/* setup the filter */
	filter = gtk_file_filter_new ();
	gtk_file_filter_add_mime_type (filter, "application/vnd.iccprofile");

	/* we can remove this when we depend on a new shared-mime-info */
	gtk_file_filter_add_pattern (filter, "*.icc");
	gtk_file_filter_add_pattern (filter, "*.icm");
	gtk_file_filter_add_pattern (filter, "*.ICC");
	gtk_file_filter_add_pattern (filter, "*.ICM");

	/* TRANSLATORS: filter name on the file->open dialog */
	gtk_file_filter_set_name (filter, _("Supported ICC profiles"));
	gtk_file_chooser_add_filter (GTK_FILE_CHOOSER(dialog), filter);

	/* setup the all files filter */
	filter = gtk_file_filter_new ();
	gtk_file_filter_add_pattern (filter, "*");
	/* TRANSLATORS: filter name on the file->open dialog */
	gtk_file_filter_set_name (filter, _("All files"));
	gtk_file_chooser_add_filter (GTK_FILE_CHOOSER(dialog), filter);

	/* did user choose file */
	if (gtk_dialog_run (GTK_DIALOG (dialog)) == GTK_RESPONSE_ACCEPT)
		file = gtk_file_chooser_get_file (GTK_FILE_CHOOSER(dialog));

	/* we're done */
	gtk_widget_destroy (dialog);

	/* or NULL for missing */
	return file;
}

/**
 * mcm_prefs_profile_import_file:
 **/
static gboolean
mcm_prefs_profile_import_file (McmPrefsData *prefsdata, GFile *file)
{
	gboolean ret;
	GError *error = NULL;
	GFile *destination = NULL;

	/* check if correct type */
	ret = mcm_utils_is_icc_profile (file);
	if (!ret) {
		egg_debug ("not a ICC profile");
		goto out;
	}

	/* copy icc file to ~/.color/icc */
	destination = mcm_utils_get_profile_destination (file);
	ret = mcm_utils_mkdir_and_copy (file, destination, &error);
	if (!ret) {
		/* TRANSLATORS: could not read file */
		mcm_prefs_error_dialog (prefsdata, _("Failed to copy file"), error->message);
		g_error_free (error);
		goto out;
	}
out:
	if (destination != NULL)
		g_object_unref (destination);
	return ret;
}

/**
 * mcm_prefs_profile_add_virtual_file:
 **/
static gboolean
mcm_prefs_profile_add_virtual_file (McmPrefsData *prefsdata, GFile *file)
{
	gboolean ret;
	McmExif *exif;
	GError *error = NULL;
	McmDevice *device = NULL;

	/* parse file */
	exif = mcm_exif_new ();
	ret = mcm_exif_parse (exif, file, &error);
	if (!ret) {
		/* TRANSLATORS: could not add virtual device */
		if (error->domain != MCM_EXIF_ERROR ||
		    error->code != MCM_EXIF_ERROR_NO_SUPPORT)
			mcm_prefs_error_dialog (prefsdata, _("Failed to get metadata from image"), error->message);
		else
			egg_debug ("not a supported image format: %s", error->message);
		g_error_free (error);
		goto out;
	}

	/* create device */
	device = mcm_device_virtual_new	();
	ret = mcm_device_virtual_create_from_params (MCM_DEVICE_VIRTUAL (device),
						     mcm_exif_get_device_kind (exif),
						     mcm_exif_get_model (exif),
						     mcm_exif_get_manufacturer (exif),
						     mcm_exif_get_serial (exif),
						     MCM_COLORSPACE_RGB);
	if (!ret) {
		/* TRANSLATORS: could not add virtual device */
		mcm_prefs_error_dialog (prefsdata, _("Failed to create virtual device"), NULL);
		goto out;
	}

	/* save what we've got */
	ret = mcm_device_save (device, &error);
	if (!ret) {
		/* TRANSLATORS: could not add virtual device */
		mcm_prefs_error_dialog (prefsdata, _("Failed to save virtual device"), error->message);
		g_error_free (error);
		goto out;
	}

	/* add to the device list */
	ret = mcm_client_add_device (prefsdata->mcm_client, device, &error);
	if (!ret) {
		/* TRANSLATORS: could not add virtual device */
		mcm_prefs_error_dialog (prefsdata, _("Failed to add virtual device"), error->message);
		g_error_free (error);
		goto out;
	}
out:
	g_object_unref (exif);
	if (device != NULL)
		g_object_unref (device);
	return ret;
}

/**
 * mcm_prefs_profile_import_cb:
 **/
static void
mcm_prefs_profile_import_cb (GtkWidget *widget, McmPrefsData *prefsdata)
{
	GFile *file;

	/* get new file */
	file = mcm_prefs_file_chooser_get_icc_profile (prefsdata);
	if (file == NULL) {
		egg_warning ("failed to get filename");
		goto out;
	}

	/* import this */
	mcm_prefs_profile_import_file (prefsdata, file);
out:
	if (file != NULL)
		g_object_unref (file);
}

/**
 * mcm_prefs_drag_data_received_cb:
 **/
static void
mcm_prefs_drag_data_received_cb (GtkWidget *widget, GdkDragContext *context, gint x, gint y, GtkSelectionData *data, guint _time, McmPrefsData *prefsdata)
{
	const guchar *filename;
	gchar **filenames = NULL;
	GFile *file = NULL;
	guint i;
	gboolean ret;
	gboolean success = FALSE;

	/* get filenames */
	filename = gtk_selection_data_get_data (data);
	if (filename == NULL)
		goto out;

	/* import this */
	egg_debug ("dropped: %p (%s)", data, filename);

	/* split, as multiple drag targets are accepted */
	filenames = g_strsplit_set ((const gchar *)filename, "\r\n", -1);
	for (i=0; filenames[i]!=NULL; i++) {

		/* blank entry */
		if (filenames[i][0] == '\0')
			continue;

		/* convert the URI */
		file = g_file_new_for_uri (filenames[i]);

		/* try to import it */
		ret = gcm_prefs_profile_import_file (prefsdata, file);
		if (ret)
			success = TRUE;

		/* try to add a virtual profile with it */
		ret = mcm_prefs_profile_add_virtual_file (prefsdata, file);
		if (ret)
			success = TRUE;

		g_object_unref (file);
	}

out:
	gtk_drag_finish (context, success, FALSE, _time);
	g_strfreev (filenames);
}

/**
 * mcm_prefs_virtual_set_from_file:
 **/
static gboolean
mcm_prefs_virtual_set_from_file (McmPrefsData *prefsdata, GFile *file)
{
	gboolean ret;
	McmExif *exif;
	GError *error = NULL;
	const gchar *model;
	const gchar *manufacturer;
	GtkWidget *widget;

	/* parse file */
	exif = mcm_exif_new ();
	ret = mcm_exif_parse (exif, file, &error);
	if (!ret) {
		egg_warning ("failed to parse file: %s", error->message);
		g_error_free (error);
		goto out;
	}

	/* set model and manufacturer */
	model = mcm_exif_get_model (exif);
	if (model != NULL) {
		widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "entry_virtual_model"));
		gtk_entry_set_text (GTK_ENTRY (widget), model);
	}
	manufacturer = mcm_exif_get_manufacturer (exif);
	if (manufacturer != NULL) {
		widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "entry_virtual_manufacturer"));
		gtk_entry_set_text (GTK_ENTRY (widget), manufacturer);
	}

	/* set type */
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "combobox_virtual_type"));
	gtk_combo_box_set_active (GTK_COMBO_BOX(widget), MCM_DEVICE_KIND_CAMERA - 2);
out:
	g_object_unref (exif);
	return ret;
}

/**
 * mcm_prefs_virtual_drag_data_received_cb:
 **/
static void
mcm_prefs_virtual_drag_data_received_cb (GtkWidget *widget, GdkDragContext *context, gint x, gint y,
					 GtkSelectionData *data, guint _time, McmPrefsData *prefsdata)
{
	const guchar *filename;
	gchar **filenames = NULL;
	GFile *file = NULL;
	guint i;
	gboolean ret;

	/* get filenames */
	filename = gtk_selection_data_get_data (data);
	if (filename == NULL) {
		gtk_drag_finish (context, FALSE, FALSE, _time);
		goto out;
	}

	/* import this */
	egg_debug ("dropped: %p (%s)", data, filename);

	/* split, as multiple drag targets are accepted */
	filenames = g_strsplit_set ((const gchar *)filename, "\r\n", -1);
	for (i=0; filenames[i]!=NULL; i++) {

		/* blank entry */
		if (filenames[i][0] == '\0')
			continue;

		/* check this is an ICC profile */
		egg_debug ("trying to set %s", filenames[i]);
		file = g_file_new_for_uri (filenames[i]);
		ret = mcm_prefs_virtual_set_from_file (prefsdata, file);
		if (!ret) {
			egg_debug ("%s did not set from file correctly", filenames[i]);
			gtk_drag_finish (context, FALSE, FALSE, _time);
			goto out;
		}
		g_object_unref (file);
		file = NULL;
	}

	gtk_drag_finish (context, TRUE, FALSE, _time);
out:
	if (file != NULL)
		g_object_unref (file);
	g_strfreev (filenames);
}

/**
 * mcm_prefs_ensure_argyllcms_installed:
 **/
static gboolean
mcm_prefs_ensure_argyllcms_installed (McmPrefsData *prefsdata)
{
	gboolean ret;
	GtkWindow *window;
	GtkWidget *dialog;
	GtkResponseType response;
	GString *string = NULL;

	/* find whether argyllcms is installed using a tool which should exist */
	ret = g_file_test ("/usr/bin/dispcal", G_FILE_TEST_EXISTS);
	if (ret)
		goto out;

#ifndef HAVE_PACKAGEKIT
	egg_warning ("cannot install: this package was not compiled with --enable-packagekit");
	goto out;
#endif

	/* ask the user to confirm */
	window = GTK_WINDOW(gtk_builder_get_object (prefsdata->builder, "dialog_prefs"));
	dialog = gtk_message_dialog_new (window, GTK_DIALOG_DESTROY_WITH_PARENT, GTK_MESSAGE_QUESTION, GTK_BUTTONS_NONE,
					 /* TRANSLATORS: title, usually we can tell based on the EDID data or output name */
					 _("Install calibration and profiling software?"));

	string = g_string_new ("");
	/* TRANSLATORS: dialog message saying the argyllcms is not installed */
	g_string_append_printf (string, "%s\n", _("Calibration and profiling software is not installed."));
	/* TRANSLATORS: dialog message saying the color targets are not installed */
	g_string_append_printf (string, "%s", _("These tools are required to build color profiles for devices."));

	gtk_message_dialog_format_secondary_text (GTK_MESSAGE_DIALOG (dialog), "%s", string->str);
	gtk_window_set_icon_name (GTK_WINDOW (dialog), MCM_STOCK_ICON);
	/* TRANSLATORS: button, skip installing a package */
	gtk_dialog_add_button (GTK_DIALOG (dialog), _("Do not install"), GTK_RESPONSE_CANCEL);
	g_string_append_printf (string, "%s", _("These tools are required to build color profiles for devices."));
	response = gtk_dialog_run (GTK_DIALOG (dialog));
	gtk_widget_destroy (dialog);

	/* only install if the user wanted to */
	if (response != GTK_RESPONSE_YES)
		goto out;

	/* do the install */
	ret = mcm_utils_install_package (MCM_PREFS_PACKAGE_NAME_ARGYLLCMS, window);
out:
	if (string != NULL)
		g_string_free (string, TRUE);
	return ret;
}

/**
 * mcm_prefs_calibrate_cb:
 **/
static void
mcm_prefs_calibrate_cb (GtkWidget *widget, McmPrefsData *prefsdata)
{
	McmCalibrate *calibrate = NULL;
	McmDeviceKind kind;
	gboolean ret;
	GError *error = NULL;
	const gchar *filename;
	guint i;
	const gchar *name;
	McmProfile *profile;
	GPtrArray *profile_array = NULL;
	GFile *file = NULL;
	GFile *dest = NULL;
	gchar *destination = NULL;

	/* ensure argyllcms is installed */
	ret = mcm_prefs_ensure_argyllcms_installed (prefsdata);
	if (!ret)
		goto out;

	/* create new calibration object */
	calibrate = MCM_CALIBRATE(mcm_calibrate_argyll_new ());

	/* choose the correct kind of calibration */
	kind = mcm_device_get_kind (prefsdata->current_device);
	switch (kind) {
	case MCM_DEVICE_KIND_DISPLAY:
		ret = mcm_prefs_calibrate_display (prefsdata, calibrate);
		break;
	case MCM_DEVICE_KIND_SCANNER:
	case MCM_DEVICE_KIND_CAMERA:
		ret = mcm_prefs_calibrate_device (prefsdata, calibrate);
		break;
	case MCM_DEVICE_KIND_PRINTER:
		ret = mcm_prefs_calibrate_printer (prefsdata, calibrate);
		break;
	default:
		egg_warning ("calibration and/or profiling not supported for this device");
		goto out;
	}

	/* we failed to calibrate */
	if (!ret) {
		egg_warning ("failed to calibrate");
		goto out;
	}

	/* failed to get profile */
	filename = mcm_calibrate_get_filename_result (calibrate);
	if (filename == NULL) {
		egg_warning ("failed to get filename from calibration");
		goto out;
	}

	/* copy the ICC file to the proper location */
	file = g_file_new_for_path (filename);
	dest = mcm_utils_get_profile_destination (file);
	ret = mcm_utils_mkdir_and_copy (file, dest, &error);
	if (!ret) {
		egg_warning ("failed to calibrate: %s", error->message);
		g_error_free (error);
		goto out;
	}

	/* find an existing profile of this name */
	profile_array = mcm_device_get_profiles (prefsdata->current_device);
	destination = g_file_get_path (dest);
	for (i=0; i<profile_array->len; i++) {
		profile = g_ptr_array_index (profile_array, i);
		name = mcm_profile_get_filename (profile);
		if (g_strcmp0 (name, destination) == 0) {
			egg_debug ("found existing profile: %s", destination);
			break;
		}
	}

	/* we didn't find an existing profile */
	if (i == profile_array->len) {
		egg_debug ("adding: %s", destination);

		/* set this default */
		mcm_device_set_default_profile_filename (prefsdata->current_device, destination);
		ret = mcm_device_save (prefsdata->current_device, &error);
		if (!ret) {
			egg_warning ("failed to save default: %s", error->message);
			g_error_free (error);
			goto out;
		}
	}

	/* remove temporary file */
	g_unlink (filename);

	/* play sound from the naming spec */
	ca_context_play (ca_gtk_context_get (), 0,
			 CA_PROP_EVENT_ID, "complete",
			 /* TRANSLATORS: this is the application name for libcanberra */
			 CA_PROP_APPLICATION_NAME, _("MATE Color Manager"),
			 /* TRANSLATORS: this is the sound description */
			 CA_PROP_EVENT_DESCRIPTION, _("Profiling completed"), NULL);
out:
	g_free (destination);
	if (profile_array != NULL)
		g_ptr_array_unref (profile_array);
	if (calibrate != NULL)
		g_object_unref (calibrate);
	if (file != NULL)
		g_object_unref (file);
	if (dest != NULL)
		g_object_unref (dest);
}

/**
 * mcm_prefs_device_add_cb:
 **/
static void
mcm_prefs_device_add_cb (GtkWidget *widget, McmPrefsData *prefsdata)
{
	/* show ui */
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "dialog_virtual"));
	gtk_widget_show (widget);

	/* clear entries */
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "combobox_virtual_type"));
	gtk_combo_box_set_active (GTK_COMBO_BOX(widget), 0);
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "entry_virtual_model"));
	gtk_entry_set_text (GTK_ENTRY (widget), "");
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "entry_virtual_manufacturer"));
	gtk_entry_set_text (GTK_ENTRY (widget), "");
}

/**
 * mcm_prefs_is_profile_suitable_for_device:
 **/
static gboolean
mcm_prefs_is_profile_suitable_for_device (McmProfile *profile, McmDevice *device)
{
	McmProfileKind profile_kind_tmp;
	McmProfileKind profile_kind;
	McmColorspace profile_colorspace;
	McmColorspace device_colorspace;
	gboolean ret = FALSE;
	McmDeviceKind device_kind;

	/* not the right colorspace */
	device_colorspace = mcm_device_get_colorspace (device);
	profile_colorspace = mcm_profile_get_colorspace (profile);
	if (device_colorspace != profile_colorspace)
		goto out;

	/* not the correct kind */
	device_kind = mcm_device_get_kind (device);
	profile_kind_tmp = mcm_profile_get_kind (profile);
	profile_kind = mcm_utils_device_kind_to_profile_kind (device_kind);
	if (profile_kind_tmp != profile_kind)
		goto out;

	/* success */
	ret = TRUE;
out:
	return ret;
}

/**
 * mcm_prefs_add_profiles_suitable_for_devices:
 **/
static void
mcm_prefs_add_profiles_suitable_for_devices (McmPrefsData *prefsdata, GtkWidget *widget, const gchar *profile_filename)
{
	GtkTreeModel *model;
	guint i;
	gboolean ret;
	McmProfile *profile;
	GPtrArray *profile_array;
	GtkTreeIter iter;

	/* clear existing entries */
	model = gtk_combo_box_get_model (GTK_COMBO_BOX (widget));
	gtk_list_store_clear (GTK_LIST_STORE (model));

	/* get new list */
	profile_array = mcm_profile_store_get_array (prefsdata->profile_store);

	/* add profiles of the right kind */
	for (i=0; i<profile_array->len; i++) {
		profile = g_ptr_array_index (profile_array, i);

		/* don't add the current profile */
		if (g_strcmp0 (mcm_profile_get_filename (profile), profile_filename) == 0)
			continue;

		/* only add correct types */
		ret = mcm_prefs_is_profile_suitable_for_device (profile, prefsdata->current_device);
		if (!ret)
			continue;

		/* add */
		mcm_prefs_combobox_add_profile (widget, profile, MCM_PREFS_ENTRY_TYPE_PROFILE, &iter);
	}

	/* add a import entry */
	mcm_prefs_combobox_add_profile (widget, NULL, MCM_PREFS_ENTRY_TYPE_IMPORT, NULL);
	gtk_combo_box_set_active (GTK_COMBO_BOX (widget), 0);
	g_ptr_array_unref (profile_array);
}

/**
 * mcm_prefs_assign_save_profiles_for_device:
 **/
static void
mcm_prefs_assign_save_profiles_for_device (McmPrefsData *prefsdata, McmDevice *device)
{
	GtkTreeIter iter;
	GtkTreeModel *model;
	gboolean is_default;
	McmProfile *profile;
	GPtrArray *array;
	gboolean ret;
	GError *error = NULL;

	/* create empty array */
	array = g_ptr_array_new_with_free_func ((GDestroyNotify) g_object_unref);

	/* get first element */
	model = GTK_TREE_MODEL (prefsdata->list_store_assign);
	ret = gtk_tree_model_get_iter_first (model, &iter);
	if (!ret)
		goto set_profiles;

	/* add default device first */
	do {
		gtk_tree_model_get (model, &iter,
				    MCM_ASSIGN_COLUMN_PROFILE, &profile,
				    MCM_ASSIGN_COLUMN_IS_DEFAULT, &is_default,
				    -1);
		if (is_default)
			g_ptr_array_add (array, g_object_ref (profile));
		g_object_unref (profile);
	} while (gtk_tree_model_iter_next (model, &iter));

	/* add non-default devices next */
	gtk_tree_model_get_iter_first (model, &iter);
	do {
		gtk_tree_model_get (model, &iter,
				    MCM_ASSIGN_COLUMN_PROFILE, &profile,
				    MCM_ASSIGN_COLUMN_IS_DEFAULT, &is_default,
				    -1);
		if (!is_default)
			g_ptr_array_add (array, g_object_ref (profile));
		g_object_unref (profile);
	} while (gtk_tree_model_iter_next (model, &iter));

set_profiles:
	/* save new array */
	mcm_device_set_profiles (device, array);

	/* save */
	ret = mcm_device_save (prefsdata->current_device, &error);
	if (!ret) {
		egg_warning ("failed to save config: %s", error->message);
		g_error_free (error);
		goto out;
	}

	/* set the profile */
	ret = mcm_device_apply (prefsdata->current_device, &error);
	if (!ret) {
		egg_warning ("failed to apply profile: %s", error->message);
		g_error_free (error);
		goto out;
	}
out:
	g_ptr_array_unref (array);
}

/**
 * mcm_prefs_assign_add_cb:
 **/
static void
mcm_prefs_assign_add_cb (GtkWidget *widget, McmPrefsData *prefsdata)
{
	const gchar *profile_filename;

	/* add profiles of the right kind */
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "combobox_profile"));
	profile_filename = mcm_device_get_default_profile_filename (prefsdata->current_device);
	mcm_prefs_add_profiles_suitable_for_devices (prefsdata, widget, profile_filename);

	/* show the dialog */
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "dialog_assign"));
	gtk_widget_show (widget);
}

/**
 * mcm_prefs_assign_remove_cb:
 **/
static void
mcm_prefs_assign_remove_cb (GtkWidget *widget, McmPrefsData *prefsdata)
{
	GtkTreeIter iter;
	GtkTreeSelection *selection;
	GtkTreeModel *model;
	gboolean is_default;
	gboolean ret;

	/* get the selected row */
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "treeview_assign"));
	selection = gtk_tree_view_get_selection (GTK_TREE_VIEW (widget));
	if (!gtk_tree_selection_get_selected (selection, &model, &iter)) {
		egg_debug ("no row selected");
		goto out;
	}

	/* if the profile is default, then we'll have to make the first profile default */
	gtk_tree_model_get (model, &iter,
			    MCM_ASSIGN_COLUMN_IS_DEFAULT, &is_default,
			    -1);

	/* remove this entry */
	gtk_list_store_remove (GTK_LIST_STORE(model), &iter);

	/* /something/ has to be the default profile */
	if (is_default) {
		ret = gtk_tree_model_get_iter_first (model, &iter);
		if (ret) {
			gtk_list_store_set (prefsdata->list_store_assign, &iter,
					    MCM_ASSIGN_COLUMN_IS_DEFAULT, TRUE,
					    MCM_ASSIGN_COLUMN_SORT, "0",
					    -1);
			do {
				gtk_list_store_set (prefsdata->list_store_assign, &iter,
						    MCM_ASSIGN_COLUMN_SORT, "1",
						    -1);
			} while (gtk_tree_model_iter_next (model, &iter));
		}
	}

	/* save device */
	mcm_prefs_assign_save_profiles_for_device (prefsdata, prefsdata->current_device);
out:
	return;
}

/**
 * mcm_prefs_assign_make_default_internal:
 **/
static void
mcm_prefs_assign_make_default_internal (McmPrefsData *prefsdata, GtkTreeModel *model, GtkTreeIter *iter_selected)
{
	GtkTreeIter iter;
	GtkWidget *widget;

	/* make none of the devices default */
	gtk_tree_model_get_iter_first (model, &iter);
	do {
		gtk_list_store_set (prefsdata->list_store_assign, &iter,
				    MCM_ASSIGN_COLUMN_SORT, "1",
				    MCM_ASSIGN_COLUMN_IS_DEFAULT, FALSE,
				    -1);
	} while (gtk_tree_model_iter_next (model, &iter));

	/* make the selected device default */
	gtk_list_store_set (prefsdata->list_store_assign, iter_selected,
			    MCM_ASSIGN_COLUMN_IS_DEFAULT, TRUE,
			    MCM_ASSIGN_COLUMN_SORT, "0",
			    -1);

	/* set button insensitive */
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "button_assign_make_default"));
	gtk_widget_set_sensitive (widget, FALSE);

	/* save device */
	mcm_prefs_assign_save_profiles_for_device (prefsdata, prefsdata->current_device);
}

/**
 * mcm_prefs_assign_make_default_cb:
 **/
static void
mcm_prefs_assign_make_default_cb (GtkWidget *widget, McmPrefsData *prefsdata)
{
	GtkTreeIter iter;
	GtkTreeModel *model;
	GtkTreeSelection *selection;

	/* get the selected row */
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "treeview_assign"));
	selection = gtk_tree_view_get_selection (GTK_TREE_VIEW (widget));
	if (!gtk_tree_selection_get_selected (selection, &model, &iter)) {
		egg_debug ("no row selected");
		return;
	}

	/* make this profile the default */
	mcm_prefs_assign_make_default_internal (prefsdata, model, &iter);
}

/**
 * mcm_prefs_button_virtual_add_cb:
 **/
static void
mcm_prefs_button_virtual_add_cb (GtkWidget *widget, McmPrefsData *prefsdata)
{
	McmDeviceKind device_kind;
	McmDevice *device;
	const gchar *model;
	const gchar *manufacturer;
	gboolean ret;
	GError *error = NULL;

	/* get device details */
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "combobox_virtual_type"));
	device_kind = gtk_combo_box_get_active (GTK_COMBO_BOX(widget)) + 2;
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "entry_virtual_model"));
	model = gtk_entry_get_text (GTK_ENTRY (widget));
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "entry_virtual_manufacturer"));
	manufacturer = gtk_entry_get_text (GTK_ENTRY (widget));

	/* create device */
	device = mcm_device_virtual_new	();
	ret = mcm_device_virtual_create_from_params (MCM_DEVICE_VIRTUAL (device),
						     device_kind, model, manufacturer,
						     NULL, MCM_COLORSPACE_RGB);
	if (!ret) {
		/* TRANSLATORS: could not add virtual device */
		mcm_prefs_error_dialog (prefsdata, _("Failed to create virtual device"), NULL);
		goto out;
	}

	/* save what we've got */
	ret = mcm_device_save (device, &error);
	if (!ret) {
		/* TRANSLATORS: could not add virtual device */
		mcm_prefs_error_dialog (prefsdata, _("Failed to save virtual device"), error->message);
		g_error_free (error);
		goto out;
	}

	/* add to the device list */
	ret = mcm_client_add_device (prefsdata->mcm_client, device, &error);
	if (!ret) {
		/* TRANSLATORS: could not add virtual device */
		mcm_prefs_error_dialog (prefsdata, _("Failed to add virtual device"), error->message);
		g_error_free (error);
		goto out;
	}

out:
	/* we're done */
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "dialog_virtual"));
	gtk_widget_hide (widget);
}

/**
 * mcm_prefs_button_virtual_cancel_cb:
 **/
static void
mcm_prefs_button_virtual_cancel_cb (GtkWidget *widget, McmPrefsData *prefsdata)
{
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "dialog_virtual"));
	gtk_widget_hide (widget);
}

/**
 * mcm_prefs_virtual_delete_event_cb:
 **/
static gboolean
mcm_prefs_virtual_delete_event_cb (GtkWidget *widget, GdkEvent *event, McmPrefsData *prefsdata)
{
	mcm_prefs_button_virtual_cancel_cb (widget, prefsdata);
	return TRUE;
}

/**
 * mcm_prefs_button_assign_cancel_cb:
 **/
static void
mcm_prefs_button_assign_cancel_cb (GtkWidget *widget, McmPrefsData *prefsdata)
{
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "dialog_assign"));
	gtk_widget_hide (widget);
}

/**
 * mcm_prefs_button_assign_ok_cb:
 **/
static void
mcm_prefs_button_assign_ok_cb (GtkWidget *widget, McmPrefsData *prefsdata)
{
	GtkTreeIter iter;
	GtkTreeModel *model;
	McmProfile *profile;
	gboolean is_default = FALSE;
	gboolean ret;

	/* hide window */
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "dialog_assign"));
	gtk_widget_hide (widget);

	/* get entry */
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "combobox_profile"));
	ret = gtk_combo_box_get_active_iter (GTK_COMBO_BOX(widget), &iter);
	if (!ret)
		return;
	model = gtk_combo_box_get_model (GTK_COMBO_BOX(widget));
	gtk_tree_model_get (model, &iter,
			    MCM_PREFS_COMBO_COLUMN_PROFILE, &profile,
			    -1);

	/* if list is empty, we want this to be the default item */
	model = GTK_TREE_MODEL (prefsdata->list_store_assign);
	is_default = !gtk_tree_model_get_iter_first (model, &iter);

	/* add profile */
	gtk_list_store_append (prefsdata->list_store_assign, &iter);
	gtk_list_store_set (prefsdata->list_store_assign, &iter,
			    MCM_ASSIGN_COLUMN_PROFILE, profile,
			    MCM_ASSIGN_COLUMN_SORT, is_default ? "0" : "1",
			    MCM_ASSIGN_COLUMN_IS_DEFAULT, is_default,
			    -1);

	/* save device */
	mcm_prefs_assign_save_profiles_for_device (prefsdata, prefsdata->current_device);
}

/**
 * mcm_prefs_assign_delete_event_cb:
 **/
static gboolean
mcm_prefs_assign_delete_event_cb (GtkWidget *widget, GdkEvent *event, McmPrefsData *prefsdata)
{
	mcm_prefs_button_assign_cancel_cb (widget, prefsdata);
	return TRUE;
}

/**
 * mcm_prefs_delete_cb:
 **/
static void
mcm_prefs_delete_cb (GtkWidget *widget, McmPrefsData *prefsdata)
{
	gboolean ret;
	GError *error = NULL;

	/* try to delete device */
	ret = mcm_client_delete_device (prefsdata->mcm_client, prefsdata->current_device, &error);
	if (!ret) {
		/* TRANSLATORS: could not read file */
		mcm_prefs_error_dialog (prefsdata, _("Failed to delete file"), error->message);
		g_error_free (error);
	}
}

/**
 * mcm_prefs_reset_cb:
 **/
static void
mcm_prefs_reset_cb (GtkWidget *widget, McmPrefsData *prefsdata)
{
	prefsdata->setting_up_device = TRUE;
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "hscale_gamma"));
	gtk_range_set_value (GTK_RANGE (widget), 1.0f);
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "hscale_brightness"));
	gtk_range_set_value (GTK_RANGE (widget), 0.0f);
	prefsdata->setting_up_device = FALSE;
	/* we only want one save, not three */
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "hscale_contrast"));
	gtk_range_set_value (GTK_RANGE (widget), 1.0f);
}

/**
 * mcm_window_set_parent_xid:
 **/
static void
mcm_window_set_parent_xid (GtkWindow *window, guint32 xid)
{
	GdkDisplay *display;
	GdkWindow *parent_window;
	GdkWindow *our_window;

	display = gdk_display_get_default ();
	parent_window = gdk_window_foreign_new_for_display (display, xid);
	our_window = gtk_widget_get_window (GTK_WIDGET (window));

	/* set this above our parent */
	gtk_window_set_modal (window, TRUE);
	gdk_window_set_transient_for (our_window, parent_window);
}

/**
 * mcm_prefs_add_devices_columns:
 **/
static void
mcm_prefs_add_devices_columns (McmPrefsData *prefsdata, GtkTreeView *treeview)
{
	GtkCellRenderer *renderer;
	GtkTreeViewColumn *column;

	/* image */
	renderer = gtk_cell_renderer_pixbuf_new ();
	g_object_set (renderer, "stock-size", GTK_ICON_SIZE_DND, NULL);
	column = gtk_tree_view_column_new_with_attributes ("", renderer,
							   "icon-name", MCM_DEVICES_COLUMN_ICON, NULL);
	gtk_tree_view_append_column (treeview, column);

	/* set minimum width */
	gtk_widget_set_size_request (GTK_WIDGET (treeview), MCM_PREFS_TREEVIEW_MAIN_WIDTH, -1);

	/* column for text */
	renderer = gtk_cell_renderer_text_new ();
	g_object_set (renderer,
		      "wrap-mode", PANGO_WRAP_WORD,
		      "wrap-width", MCM_PREFS_TREEVIEW_MAIN_WIDTH - 62,
		      NULL);
	column = gtk_tree_view_column_new_with_attributes ("", renderer,
							   "markup", MCM_DEVICES_COLUMN_TITLE, NULL);
	gtk_tree_view_column_set_sort_column_id (column, MCM_DEVICES_COLUMN_SORT);
	gtk_tree_sortable_set_sort_column_id (GTK_TREE_SORTABLE (prefsdata->list_store_devices), MCM_DEVICES_COLUMN_SORT, GTK_SORT_ASCENDING);
	gtk_tree_view_append_column (treeview, column);
	gtk_tree_view_column_set_expand (column, TRUE);
}

/**
 * mcm_prefs_add_profiles_columns:
 **/
static void
mcm_prefs_add_profiles_columns (McmPrefsData *prefsdata, GtkTreeView *treeview)
{
	GtkCellRenderer *renderer;
	GtkTreeViewColumn *column;

	/* image */
	renderer = gtk_cell_renderer_pixbuf_new ();
	g_object_set (renderer, "stock-size", GTK_ICON_SIZE_DND, NULL);
	column = gtk_tree_view_column_new_with_attributes ("", renderer,
							   "icon-name", MCM_PROFILES_COLUMN_ICON, NULL);
	gtk_tree_view_append_column (treeview, column);

	/* set minimum width */
	gtk_widget_set_size_request (GTK_WIDGET (treeview), MCM_PREFS_TREEVIEW_MAIN_WIDTH, -1);

	/* column for text */
	renderer = mcm_cell_renderer_profile_new ();
	g_object_set (renderer,
		      "wrap-mode", PANGO_WRAP_WORD,
		      "wrap-width", MCM_PREFS_TREEVIEW_MAIN_WIDTH - 62,
		      NULL);
	column = gtk_tree_view_column_new_with_attributes ("", renderer,
							   "profile", MCM_PROFILES_COLUMN_PROFILE, NULL);
	gtk_tree_view_column_set_sort_column_id (column, MCM_PROFILES_COLUMN_SORT);
	gtk_tree_sortable_set_sort_column_id (GTK_TREE_SORTABLE (prefsdata->list_store_profiles), MCM_PROFILES_COLUMN_SORT, GTK_SORT_ASCENDING);
	gtk_tree_view_append_column (treeview, column);
	gtk_tree_view_column_set_expand (column, TRUE);
}

/**
 * mcm_prefs_add_assign_columns:
 **/
static void
mcm_prefs_add_assign_columns (McmPrefsData *prefsdata, GtkTreeView *treeview)
{
	GtkCellRenderer *renderer;
	GtkTreeViewColumn *column;

	/* set minimum width */
	gtk_widget_set_size_request (GTK_WIDGET (treeview), MCM_PREFS_TREEVIEW_PROFILES_WIDTH, -1);

	/* column for text */
	renderer = mcm_cell_renderer_profile_new ();
	g_object_set (renderer,
		      "wrap-mode", PANGO_WRAP_WORD,
		      "wrap-width", MCM_PREFS_TREEVIEW_PROFILES_WIDTH - 62,
		      NULL);
	column = gtk_tree_view_column_new_with_attributes ("", renderer,
							   "profile", MCM_ASSIGN_COLUMN_PROFILE,
							   "is-default", MCM_ASSIGN_COLUMN_IS_DEFAULT,
							   NULL);
	gtk_tree_view_column_set_sort_column_id (column, MCM_ASSIGN_COLUMN_SORT);
	gtk_tree_sortable_set_sort_column_id (GTK_TREE_SORTABLE (prefsdata->list_store_assign), MCM_ASSIGN_COLUMN_SORT, GTK_SORT_ASCENDING);
	gtk_tree_view_append_column (treeview, column);
	gtk_tree_view_column_set_expand (column, TRUE);
}

/**
 * mcm_prefs_set_calibrate_button_sensitivity:
 **/
static void
mcm_prefs_set_calibrate_button_sensitivity (McmPrefsData *prefsdata)
{
	gboolean ret = FALSE;
	GtkWidget *widget;
	const gchar *tooltip;
	McmDeviceKind kind;
	gboolean connected;
	gboolean xrandr_fallback;
	gboolean has_vte = TRUE;

	/* TRANSLATORS: this is when the button is sensitive */
	tooltip = _("Create a color profile for the selected device");

	/* no device selected */
	if (prefsdata->current_device == NULL) {
		/* TRANSLATORS: this is when the button is insensitive */
		tooltip = _("Cannot profile: No device is selected");
		tooltip = _("Cannot create profile: No device is selected");
		goto out;
	}

#ifndef HAVE_VTE
	has_vte = FALSE;
#endif

	/* no VTE support */
	if (!has_vte) {
		/* TRANSLATORS: this is when the button is insensitive because the distro compiled MCM without VTE */
		tooltip = _("Cannot create profile: Virtual console support is missing");
		goto out;
	}

	/* are we a display */
	kind = mcm_device_get_kind (prefsdata->current_device);
	if (kind == MCM_DEVICE_KIND_DISPLAY) {

		/* are we disconnected */
		connected = mcm_device_get_connected (prefsdata->current_device);
		if (!connected) {
			/* TRANSLATORS: this is when the button is insensitive */
			tooltip = _("Cannot create profile: The display device is not connected");
			goto out;
		}

		/* are we not XRandR 1.3 compat */
		xrandr_fallback = mcm_device_xrandr_get_fallback (MCM_DEVICE_XRANDR (prefsdata->current_device));
		if (xrandr_fallback) {
			/* TRANSLATORS: this is when the button is insensitive */
			tooltip = _("Cannot create profile: The display driver does not support XRandR 1.3");
			goto out;
		}

		/* find whether we have hardware installed */
		ret = mcm_colorimeter_get_present (prefsdata->colorimeter);
		if (!ret) {
			/* TRANSLATORS: this is when the button is insensitive */
			tooltip = _("Cannot create profile: The measuring instrument is not plugged in");
			goto out;
		}
	} else if (kind == MCM_DEVICE_KIND_SCANNER ||
		   kind == MCM_DEVICE_KIND_CAMERA) {

		/* TODO: find out if we can scan using mate-scan */
		ret = TRUE;

	} else if (kind == MCM_DEVICE_KIND_PRINTER) {

		/* find whether we have hardware installed */
		ret = mcm_colorimeter_get_present (prefsdata->colorimeter);
		if (!ret) {
			/* TRANSLATORS: this is when the button is insensitive */
			tooltip = _("Cannot create profile: The measuring instrument is not plugged in");
			goto out;
		}

		/* find whether we have hardware installed */
		ret = mcm_colorimeter_supports_printer (prefsdata->colorimeter);
		if (!ret) {
			/* TRANSLATORS: this is when the button is insensitive */
			tooltip = _("Cannot create profile: The measuring instrument does not support printer profiling");
			goto out;
		}

	} else {

		/* TRANSLATORS: this is when the button is insensitive */
		tooltip = _("Cannot create a profile for this type of device");
	}
out:
	/* control the tooltip and sensitivity of the button */
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "button_calibrate"));
	gtk_widget_set_tooltip_text (widget, tooltip);
	gtk_widget_set_sensitive (widget, ret);
}

/**
 * mcm_prefs_devices_treeview_clicked_cb:
 **/
static void
mcm_prefs_devices_treeview_clicked_cb (GtkTreeSelection *selection, McmPrefsData *prefsdata)
{
	guint i;
	GtkTreeModel *model;
	GtkTreeIter iter;
	GtkTreePath *path;
	GtkWidget *widget;
	gfloat localgamma;
	gfloat brightness;
	gfloat contrast;
	gboolean connected;
	gchar *id = NULL;
	gboolean ret;
	McmDeviceKind kind;
	const gchar *device_serial = NULL;
	const gchar *device_model = NULL;
	const gchar *device_manufacturer = NULL;
	const gchar *eisa_id = NULL;
	GPtrArray *profiles = NULL;
	McmProfile *profile;

	/* This will only work in single or browse selection mode! */
	if (!gtk_tree_selection_get_selected (selection, &model, &iter)) {
		egg_debug ("no row selected");
		goto out;
	}

	/* get id */
	gtk_tree_model_get (model, &iter,
			    MCM_DEVICES_COLUMN_ID, &id,
			    -1);

	/* we have a new device */
	egg_debug ("selected device is: %s", id);
	if (prefsdata->current_device != NULL) {
		g_object_unref (prefsdata->current_device);
		prefsdata->current_device = NULL;
	}
	prefsdata->current_device = mcm_client_get_device_by_id (prefsdata->mcm_client, id);
	if (prefsdata->current_device == NULL)
		goto out;

	/* not a xrandr device */
	kind = mcm_device_get_kind (prefsdata->current_device);
	if (kind != MCM_DEVICE_KIND_DISPLAY) {
		widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "expander_fine_tuning"));
		gtk_widget_set_sensitive (widget, FALSE);
		widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "button_reset"));
		gtk_widget_set_sensitive (widget, FALSE);
	} else {
		/* show more UI */
		widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "expander_fine_tuning"));
		gtk_widget_set_sensitive (widget, TRUE);
		widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "button_reset"));
		gtk_widget_set_sensitive (widget, TRUE);
	}

	/* show broken devices */
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "label_problems"));
	if (kind == MCM_DEVICE_KIND_DISPLAY) {
		ret = mcm_device_xrandr_get_fallback (MCM_DEVICE_XRANDR (prefsdata->current_device));
		if (ret) {
			/* TRANSLATORS: Some shitty binary drivers do not support per-head gamma controls.
			 * Whilst this does not matter if you only have one monitor attached, it means you
			 * can't color correct additional monitors or projectors. */
			gtk_label_set_label (GTK_LABEL (widget), _("Per-device settings not supported. Check your display driver."));
			gtk_widget_show (widget);
		} else {
			gtk_widget_hide (widget);
		}
	} else {
		gtk_widget_hide (widget);
	}

	/* set device labels */
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "hbox_serial"));
	device_serial = mcm_device_get_serial (prefsdata->current_device);
	if (device_serial != NULL) {
		gtk_widget_show (widget);
		widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "label_serial"));
		gtk_label_set_label (GTK_LABEL (widget), device_serial);
	} else {
		gtk_widget_hide (widget);
	}
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "hbox_model"));
	device_model = mcm_device_get_model (prefsdata->current_device);
	if (device_model != NULL) {
		gtk_widget_show (widget);
		widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "label_model"));
		gtk_label_set_label (GTK_LABEL (widget), device_model);
	} else {
		gtk_widget_hide (widget);
	}
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "hbox_manufacturer"));
	device_manufacturer = mcm_device_get_manufacturer (prefsdata->current_device);
	if (device_manufacturer != NULL) {
		gtk_widget_show (widget);
		widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "label_manufacturer"));
		gtk_label_set_label (GTK_LABEL (widget), device_manufacturer);
	} else {
		gtk_widget_hide (widget);
	}
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "vbox_device_details"));
	gtk_widget_show (widget);

	/* get display specific properties */
	if (kind == MCM_DEVICE_KIND_DISPLAY)
		eisa_id = mcm_device_xrandr_get_eisa_id (MCM_DEVICE_XRANDR (prefsdata->current_device));
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "hbox_eisa"));
	if (eisa_id != NULL) {
		gtk_widget_show (widget);
		widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "label_eisa"));
		gtk_label_set_label (GTK_LABEL (widget), eisa_id);
	} else {
		gtk_widget_hide (widget);
	}

	/* set adjustments */
	prefsdata->setting_up_device = TRUE;
	localgamma = mcm_device_get_gamma (prefsdata->current_device);
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "hscale_gamma"));
	gtk_range_set_value (GTK_RANGE (widget), localgamma);
	brightness = mcm_device_get_brightness (prefsdata->current_device);
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "hscale_brightness"));
	gtk_range_set_value (GTK_RANGE (widget), brightness);
	contrast = mcm_device_get_contrast (prefsdata->current_device);
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "hscale_contrast"));
	gtk_range_set_value (GTK_RANGE (widget), contrast);
	prefsdata->setting_up_device = FALSE;

	/* clear existing list */
	gtk_list_store_clear (prefsdata->list_store_assign);

	/* add profiles for the device */
	profiles = mcm_device_get_profiles (prefsdata->current_device);
	for (i=0; i<profiles->len; i++) {
		profile = g_ptr_array_index (profiles, i);
		gtk_list_store_append (prefsdata->list_store_assign, &iter);
		gtk_list_store_set (prefsdata->list_store_assign, &iter,
				    MCM_ASSIGN_COLUMN_PROFILE, profile,
				    MCM_ASSIGN_COLUMN_SORT, (i == 0) ? "0" : "1",
				    MCM_ASSIGN_COLUMN_IS_DEFAULT, (i == 0),
				    -1);
	}

	/* select the default profile to display */
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "treeview_assign"));
	selection = gtk_tree_view_get_selection (GTK_TREE_VIEW (widget));
	path = gtk_tree_path_new_from_string ("0");
	gtk_tree_selection_select_path (selection, path);
	gtk_tree_path_free (path);

	/* make sure selectable */
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "combobox_profile"));
	gtk_widget_set_sensitive (widget, TRUE);
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "button_reset"));
	gtk_widget_set_sensitive (widget, TRUE);
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "label_profile"));
	gtk_widget_set_sensitive (widget, TRUE);

	/* can we delete this device? */
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "button_delete"));
	connected = mcm_device_get_connected (prefsdata->current_device);
	gtk_widget_set_sensitive (widget, !connected);

	/* can this device calibrate */
	mcm_prefs_set_calibrate_button_sensitivity (prefsdata);
out:
	if (profiles != NULL)
		g_ptr_array_unref (profiles);
	g_free (id);
}

/**
 * mcm_prefs_profile_kind_to_string:
 **/
static gchar *
mcm_prefs_profile_kind_to_string (McmProfileKind kind)
{
	if (kind == MCM_PROFILE_KIND_INPUT_DEVICE) {
		/* TRANSLATORS: this the ICC profile type */
		return _("Input device");
	}
	if (kind == MCM_PROFILE_KIND_DISPLAY_DEVICE) {
		/* TRANSLATORS: this the ICC profile type */
		return _("Display device");
	}
	if (kind == MCM_PROFILE_KIND_OUTPUT_DEVICE) {
		/* TRANSLATORS: this the ICC profile type */
		return _("Output device");
	}
	if (kind == MCM_PROFILE_KIND_DEVICELINK) {
		/* TRANSLATORS: this the ICC profile type */
		return _("Devicelink");
	}
	if (kind == MCM_PROFILE_KIND_COLORSPACE_CONVERSION) {
		/* TRANSLATORS: this the ICC profile type */
		return _("Colorspace conversion");
	}
	if (kind == MCM_PROFILE_KIND_ABSTRACT) {
		/* TRANSLATORS: this the ICC profile kind */
		return _("Abstract");
	}
	if (kind == MCM_PROFILE_KIND_NAMED_COLOR) {
		/* TRANSLATORS: this the ICC profile type */
		return _("Named color");
	}
	/* TRANSLATORS: this the ICC profile type */
	return _("Unknown");
}

/**
 * mcm_prefs_profile_colorspace_to_string:
 **/
static gchar *
mcm_prefs_profile_colorspace_to_string (McmColorspace colorspace)
{
	if (colorspace == MCM_COLORSPACE_XYZ) {
		/* TRANSLATORS: this the ICC colorspace type */
		return _("XYZ");
	}
	if (colorspace == MCM_COLORSPACE_LAB) {
		/* TRANSLATORS: this the ICC colorspace type */
		return _("LAB");
	}
	if (colorspace == MCM_COLORSPACE_LUV) {
		/* TRANSLATORS: this the ICC colorspace type */
		return _("LUV");
	}
	if (colorspace == MCM_COLORSPACE_YCBCR) {
		/* TRANSLATORS: this the ICC colorspace type */
		return _("YCbCr");
	}
	if (colorspace == MCM_COLORSPACE_YXY) {
		/* TRANSLATORS: this the ICC colorspace type */
		return _("Yxy");
	}
	if (colorspace == MCM_COLORSPACE_RGB) {
		/* TRANSLATORS: this the ICC colorspace type */
		return _("RGB");
	}
	if (colorspace == MCM_COLORSPACE_GRAY) {
		/* TRANSLATORS: this the ICC colorspace type */
		return _("Gray");
	}
	if (colorspace == MCM_COLORSPACE_HSV) {
		/* TRANSLATORS: this the ICC colorspace type */
		return _("HSV");
	}
	if (colorspace == MCM_COLORSPACE_CMYK) {
		/* TRANSLATORS: this the ICC colorspace type */
		return _("CMYK");
	}
	if (colorspace == MCM_COLORSPACE_CMY) {
		/* TRANSLATORS: this the ICC colorspace type */
		return _("CMY");
	}
	/* TRANSLATORS: this the ICC colorspace type */
	return _("Unknown");
}

/**
 * mcm_prefs_assign_treeview_row_activated_cb:
 **/
static void
mcm_prefs_assign_treeview_row_activated_cb (GtkTreeView *tree_view, GtkTreePath *path,
					    GtkTreeViewColumn *column, McmPrefsData *prefsdata)
{
	GtkTreeModel *model;
	GtkTreeIter iter;
	gboolean ret;

	/* get the iter */
	model = GTK_TREE_MODEL (prefsdata->list_store_assign);
	ret = gtk_tree_model_get_iter (model, &iter, path);
	if (!ret)
		return;

	/* make this profile the default */
	mcm_prefs_assign_make_default_internal (prefsdata, model, &iter);
}

/**
 * mcm_prefs_assign_treeview_clicked_cb:
 **/
static void
mcm_prefs_assign_treeview_clicked_cb (GtkTreeSelection *selection, McmPrefsData *prefsdata)
{
	GtkTreeModel *model;
	GtkTreeIter iter;
	gboolean is_default;
	GtkWidget *widget;
	McmProfile *profile;

	/* This will only work in single or browse selection mode! */
	if (!gtk_tree_selection_get_selected (selection, &model, &iter)) {

		widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "button_assign_make_default"));
		gtk_widget_set_sensitive (widget, FALSE);
		widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "button_assign_remove"));
		gtk_widget_set_sensitive (widget, FALSE);

		egg_debug ("no row selected");
		return;
	}

	/* get profile */
	gtk_tree_model_get (model, &iter,
			    MCM_ASSIGN_COLUMN_PROFILE, &profile,
			    MCM_ASSIGN_COLUMN_IS_DEFAULT, &is_default,
			    -1);
	egg_debug ("selected profile = %s", mcm_profile_get_filename (profile));

	/* is the element the first in the list */
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "button_assign_make_default"));
	gtk_widget_set_sensitive (widget, !is_default);

	/* we can remove it now */
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "button_assign_remove"));
	gtk_widget_set_sensitive (widget, TRUE);

	/* show a warning if the profile is crap */
	if (mcm_device_get_kind (prefsdata->current_device) == MCM_DEVICE_KIND_DISPLAY &&
	    !mcm_profile_get_has_vcgt (profile)) {
		gtk_widget_show (prefsdata->info_bar_vcgt);
	} else {
		gtk_widget_hide (prefsdata->info_bar_vcgt);
	}
}

/**
 * mcm_prefs_profiles_treeview_clicked_cb:
 **/
static void
mcm_prefs_profiles_treeview_clicked_cb (GtkTreeSelection *selection, McmPrefsData *prefsdata)
{
	GtkTreeModel *model;
	GtkTreeIter iter;
	GtkWidget *widget;
	McmProfile *profile;
	McmClut *clut_trc = NULL;
	McmClut *clut_vcgt = NULL;
	McmXyz *white;
	McmXyz *red;
	McmXyz *green;
	McmXyz *blue;
	const gchar *profile_copyright;
	const gchar *profile_manufacturer;
	const gchar *profile_model ;
	const gchar *profile_datetime;
	gchar *temp;
	const gchar *filename;
	gchar *basename = NULL;
	gchar *size_text = NULL;
	McmProfileKind profile_kind;
	McmColorspace profile_colorspace;
	const gchar *profile_kind_text;
	const gchar *profile_colorspace_text;
	gboolean ret;
	gboolean has_vcgt;
	guint size = 0;
	guint filesize;
	gfloat x;
	gboolean show_section = FALSE;

	/* This will only work in single or browse selection mode! */
	if (!gtk_tree_selection_get_selected (selection, &model, &iter)) {
		egg_debug ("no row selected");
		return;
	}

	/* get profile */
	gtk_tree_model_get (model, &iter,
			    MCM_PROFILES_COLUMN_PROFILE, &profile,
			    -1);

	/* get the new details from the profile */
	g_object_get (profile,
		      "white", &white,
		      "red", &red,
		      "green", &green,
		      "blue", &blue,
		      NULL);

	/* check we have enough data for the CIE widget */
	x = mcm_xyz_get_x (red);
	if (x > 0.001) {
		g_object_set (prefsdata->cie_widget,
			      "white", white,
			      "red", red,
			      "green", green,
			      "blue", blue,
			      NULL);
		gtk_widget_show (prefsdata->cie_widget);
		show_section = TRUE;
	} else {
		gtk_widget_hide (prefsdata->cie_widget);
	}

	/* get curve data */
	clut_trc = mcm_profile_generate_curve (profile, 256);

	/* only show if there is useful information */
	if (clut_trc != NULL)
		size = mcm_clut_get_size (clut_trc);
	if (size > 0) {
		g_object_set (prefsdata->trc_widget,
			      "clut", clut_trc,
			      NULL);
		gtk_widget_show (prefsdata->trc_widget);
		show_section = TRUE;
	} else {
		gtk_widget_hide (prefsdata->trc_widget);
	}

	/* get vcgt data */
	clut_vcgt = mcm_profile_generate_vcgt (profile, 256);

	/* only show if there is useful information */
	if (clut_vcgt != NULL)
		size = mcm_clut_get_size (clut_vcgt);
	if (size > 0) {
		g_object_set (prefsdata->vcgt_widget,
			      "clut", clut_vcgt,
			      NULL);
		gtk_widget_show (prefsdata->vcgt_widget);
		show_section = TRUE;
	} else {
		gtk_widget_hide (prefsdata->vcgt_widget);
	}

	/* set kind */
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "hbox_type"));
	profile_kind = mcm_profile_get_kind (profile);
	if (profile_kind == MCM_PROFILE_KIND_UNKNOWN) {
		gtk_widget_hide (widget);
	} else {
		gtk_widget_show (widget);
		widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "label_type"));
		profile_kind_text = mcm_prefs_profile_kind_to_string (profile_kind);
		gtk_label_set_label (GTK_LABEL (widget), profile_kind_text);
	}

	/* set colorspace */
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "hbox_colorspace"));
	profile_colorspace = mcm_profile_get_colorspace (profile);
	if (profile_colorspace == MCM_COLORSPACE_UNKNOWN) {
		gtk_widget_hide (widget);
	} else {
		gtk_widget_show (widget);
		widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "label_colorspace"));
		profile_colorspace_text = mcm_prefs_profile_colorspace_to_string (profile_colorspace);
		gtk_label_set_label (GTK_LABEL (widget), profile_colorspace_text);
	}

	/* set vcgt */
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "hbox_vcgt"));
	gtk_widget_set_visible (widget, (profile_kind == MCM_PROFILE_KIND_DISPLAY_DEVICE));
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "label_vcgt"));
	has_vcgt = mcm_profile_get_has_vcgt (profile);
	if (has_vcgt) {
		/* TRANSLATORS: if the device has a VCGT profile */
		gtk_label_set_label (GTK_LABEL (widget), _("Yes"));
	} else {
		/* TRANSLATORS: if the device has a VCGT profile */
		gtk_label_set_label (GTK_LABEL (widget), _("No"));
	}

	/* set basename */
	filename = mcm_profile_get_filename (profile);
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "label_filename"));
	basename = g_path_get_basename (filename);
	gtk_label_set_label (GTK_LABEL (widget), basename);

	/* set size */
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "hbox_size"));
	filesize = mcm_profile_get_size (profile);
	if (filesize == 0) {
		gtk_widget_hide (widget);
	} else {
		gtk_widget_show (widget);
		widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "label_size"));
		size_text = g_format_size_for_display (filesize);
		gtk_label_set_label (GTK_LABEL (widget), size_text);
	}

	/* set new copyright */
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "hbox_copyright"));
	profile_copyright = mcm_profile_get_copyright (profile);
	if (profile_copyright == NULL) {
		gtk_widget_hide (widget);
	} else {
		gtk_widget_show (widget);
		widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "label_copyright"));
		temp = mcm_utils_linkify (profile_copyright);
		gtk_label_set_label (GTK_LABEL (widget), temp);
		g_free (temp);
	}

	/* set new manufacturer */
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "hbox_profile_manufacturer"));
	profile_manufacturer = mcm_profile_get_manufacturer (profile);
	if (profile_manufacturer == NULL) {
		gtk_widget_hide (widget);
	} else {
		gtk_widget_show (widget);
		widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "label_profile_manufacturer"));
		temp = mcm_utils_linkify (profile_manufacturer);
		gtk_label_set_label (GTK_LABEL (widget), temp);
		g_free (temp);
	}

	/* set new model */
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "hbox_profile_model"));
	profile_model = mcm_profile_get_model (profile);
	if (profile_model == NULL) {
		gtk_widget_hide (widget);
	} else {
		gtk_widget_show (widget);
		widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "label_profile_model"));
		gtk_label_set_label (GTK_LABEL(widget), profile_model);
	}

	/* set new datetime */
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "hbox_datetime"));
	profile_datetime = mcm_profile_get_datetime (profile);
	if (profile_datetime == NULL) {
		gtk_widget_hide (widget);
	} else {
		gtk_widget_show (widget);
		widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "label_datetime"));
		gtk_label_set_label (GTK_LABEL(widget), profile_datetime);
	}

	/* set delete sensitivity */
	ret = mcm_profile_get_can_delete (profile);
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "button_profile_delete"));
	gtk_widget_set_sensitive (widget, ret);
	if (ret) {
		/* TRANSLATORS: this is the tooltip when the profile can be deleted */
		gtk_widget_set_tooltip_text (widget, _("Delete this profile"));
	} else {
		/* TRANSLATORS: this is the tooltip when the profile cannot be deleted */
		gtk_widget_set_tooltip_text (widget, _("This profile cannot be deleted"));
	}

	/* should we show the pane at all */
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "vbox_graph"));
	gtk_widget_set_visible (widget, show_section);
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "vbox_profile_info"));
	gtk_widget_set_visible (widget, TRUE);

	if (clut_trc != NULL)
		g_object_unref (clut_trc);
	if (clut_vcgt != NULL)
		g_object_unref (clut_vcgt);
	g_object_unref (white);
	g_object_unref (red);
	g_object_unref (green);
	g_object_unref (blue);
	g_free (size_text);
	g_free (basename);
}

/**
 * mcm_device_kind_to_string:
 **/
static const gchar *
mcm_prefs_device_kind_to_string (McmDeviceKind kind)
{
	if (kind == MCM_DEVICE_KIND_DISPLAY)
		return "1";
	if (kind == MCM_DEVICE_KIND_SCANNER)
		return "2";
	if (kind == MCM_DEVICE_KIND_CAMERA)
		return "3";
	if (kind == MCM_DEVICE_KIND_PRINTER)
		return "4";
	return "5";
}

/**
 * mcm_prefs_add_device_xrandr:
 **/
static void
mcm_prefs_add_device_xrandr (McmPrefsData *prefsdata, McmDevice *device)
{
	GtkTreeIter iter;
	const gchar *title_tmp;
	gchar *title = NULL;
	gchar *sort = NULL;
	const gchar *id;
	gboolean ret;
	gboolean connected;
	GError *error = NULL;

	/* sanity check */
	if (!MCM_IS_DEVICE_XRANDR (device)) {
		egg_warning ("not a xrandr device");
		goto out;
	}

	/* italic for non-connected devices */
	connected = mcm_device_get_connected (device);
	title_tmp = mcm_device_get_title (device);
	if (connected) {
		/* set the gamma on the device */
		ret = mcm_device_apply (device, &error);
		if (!ret) {
			egg_warning ("failed to apply profile: %s", error->message);
			g_error_free (error);
		}

		/* use a different title if we have crap xorg drivers */
		if (ret) {
			title = g_strdup (title_tmp);
		} else {
			/* TRANSLATORS: this is where an output is not settable, but we are showing it in the UI */
			title = g_strdup_printf ("%s\n(%s)", title_tmp, _("No hardware support"));
		}
	} else {
		/* TRANSLATORS: this is where the device has been setup but is not connected */
		title = g_strdup_printf ("%s\n<i>[%s]</i>", title_tmp, _("disconnected"));
	}

	/* create sort order */
	sort = g_strdup_printf ("%s%s",
				mcm_prefs_device_kind_to_string (MCM_DEVICE_KIND_DISPLAY),
				title);

	/* add to list */
	id = mcm_device_get_id (device);
	egg_debug ("add %s to device list", id);
	gtk_list_store_append (prefsdata->list_store_devices, &iter);
	gtk_list_store_set (prefsdata->list_store_devices, &iter,
			    MCM_DEVICES_COLUMN_ID, id,
			    MCM_DEVICES_COLUMN_SORT, sort,
			    MCM_DEVICES_COLUMN_TITLE, title,
			    MCM_DEVICES_COLUMN_ICON, "video-display", -1);
out:
	g_free (sort);
	g_free (title);
}

/**
 * mcm_prefs_set_combo_simple_text:
 **/
static void
mcm_prefs_set_combo_simple_text (GtkWidget *combo_box)
{
	GtkCellRenderer *renderer;
	GtkListStore *store;

	store = gtk_list_store_new (4, G_TYPE_STRING, MCM_TYPE_PROFILE, G_TYPE_UINT, G_TYPE_STRING);
	gtk_tree_sortable_set_sort_column_id (GTK_TREE_SORTABLE (store), MCM_PREFS_COMBO_COLUMN_SORTABLE, GTK_SORT_ASCENDING);
	gtk_combo_box_set_model (GTK_COMBO_BOX (combo_box), GTK_TREE_MODEL (store));
	g_object_unref (store);

	renderer = gtk_cell_renderer_text_new ();
	g_object_set (renderer,
		      "ellipsize", PANGO_ELLIPSIZE_END,
		      "wrap-mode", PANGO_WRAP_WORD_CHAR,
		      "width-chars", 60,
		      NULL);
	gtk_cell_layout_pack_start (GTK_CELL_LAYOUT (combo_box), renderer, TRUE);
	gtk_cell_layout_set_attributes (GTK_CELL_LAYOUT (combo_box), renderer,
					"text", MCM_PREFS_COMBO_COLUMN_TEXT,
					NULL);
}

/**
 * mcm_prefs_profile_combo_changed_cb:
 **/
static void
mcm_prefs_profile_combo_changed_cb (GtkWidget *widget, McmPrefsData *prefsdata)
{
	GFile *file = NULL;
	GFile *dest = NULL;
	gboolean ret;
	GError *error = NULL;
	McmProfile *profile = NULL;
	GtkTreeIter iter;
	GtkTreeModel *model;
	McmPrefsEntryType entry_type;

	/* no devices */
	if (prefsdata->current_device == NULL)
		return;

	/* no selection */
	ret = gtk_combo_box_get_active_iter (GTK_COMBO_BOX(widget), &iter);
	if (!ret)
		return;

	/* get entry */
	model = gtk_combo_box_get_model (GTK_COMBO_BOX(widget));
	gtk_tree_model_get (model, &iter,
			    MCM_PREFS_COMBO_COLUMN_TYPE, &entry_type,
			    -1);

	/* import */
	if (entry_type == MCM_PREFS_ENTRY_TYPE_IMPORT) {
		file = mcm_prefs_file_chooser_get_icc_profile (prefsdata);
		if (file == NULL) {
			egg_warning ("failed to get ICC file");
			gtk_combo_box_set_active (GTK_COMBO_BOX (widget), 0);
			goto out;
		}

		/* import this */
		ret = mcm_prefs_profile_import_file (prefsdata, file);
		if (!ret) {
			gchar *uri;
			/* set to 'None' */
			gtk_combo_box_set_active (GTK_COMBO_BOX (widget), 0);

			uri = g_file_get_uri (file);
			egg_debug ("%s did not import correctly", uri);
			g_free (uri);
			goto out;
		}

		/* get an object of the destination */
		dest = mcm_utils_get_profile_destination (file);
		profile = mcm_profile_default_new ();
		ret = mcm_profile_parse (profile, dest, &error);
		if (!ret) {
			/* set to first entry */
			gtk_combo_box_set_active (GTK_COMBO_BOX (widget), 0);
			egg_warning ("failed to parse ICC file: %s", error->message);
			g_error_free (error);
			goto out;
		}

		/* check the file is suitable */
		ret = mcm_prefs_is_profile_suitable_for_device (profile, prefsdata->current_device);
		if (!ret) {
			/* set to 'None' */
			gtk_combo_box_set_active (GTK_COMBO_BOX (widget), 0);

			/* TRANSLATORS: the profile was of the wrong sort for this device */
			mcm_prefs_error_dialog (prefsdata, _("Could not import profile"),
						_("The profile was of the wrong type for this device"));
			goto out;
		}

		/* add to combobox */
		gtk_list_store_append (GTK_LIST_STORE(model), &iter);
		gtk_list_store_set (GTK_LIST_STORE(model), &iter,
				    MCM_PREFS_COMBO_COLUMN_PROFILE, profile,
				    MCM_PREFS_COMBO_COLUMN_SORTABLE, "0",
				    -1);
		gtk_combo_box_set_active_iter (GTK_COMBO_BOX (widget), &iter);
	}
out:
	if (file != NULL)
		g_object_unref (file);
	if (dest != NULL)
		g_object_unref (dest);
	if (profile != NULL)
		g_object_unref (profile);
}

/**
 * mcm_prefs_slider_changed_cb:
 **/
static void
mcm_prefs_slider_changed_cb (GtkRange *range, McmPrefsData *prefsdata)
{
	gfloat localgamma;
	gfloat brightness;
	gfloat contrast;
	GtkWidget *widget;
	gboolean ret;
	GError *error = NULL;

	/* we're just setting up the device, not moving the slider */
	if (prefsdata->setting_up_device)
		return;

	/* get values */
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "hscale_gamma"));
	localgamma = gtk_range_get_value (GTK_RANGE (widget));
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "hscale_brightness"));
	brightness = gtk_range_get_value (GTK_RANGE (widget));
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "hscale_contrast"));
	contrast = gtk_range_get_value (GTK_RANGE (widget));

	mcm_device_set_gamma (prefsdata->current_device, localgamma);
	mcm_device_set_brightness (prefsdata->current_device, brightness * 100.0f);
	mcm_device_set_contrast (prefsdata->current_device, contrast * 100.0f);

	/* save new profile */
	ret = mcm_device_save (prefsdata->current_device, &error);
	if (!ret) {
		egg_warning ("failed to save config: %s", error->message);
		g_error_free (error);
		goto out;
	}

	/* actually set the new profile */
	ret = mcm_device_apply (prefsdata->current_device, &error);
	if (!ret) {
		egg_warning ("failed to apply profile: %s", error->message);
		g_error_free (error);
		goto out;
	}
out:
	return;
}

/**
 * mcm_prefs_colorimeter_changed_cb:
 **/
static void
mcm_prefs_colorimeter_changed_cb (McmColorimeter *colorimeter, McmPrefsData *prefsdata)
{
	gboolean present;
	const gchar *event_id;
	const gchar *message;

	present = mcm_colorimeter_get_present (colorimeter);

	if (present) {
		/* TRANSLATORS: this is a sound description */
		message = _("Device added");
		event_id = "device-added";
	} else {
		/* TRANSLATORS: this is a sound description */
		message = _("Device removed");
		event_id = "device-removed";
	}

	/* play sound from the naming spec */
	ca_context_play (ca_gtk_context_get (), 0,
			 CA_PROP_EVENT_ID, event_id,
			 /* TRANSLATORS: this is the application name for libcanberra */
			 CA_PROP_APPLICATION_NAME, _("MATE Color Manager"),
			 CA_PROP_EVENT_DESCRIPTION, message, NULL);

	mcm_prefs_set_calibrate_button_sensitivity (prefsdata);
}

/**
 * mcm_prefs_device_kind_to_icon_name:
 **/
static const gchar *
mcm_prefs_device_kind_to_icon_name (McmDeviceKind kind)
{
	if (kind == MCM_DEVICE_KIND_DISPLAY)
		return "video-display";
	if (kind == MCM_DEVICE_KIND_SCANNER)
		return "scanner";
	if (kind == MCM_DEVICE_KIND_PRINTER)
		return "printer";
	if (kind == MCM_DEVICE_KIND_CAMERA)
		return "camera-photo";
	return "image-missing";
}

/**
 * mcm_prefs_add_device_kind:
 **/
static void
mcm_prefs_add_device_kind (McmPrefsData *prefsdata, McmDevice *device)
{
	GtkTreeIter iter;
	const gchar *title;
	GString *string;
	const gchar *id;
	gchar *sort = NULL;
	McmDeviceKind kind;
	const gchar *icon_name;
	gboolean connected;
	gboolean virtual;

	/* get icon */
	kind = mcm_device_get_kind (device);
	icon_name = mcm_prefs_device_kind_to_icon_name (kind);

	/* create a title for the device */
	title = mcm_device_get_title (device);
	string = g_string_new (title);

	/* italic for non-connected devices */
	connected = mcm_device_get_connected (device);
	virtual = mcm_device_get_virtual (device);
	if (!connected && !virtual) {
		/* TRANSLATORS: this is where the device has been setup but is not connected */
		g_string_append_printf (string, "\n<i>[%s]</i>", _("disconnected"));
	}

	/* create sort order */
	sort = g_strdup_printf ("%s%s",
				mcm_prefs_device_kind_to_string (kind),
				string->str);

	/* add to list */
	id = mcm_device_get_id (device);
	gtk_list_store_append (prefsdata->list_store_devices, &iter);
	gtk_list_store_set (prefsdata->list_store_devices, &iter,
			    MCM_DEVICES_COLUMN_ID, id,
			    MCM_DEVICES_COLUMN_SORT, sort,
			    MCM_DEVICES_COLUMN_TITLE, string->str,
			    MCM_DEVICES_COLUMN_ICON, icon_name, -1);
	g_free (sort);
	g_string_free (string, TRUE);
}

/**
 * mcm_prefs_remove_device:
 **/
static void
mcm_prefs_remove_device (McmPrefsData *prefsdata, McmDevice *mcm_device)
{
	GtkTreeIter iter;
	GtkTreeModel *model;
	const gchar *id;
	gchar *id_tmp;
	gboolean ret;

	/* remove */
	id = mcm_device_get_id (mcm_device);
	egg_debug ("removing: %s (connected: %i)", id,
		   mcm_device_get_connected (mcm_device));

	/* get first element */
	model = GTK_TREE_MODEL (prefsdata->list_store_devices);
	ret = gtk_tree_model_get_iter_first (model, &iter);
	if (!ret)
		return;

	/* get the other elements */
	do {
		gtk_tree_model_get (model, &iter,
				    MCM_DEVICES_COLUMN_ID, &id_tmp,
				    -1);
		if (g_strcmp0 (id_tmp, id) == 0) {
			gtk_list_store_remove (GTK_LIST_STORE(model), &iter);
			g_free (id_tmp);
			break;
		}
		g_free (id_tmp);
	} while (gtk_tree_model_iter_next (model, &iter));
}

/**
 * mcm_prefs_added_cb:
 **/
static void
mcm_prefs_added_cb (McmClient *client, McmDevice *device, McmPrefsData *prefsdata)
{
	McmDeviceKind kind;
	egg_debug ("added: %s (connected: %i, saved: %i)",
		   mcm_device_get_id (device),
		   mcm_device_get_connected (device),
		   mcm_device_get_saved (device));

	/* remove the saved device if it's already there */
	mcm_prefs_remove_device (prefsdata, device);

	/* add the device */
	kind = mcm_device_get_kind (device);
	if (kind == MCM_DEVICE_KIND_DISPLAY)
		mcm_prefs_add_device_xrandr (prefsdata, device);
	else
		mcm_prefs_add_device_kind (prefsdata, device);
}

/**
 * mcm_prefs_changed_cb:
 **/
static void
mcm_prefs_changed_cb (McmClient *client, McmDevice *device, McmPrefsData *prefsdata)
{
	McmDeviceKind kind;

	/* no not re-add to the ui if we just deleted this */
	if (!mcm_device_get_connected (device) &&
	    !mcm_device_get_saved (device)) {
		egg_warning ("ignoring uninteresting device: %s", mcm_device_get_id (device));
		return;
	}

	egg_debug ("changed: %s", mcm_device_get_id (device));

	/* remove the saved device if it's already there */
	mcm_prefs_remove_device (prefsdata, device);

	/* add the device */
	kind = mcm_device_get_kind (device);
	if (kind == MCM_DEVICE_KIND_DISPLAY)
		mcm_prefs_add_device_xrandr (prefsdata, device);
	else
		mcm_prefs_add_device_kind (prefsdata, device);
}

/**
 * mcm_prefs_removed_cb:
 **/
static void
mcm_prefs_removed_cb (McmClient *client, McmDevice *device, McmPrefsData *prefsdata)
{
	gboolean connected;
	GtkTreeIter iter;
	GtkTreeSelection *selection;
	GtkWidget *widget;
	gboolean ret;

	/* remove from the UI */
	mcm_prefs_remove_device (prefsdata, device);

	/* ensure this device is re-added if it's been saved */
	connected = mcm_device_get_connected (device);
	if (connected)
		mcm_client_coldplug (prefsdata->mcm_client, MCM_CLIENT_COLDPLUG_SAVED, NULL);

	/* select the first device */
	ret = gtk_tree_model_get_iter_first (GTK_TREE_MODEL (prefsdata->list_store_devices), &iter);
	if (!ret)
		return;

	/* click it */
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "treeview_devices"));
	gtk_tree_view_set_model (GTK_TREE_VIEW (widget), GTK_TREE_MODEL (prefsdata->list_store_devices));
	selection = gtk_tree_view_get_selection (GTK_TREE_VIEW (widget));
	gtk_tree_selection_select_iter (selection, &iter);
}

/**
 * mcm_prefs_startup_phase2_idle_cb:
 **/
static gboolean
mcm_prefs_startup_phase2_idle_cb (McmPrefsData *prefsdata)
{
	GtkWidget *widget;
	GtkTreeSelection *selection;
	GtkTreePath *path;
	gboolean ret;

	/* update list of profiles */
	mcm_prefs_update_profile_list (prefsdata);

	/* select a profile to display */
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "treeview_profiles"));
	selection = gtk_tree_view_get_selection (GTK_TREE_VIEW (widget));
	path = gtk_tree_path_new_from_string ("0");
	gtk_tree_selection_select_path (selection, path);
	gtk_tree_path_free (path);

	/* do we show the shared-color-profiles-extra installer? */
	egg_debug ("getting installed");
	ret = mcm_utils_is_package_installed (MCM_PREFS_PACKAGE_NAME_COLOR_PROFILES_EXTRA);
	gtk_widget_set_visible (prefsdata->info_bar_profiles, !ret);

	return FALSE;
}

/**
 * mcm_prefs_setup_space_combobox:
 **/
static void
mcm_prefs_setup_space_combobox (McmPrefsData *prefsdata, GtkWidget *widget, McmColorspace colorspace, const gchar *profile_filename)
{
	McmProfile *profile;
	guint i;
	const gchar *filename;
	McmColorspace colorspace_tmp;
	gboolean has_profile = FALSE;
	gboolean has_vcgt;
	gboolean has_colorspace_description;
	gchar *text = NULL;
	GPtrArray *profile_array = NULL;
	GtkTreeIter iter;

	/* get new list */
	profile_array = mcm_profile_store_get_array (prefsdata->profile_store);

	/* update each list */
	for (i=0; i<profile_array->len; i++) {
		profile = g_ptr_array_index (profile_array, i);

		/* only for correct kind */
		has_vcgt = mcm_profile_get_has_vcgt (profile);
		has_colorspace_description = mcm_profile_has_colorspace_description (profile);
		colorspace_tmp = mcm_profile_get_colorspace (profile);
		if (!has_vcgt &&
		    colorspace == colorspace_tmp &&
		    (colorspace == MCM_COLORSPACE_CMYK ||
		     has_colorspace_description)) {
			mcm_prefs_combobox_add_profile (widget, profile, MCM_PREFS_ENTRY_TYPE_PROFILE, &iter);

			/* set active option */
			filename = mcm_profile_get_filename (profile);
			if (g_strcmp0 (filename, profile_filename) == 0)
				gtk_combo_box_set_active_iter (GTK_COMBO_BOX (widget), &iter);
			has_profile = TRUE;
		}
	}
	if (!has_profile) {
		/* TRANSLATORS: this is when there are no profiles that can be used; the search term is either "RGB" or "CMYK" */
		text = g_strdup_printf (_("No %s color spaces available"),
					mcm_colorspace_to_localised_string (colorspace));
		gtk_combo_box_append_text (GTK_COMBO_BOX(widget), text);
		gtk_combo_box_set_active (GTK_COMBO_BOX (widget), 0);
		gtk_widget_set_sensitive (widget, FALSE);
	}
	if (profile_array != NULL)
		g_ptr_array_unref (profile_array);
	g_free (text);
}

/**
 * mcm_prefs_space_combo_changed_cb:
 **/
static void
mcm_prefs_space_combo_changed_cb (GtkWidget *widget, McmPrefsData *prefsdata)
{
	gboolean ret;
	GtkTreeIter iter;
	const gchar *filename;
	GtkTreeModel *model;
	McmProfile *profile = NULL;
	const gchar *key = g_object_get_data (G_OBJECT(widget), "MCM:GSettingsKey");

	/* no selection */
	ret = gtk_combo_box_get_active_iter (GTK_COMBO_BOX(widget), &iter);
	if (!ret)
		return;

	/* get profile */
	model = gtk_combo_box_get_model (GTK_COMBO_BOX(widget));
	gtk_tree_model_get (model, &iter,
			    MCM_PREFS_COMBO_COLUMN_PROFILE, &profile,
			    -1);
	if (profile == NULL)
		goto out;

	filename = mcm_profile_get_filename (profile);
	egg_debug ("changed working space %s", filename);
	g_settings_set_string (prefsdata->settings, key, filename);
out:
	if (profile != NULL)
		g_object_unref (profile);
}

/**
 * mcm_prefs_renderer_combo_changed_cb:
 **/
static void
mcm_prefs_renderer_combo_changed_cb (GtkWidget *widget, McmPrefsData *prefsdata)
{
	gint active;
	const gchar *key = g_object_get_data (G_OBJECT(widget), "MCM:GSettingsKey");

	/* no selection */
	active = gtk_combo_box_get_active (GTK_COMBO_BOX(widget));
	if (active == -1)
		return;

	/* save to GSettings */
	egg_debug ("changed rendering intent to %s", mcm_intent_to_string (active+1));
	g_settings_set_enum (prefsdata->settings, key, active+1);
}

/**
 * mcm_prefs_setup_rendering_combobox:
 **/
static void
mcm_prefs_setup_rendering_combobox (GtkWidget *widget, McmIntent intent)
{
	guint i;
	gboolean ret = FALSE;
	gchar *label;

	for (i=1; i<MCM_INTENT_LAST; i++) {
		label = g_strdup_printf ("%s - %s",
					 mcm_intent_to_localized_text (i),
					 mcm_intent_to_localized_description (i));
		gtk_combo_box_append_text (GTK_COMBO_BOX (widget), label);
		g_free (label);
		if (i == intent) {
			ret = TRUE;
			gtk_combo_box_set_active (GTK_COMBO_BOX (widget), i-1);
		}
	}
	/* nothing matches, just set the first option */
	if (!ret)
		gtk_combo_box_set_active (GTK_COMBO_BOX (widget), 0);
}

/**
 * mcm_prefs_startup_phase1_idle_cb:
 **/
static gboolean
mcm_prefs_startup_phase1_idle_cb (McmPrefsData *prefsdata)
{
	GtkWidget *widget;
	gboolean ret;
	GError *error = NULL;
	gchar *colorspace_rgb;
	gchar *colorspace_cmyk;
	gint intent_display = -1;
	gint intent_softproof = -1;

	/* search the disk for profiles */
	mcm_profile_store_search_default (prefsdata->profile_store);
	g_signal_connect (prefsdata->profile_store, "changed", G_CALLBACK(mcm_prefs_profile_store_changed_cb), prefsdata);

	/* setup RGB combobox */
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "combobox_space_rgb"));
	colorspace_rgb = g_settings_get_string (prefsdata->settings, MCM_SETTINGS_COLORSPACE_RGB);
	mcm_prefs_set_combo_simple_text (widget);
	mcm_prefs_setup_space_combobox (prefsdata, widget, MCM_COLORSPACE_RGB, colorspace_rgb);
	g_object_set_data (G_OBJECT(widget), "MCM:GSettingsKey", (gpointer) MCM_SETTINGS_COLORSPACE_RGB);
	g_signal_connect (G_OBJECT (widget), "changed",
			  G_CALLBACK (mcm_prefs_space_combo_changed_cb), prefsdata);

	/* setup CMYK combobox */
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "combobox_space_cmyk"));
	colorspace_cmyk = g_settings_get_string (prefsdata->settings, MCM_SETTINGS_COLORSPACE_CMYK);
	mcm_prefs_set_combo_simple_text (widget);
	mcm_prefs_setup_space_combobox (prefsdata, widget, MCM_COLORSPACE_CMYK, colorspace_cmyk);
	g_object_set_data (G_OBJECT(widget), "MCM:GSettingsKey", (gpointer) MCM_SETTINGS_COLORSPACE_CMYK);
	g_signal_connect (G_OBJECT (widget), "changed",
			  G_CALLBACK (mcm_prefs_space_combo_changed_cb), prefsdata);

	/* setup rendering lists */
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "combobox_rendering_display"));
	mcm_prefs_set_combo_simple_text (widget);
	intent_display = g_settings_get_enum (prefsdata->settings, MCM_SETTINGS_RENDERING_INTENT_DISPLAY);
	mcm_prefs_setup_rendering_combobox (widget, intent_display);
	g_object_set_data (G_OBJECT(widget), "MCM:GSettingsKey", (gpointer) MCM_SETTINGS_RENDERING_INTENT_DISPLAY);
	g_signal_connect (G_OBJECT (widget), "changed",
			  G_CALLBACK (mcm_prefs_renderer_combo_changed_cb), prefsdata);

	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "combobox_rendering_softproof"));
	mcm_prefs_set_combo_simple_text (widget);
	intent_softproof = g_settings_get_enum (prefsdata->settings, MCM_SETTINGS_RENDERING_INTENT_SOFTPROOF);
	mcm_prefs_setup_rendering_combobox (widget, intent_softproof);
	g_object_set_data (G_OBJECT(widget), "MCM:GSettingsKey", (gpointer) MCM_SETTINGS_RENDERING_INTENT_SOFTPROOF);
	g_signal_connect (G_OBJECT (widget), "changed",
			  G_CALLBACK (mcm_prefs_renderer_combo_changed_cb), prefsdata);

	/* coldplug plugged in devices */
	ret = mcm_client_coldplug (prefsdata->mcm_client, MCM_CLIENT_COLDPLUG_ALL, &error);
	if (!ret) {
		egg_warning ("failed to add connected devices: %s", error->message);
		g_error_free (error);
		goto out;
	}

	/* set calibrate button sensitivity */
	mcm_prefs_set_calibrate_button_sensitivity (prefsdata);

	/* start phase 2 of the startup */
	g_idle_add ((GSourceFunc) mcm_prefs_startup_phase2_idle_cb, prefsdata);

out:
	g_free (colorspace_rgb);
	g_free (colorspace_cmyk);
	return FALSE;
}

/**
 * mcm_prefs_reset_devices_idle_cb:
 **/
static gboolean
mcm_prefs_reset_devices_idle_cb (McmPrefsData *prefsdata)
{
	GPtrArray *array = NULL;
	McmDevice *device;
	GError *error = NULL;
	gboolean ret;
	guint i;

	/* set for each output */
	array = mcm_client_get_devices (prefsdata->mcm_client);
	for (i=0; i<array->len; i++) {
		device = g_ptr_array_index (array, i);

		/* set gamma for device */
		ret = mcm_device_apply (device, &error);
		if (!ret) {
			egg_warning ("failed to set profile: %s", error->message);
			g_error_free (error);
			break;
		}
	}
	g_ptr_array_unref (array);
	return FALSE;
}

/**
 * mcm_prefs_checkbutton_changed_cb:
 **/
static void
mcm_prefs_checkbutton_changed_cb (GtkWidget *widget, McmPrefsData *prefsdata)
{
	/* set the new setting */
	g_idle_add ((GSourceFunc) mcm_prefs_reset_devices_idle_cb, prefsdata);
}

/**
 * mcm_prefs_setup_drag_and_drop:
 **/
static void
mcm_prefs_setup_drag_and_drop (GtkWidget *widget)
{
	GtkTargetEntry entry;

	/* setup a dummy entry */
	entry.target = g_strdup ("text/plain");
	entry.flags = GTK_TARGET_OTHER_APP;
	entry.info = 0;

	gtk_drag_dest_set (widget, GTK_DEST_DEFAULT_ALL, &entry, 1, GDK_ACTION_MOVE | GDK_ACTION_COPY);
	g_free (entry.target);
}

/**
 * mcm_prefs_profile_store_changed_cb:
 **/
static void
mcm_prefs_profile_store_changed_cb (McmProfileStore *profile_store, McmPrefsData *prefsdata)
{
	GtkTreeSelection *selection;
	GtkWidget *widget;

	/* clear and update the profile list */
	mcm_prefs_update_profile_list (prefsdata);

	/* re-get all the profiles for this device */
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "treeview_devices"));
	selection = gtk_tree_view_get_selection (GTK_TREE_VIEW (widget));
	if (selection == NULL)
		return;
	g_signal_emit_by_name (selection, "changed", prefsdata);
}

/**
 * mcm_prefs_select_first_device_idle_cb:
 **/
static gboolean
mcm_prefs_select_first_device_idle_cb (McmPrefsData *prefsdata)
{
	GtkTreePath *path;
	GtkWidget *widget;

	/* set the cursor on the first device */
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "treeview_devices"));
	path = gtk_tree_path_new_from_string ("0");
	gtk_tree_view_set_cursor (GTK_TREE_VIEW (widget), path, NULL, FALSE);
	gtk_tree_path_free (path);

	return FALSE;
}

/**
 * mcm_prefs_client_notify_loading_cb:
 **/
static void
mcm_prefs_client_notify_loading_cb (McmClient *client, GParamSpec *pspec, McmPrefsData *prefsdata)
{
	gboolean loading;

	/*if loading show the bar */
	loading = mcm_client_get_loading (client);
	if (loading) {
		gtk_widget_show (prefsdata->info_bar_loading);
		return;
	}

	/* otherwise clear the loading widget */
	gtk_widget_hide (prefsdata->info_bar_loading);

	/* idle callback */
	g_idle_add ((GSourceFunc) mcm_prefs_select_first_device_idle_cb, prefsdata);
}

/**
 * mcm_prefs_info_bar_response_cb:
 **/
static void
mcm_prefs_info_bar_response_cb (GtkDialog *dialog, GtkResponseType response, McmPrefsData *prefsdata)
{
	GtkWindow *window;
	gboolean ret;
	if (response == GTK_RESPONSE_HELP) {
		/* open the help file in the right place */
		mcm_mate_help ("faq-missing-vcgt");

	} else if (response == GTK_RESPONSE_APPLY) {
		/* install the extra profiles */
		window = GTK_WINDOW(gtk_builder_get_object (prefsdata->builder, "dialog_prefs"));
		ret = mcm_utils_install_package (MCM_PREFS_PACKAGE_NAME_COLOR_PROFILES_EXTRA, window);
		if (ret)
			gtk_widget_hide (prefsdata->info_bar_profiles);
	}
}

/**
 * mcm_device_kind_to_localised_string:
 **/
static const gchar *
mcm_device_kind_to_localised_string (McmDeviceKind device_kind)
{
	if (device_kind == MCM_DEVICE_KIND_DISPLAY) {
		/* TRANSLATORS: device type */
		return _("Display");
	}
	if (device_kind == MCM_DEVICE_KIND_SCANNER) {
		/* TRANSLATORS: device type */
		return _("Scanner");
	}
	if (device_kind == MCM_DEVICE_KIND_PRINTER) {
		/* TRANSLATORS: device type */
		return _("Printer");
	}
	if (device_kind == MCM_DEVICE_KIND_CAMERA) {
		/* TRANSLATORS: device type */
		return _("Camera");
	}
	return NULL;
}

/**
 * mcm_prefs_setup_virtual_combobox:
 **/
static void
mcm_prefs_setup_virtual_combobox (GtkWidget *widget)
{
	guint i;
	const gchar *text;

	for (i=MCM_DEVICE_KIND_SCANNER; i<MCM_DEVICE_KIND_LAST; i++) {
		text = mcm_device_kind_to_localised_string (i);
		gtk_combo_box_append_text (GTK_COMBO_BOX(widget), text);
	}
	gtk_combo_box_set_active (GTK_COMBO_BOX (widget), MCM_DEVICE_KIND_PRINTER - 2);
}

/**
 * mcm_prefs_graph_combo_changed_cb:
 **/
static void
mcm_prefs_graph_combo_changed_cb (GtkWidget *widget, McmPrefsData *prefsdata)
{
	gint active;

	/* no selection */
	active = gtk_combo_box_get_active (GTK_COMBO_BOX(widget));
	if (active == -1)
		return;

	/* hide or show the correct graphs */
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "hbox_graph_widgets"));
	gtk_widget_set_visible (widget, active != 0);

	/* hide or show the correct graphs */
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "vbox_cie_axis"));
	gtk_widget_set_visible (widget, active == 1);

	/* hide or show the correct graphs */
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "vbox_trc_axis"));
	gtk_widget_set_visible (widget, active == 2);

	/* hide or show the correct graphs */
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "vbox_vcgt_axis"));
	gtk_widget_set_visible (widget, active == 3);

	/* save to GSettings */
	g_settings_set_enum (prefsdata->settings, MCM_SETTINGS_PROFILE_GRAPH_TYPE, active);
}

/**
 * mcm_prefs_setup_graph_combobox:
 **/
static void
mcm_prefs_setup_graph_combobox (McmPrefsData *prefsdata, GtkWidget *widget)
{
	gint active;

	/* TRANSLATORS: combo-entry, no graph selected to be shown */
	gtk_combo_box_append_text (GTK_COMBO_BOX(widget), _("None"));

	/* TRANSLATORS: combo-entry, this is a graph plot type (look it up on google...) */
	gtk_combo_box_append_text (GTK_COMBO_BOX(widget), _("CIE 1931 xy"));

	/* TRANSLATORS: combo-entry, this is a graph plot type (what goes in, v.s. what goes out) */
	gtk_combo_box_append_text (GTK_COMBO_BOX(widget), _("Transfer response curve"));

	/* TRANSLATORS: combo-entry, this is a graph plot type (what data we snd the graphics card) */
	gtk_combo_box_append_text (GTK_COMBO_BOX(widget), _("Video card gamma table"));

	/* get from settings */
	active = g_settings_get_enum (prefsdata->settings, MCM_SETTINGS_PROFILE_GRAPH_TYPE);
	gtk_combo_box_set_active (GTK_COMBO_BOX (widget), active);
}

/**
 * gpk_update_viewer_notify_network_state_cb:
 **/
static void
mcm_prefs_button_virtual_entry_changed_cb (GtkEntry *entry, GParamSpec *pspec, McmPrefsData *prefsdata)
{
	const gchar *model;
	const gchar *manufacturer;
	GtkWidget *widget;

	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "entry_virtual_model"));
	model = gtk_entry_get_text (GTK_ENTRY (widget));
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "entry_virtual_manufacturer"));
	manufacturer = gtk_entry_get_text (GTK_ENTRY (widget));

	/* only set the add button sensitive if both sections have text */
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "button_virtual_add"));
	gtk_widget_set_sensitive (widget, (model != NULL && model[0] != '\0' && manufacturer != NULL && manufacturer[0] != '\0'));
}

/**
 * main:
 **/
int
main (int argc, char **argv)
{
	guint retval = 0;
	GOptionContext *context;
	GtkWidget *main_window;
	GtkWidget *widget;
	guint xid = 0;
	GError *error = NULL;
	GtkTreeSelection *selection;
	GtkWidget *info_bar_loading_label;
	GtkWidget *info_bar_vcgt_label;
	GtkWidget *info_bar_profiles_label;
	GdkScreen *screen;
	McmPrefsData *prefsdata;

	const GOptionEntry options[] = {
		{ "parent-window", 'p', 0, G_OPTION_ARG_INT, &xid,
		  /* TRANSLATORS: we can make this modal (stay on top of) another window */
		  _("Set the parent window to make this modal"), NULL },
		{ NULL}
	};

	setlocale (LC_ALL, "");

	bindtextdomain (GETTEXT_PACKAGE, LOCALEDIR);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
	textdomain (GETTEXT_PACKAGE);

	gtk_init (&argc, &argv);

	context = g_option_context_new ("mate-color-manager prefs program");
	g_option_context_add_main_entries (context, options, NULL);
	g_option_context_add_group (context, egg_debug_get_option_group ());
	g_option_context_add_group (context, gtk_get_option_group (TRUE));
	g_option_context_parse (context, &argc, &argv, NULL);
	g_option_context_free (context);

	prefsdata = g_new0 (McmPrefsData, 1);

	/* ensure single instance */
	prefsdata->application = gtk_application_new ("org.mate.ColorManager.Prefs", &argc, &argv);

	/* setup defaults */
	prefsdata->settings = g_settings_new (MCM_SETTINGS_SCHEMA);

	/* get UI */
	prefsdata->builder = gtk_builder_new ();
	retval = gtk_builder_add_from_file (prefsdata->builder, MCM_DATA "/mcm-prefs.ui", &error);
	if (retval == 0) {
		egg_warning ("failed to load ui: %s", error->message);
		g_error_free (error);
		goto out;
	}

	/* add application specific icons to search path */
	gtk_icon_theme_append_search_path (gtk_icon_theme_get_default (),
	                                   MCM_DATA G_DIR_SEPARATOR_S "icons");

	/* maintain a list of profiles */
	prefsdata->profile_store = mcm_profile_store_new ();

	/* create list stores */
	prefsdata->list_store_devices = gtk_list_store_new (MCM_DEVICES_COLUMN_LAST, G_TYPE_STRING, G_TYPE_STRING,
						 G_TYPE_STRING, G_TYPE_STRING);
	prefsdata->list_store_profiles = gtk_list_store_new (MCM_PROFILES_COLUMN_LAST, G_TYPE_STRING,
						  G_TYPE_STRING, G_TYPE_STRING, MCM_TYPE_PROFILE);
	prefsdata->list_store_assign = gtk_list_store_new (MCM_ASSIGN_COLUMN_LAST, G_TYPE_STRING, MCM_TYPE_PROFILE, G_TYPE_BOOLEAN);

	/* assign buttons */
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "button_assign_add"));
	g_signal_connect (widget, "clicked",
			  G_CALLBACK (mcm_prefs_assign_add_cb), prefsdata);
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "button_assign_remove"));
	g_signal_connect (widget, "clicked",
			  G_CALLBACK (mcm_prefs_assign_remove_cb), prefsdata);
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "button_assign_make_default"));
	g_signal_connect (widget, "clicked",
			  G_CALLBACK (mcm_prefs_assign_make_default_cb), prefsdata);

	/* create device tree view */
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "treeview_devices"));
	gtk_tree_view_set_model (GTK_TREE_VIEW (widget),
				 GTK_TREE_MODEL (prefsdata->list_store_devices));
	selection = gtk_tree_view_get_selection (GTK_TREE_VIEW (widget));
	g_signal_connect (selection, "changed",
			  G_CALLBACK (mcm_prefs_devices_treeview_clicked_cb), prefsdata);

	/* add columns to the tree view */
	mcm_prefs_add_devices_columns (prefsdata, GTK_TREE_VIEW (widget));
	gtk_tree_view_columns_autosize (GTK_TREE_VIEW (widget));

	/* create profile tree view */
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "treeview_profiles"));
	gtk_tree_view_set_model (GTK_TREE_VIEW (widget),
				 GTK_TREE_MODEL (prefsdata->list_store_profiles));
	selection = gtk_tree_view_get_selection (GTK_TREE_VIEW (widget));
	g_signal_connect (selection, "changed",
			  G_CALLBACK (mcm_prefs_profiles_treeview_clicked_cb), prefsdata);

	/* add columns to the tree view */
	mcm_prefs_add_profiles_columns (prefsdata, GTK_TREE_VIEW (widget));
	gtk_tree_view_columns_autosize (GTK_TREE_VIEW (widget));

	/* create assign tree view */
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "treeview_assign"));
	gtk_tree_view_set_model (GTK_TREE_VIEW (widget),
				 GTK_TREE_MODEL (prefsdata->list_store_assign));
	g_signal_connect (GTK_TREE_VIEW (widget), "row-activated",
			  G_CALLBACK (mcm_prefs_assign_treeview_row_activated_cb), prefsdata);
	selection = gtk_tree_view_get_selection (GTK_TREE_VIEW (widget));
	g_signal_connect (selection, "changed",
			  G_CALLBACK (mcm_prefs_assign_treeview_clicked_cb), prefsdata);

	/* add columns to the tree view */
	mcm_prefs_add_assign_columns (prefsdata, GTK_TREE_VIEW (widget));
	gtk_tree_view_columns_autosize (GTK_TREE_VIEW (widget));
	gtk_tree_view_set_reorderable (GTK_TREE_VIEW (widget), TRUE);

	main_window = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "dialog_prefs"));
	gtk_application_add_window (prefsdata->application, GTK_WINDOW (main_window));

	/* Hide window first so that the dialogue resizes itself without redrawing */
	gtk_widget_hide (main_window);
	gtk_window_set_icon_name (GTK_WINDOW (main_window), MCM_STOCK_ICON);
	g_signal_connect (main_window, "delete_event",
			  G_CALLBACK (mcm_prefs_delete_event_cb), prefsdata);
	g_signal_connect (main_window, "drag-data-received",
			  G_CALLBACK (mcm_prefs_drag_data_received_cb), prefsdata);
	mcm_prefs_setup_drag_and_drop (GTK_WIDGET(main_window));

	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "button_close"));
	g_signal_connect (widget, "clicked",
			  G_CALLBACK (mcm_prefs_close_cb), prefsdata);
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "button_default"));
	g_signal_connect (widget, "clicked",
			  G_CALLBACK (mcm_prefs_default_cb), prefsdata);
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "button_help"));
	g_signal_connect (widget, "clicked",
			  G_CALLBACK (mcm_prefs_help_cb), prefsdata);
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "button_reset"));
	g_signal_connect (widget, "clicked",
			  G_CALLBACK (mcm_prefs_reset_cb), prefsdata);
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "button_delete"));
	g_signal_connect (widget, "clicked",
			  G_CALLBACK (mcm_prefs_delete_cb), prefsdata);
	gtk_widget_set_sensitive (widget, FALSE);
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "button_device_add"));
	g_signal_connect (widget, "clicked",
			  G_CALLBACK (mcm_prefs_device_add_cb), prefsdata);
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "button_calibrate"));
	g_signal_connect (widget, "clicked",
			  G_CALLBACK (mcm_prefs_calibrate_cb), prefsdata);
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "button_profile_delete"));
	g_signal_connect (widget, "clicked",
			  G_CALLBACK (mcm_prefs_profile_delete_cb), prefsdata);
	gtk_widget_set_sensitive (widget, FALSE);
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "button_profile_import"));
	g_signal_connect (widget, "clicked",
			  G_CALLBACK (mcm_prefs_profile_import_cb), prefsdata);
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "expander_fine_tuning"));
	gtk_widget_set_sensitive (widget, FALSE);

	/* hidden until a profile is selected */
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "vbox_graph"));
	gtk_widget_set_visible (widget, FALSE);
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "vbox_profile_info"));
	gtk_widget_set_visible (widget, FALSE);

	/* hide widgets by default */
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "vbox_device_details"));
	gtk_widget_hide (widget);
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "label_profile"));
	gtk_widget_set_sensitive (widget, FALSE);
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "hbox_manufacturer"));
	gtk_widget_hide (widget);
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "hbox_model"));
	gtk_widget_hide (widget);
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "hbox_serial"));
	gtk_widget_hide (widget);

	/* set up virtual dialog */
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "dialog_virtual"));
	g_signal_connect (widget, "delete-event",
			  G_CALLBACK (mcm_prefs_virtual_delete_event_cb), prefsdata);
	g_signal_connect (widget, "drag-data-received",
			  G_CALLBACK (mcm_prefs_virtual_drag_data_received_cb), prefsdata);
	mcm_prefs_setup_drag_and_drop (widget);

	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "button_virtual_add"));
	g_signal_connect (widget, "clicked",
			  G_CALLBACK (mcm_prefs_button_virtual_add_cb), prefsdata);
	gtk_widget_set_sensitive (widget, FALSE);

	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "button_virtual_cancel"));
	g_signal_connect (widget, "clicked",
			  G_CALLBACK (mcm_prefs_button_virtual_cancel_cb), prefsdata);

	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "combobox_virtual_type"));
	mcm_prefs_set_combo_simple_text (widget);
	mcm_prefs_setup_virtual_combobox (widget);

	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "combobox_graph"));
	mcm_prefs_set_combo_simple_text (widget);
	mcm_prefs_setup_graph_combobox (prefsdata, widget);
	g_signal_connect (widget, "changed",
			  G_CALLBACK (mcm_prefs_graph_combo_changed_cb), prefsdata);

	/* set up assign dialog */
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "dialog_assign"));
	g_signal_connect (widget, "delete-event",
			  G_CALLBACK (mcm_prefs_assign_delete_event_cb), prefsdata);
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "button_assign_cancel"));
	g_signal_connect (widget, "clicked",
			  G_CALLBACK (mcm_prefs_button_assign_cancel_cb), prefsdata);
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "button_assign_ok"));
	g_signal_connect (widget, "clicked",
			  G_CALLBACK (mcm_prefs_button_assign_ok_cb), prefsdata);

	/* disable the add button if nothing in either box */
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "entry_virtual_model"));
	g_signal_connect (widget, "notify::text",
			  G_CALLBACK (mcm_prefs_button_virtual_entry_changed_cb), prefsdata);
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "entry_virtual_manufacturer"));
	g_signal_connect (widget, "notify::text",
			  G_CALLBACK (mcm_prefs_button_virtual_entry_changed_cb), prefsdata);

	/* setup icc profiles list */
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "combobox_profile"));
	mcm_prefs_set_combo_simple_text (widget);
	gtk_widget_set_sensitive (widget, FALSE);
	g_signal_connect (G_OBJECT (widget), "changed",
			  G_CALLBACK (mcm_prefs_profile_combo_changed_cb), prefsdata);

	/* set ranges */
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "hscale_gamma"));
	gtk_range_set_range (GTK_RANGE (widget), 0.1f, 5.0f);
	gtk_scale_add_mark (GTK_SCALE (widget), 1.0f, GTK_POS_TOP, "");
	gtk_scale_add_mark (GTK_SCALE (widget), 1.8f, GTK_POS_TOP, "");
	gtk_scale_add_mark (GTK_SCALE (widget), 2.2f, GTK_POS_TOP, "");

	/* set ranges */
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "hscale_brightness"));
	gtk_range_set_range (GTK_RANGE (widget), 0.0f, 0.9f);
//	gtk_scale_add_mark (GTK_SCALE (widget), 0.0f, GTK_POS_TOP, "");

	/* set ranges */
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "hscale_contrast"));
	gtk_range_set_range (GTK_RANGE (widget), 0.1f, 1.0f);
//	gtk_scale_add_mark (GTK_SCALE (widget), 1.0f, GTK_POS_TOP, "");

	/* use a device client array */
	prefsdata->mcm_client = mcm_client_new ();
	mcm_client_set_use_threads (prefsdata->mcm_client, TRUE);
	g_signal_connect (prefsdata->mcm_client, "added", G_CALLBACK (mcm_prefs_added_cb), prefsdata);
	g_signal_connect (prefsdata->mcm_client, "removed", G_CALLBACK (mcm_prefs_removed_cb), prefsdata);
	g_signal_connect (prefsdata->mcm_client, "changed", G_CALLBACK (mcm_prefs_changed_cb), prefsdata);
	g_signal_connect (prefsdata->mcm_client, "notify::loading",
			  G_CALLBACK (mcm_prefs_client_notify_loading_cb), prefsdata);

	/* use the color device */
	prefsdata->colorimeter = mcm_colorimeter_new ();
	g_signal_connect (prefsdata->colorimeter, "changed", G_CALLBACK (mcm_prefs_colorimeter_changed_cb), prefsdata);

	/* set the parent window if it is specified */
	if (xid != 0) {
		egg_debug ("Setting xid %i", xid);
		mcm_window_set_parent_xid (GTK_WINDOW (main_window), xid);
	}

	/* use cie widget */
	prefsdata->cie_widget = mcm_cie_widget_new ();
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "hbox_cie_widget"));
	gtk_box_pack_start (GTK_BOX(widget), prefsdata->cie_widget, TRUE, TRUE, 0);
	gtk_box_reorder_child (GTK_BOX(widget), prefsdata->cie_widget, 0);

	/* use trc widget */
	prefsdata->trc_widget = mcm_trc_widget_new ();
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "hbox_trc_widget"));
	gtk_box_pack_start (GTK_BOX(widget), prefsdata->trc_widget, TRUE, TRUE, 0);
	gtk_box_reorder_child (GTK_BOX(widget), prefsdata->trc_widget, 0);

	/* use vcgt widget */
	prefsdata->vcgt_widget = mcm_trc_widget_new ();
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "hbox_vcgt_widget"));
	gtk_box_pack_start (GTK_BOX(widget), prefsdata->vcgt_widget, TRUE, TRUE, 0);
	gtk_box_reorder_child (GTK_BOX(widget), prefsdata->vcgt_widget, 0);

	/* do we set a default size to make the window larger? */
	screen = gdk_screen_get_default ();
	if (gdk_screen_get_width (screen) < 1024 ||
	    gdk_screen_get_height (screen) < 768) {
		gtk_widget_set_size_request (prefsdata->cie_widget, 50, 50);
		gtk_widget_set_size_request (prefsdata->trc_widget, 50, 50);
		gtk_widget_set_size_request (prefsdata->vcgt_widget, 50, 50);
	} else {
		gtk_widget_set_size_request (prefsdata->cie_widget, 200, 200);
		gtk_widget_set_size_request (prefsdata->trc_widget, 200, 200);
		gtk_widget_set_size_request (prefsdata->vcgt_widget, 200, 200);
	}

	/* use infobar */
	prefsdata->info_bar_loading = gtk_info_bar_new ();
	prefsdata->info_bar_vcgt = gtk_info_bar_new ();
	g_signal_connect (prefsdata->info_bar_vcgt, "response",
			  G_CALLBACK (mcm_prefs_info_bar_response_cb), prefsdata);
	prefsdata->info_bar_profiles = gtk_info_bar_new ();
	g_signal_connect (prefsdata->info_bar_profiles, "response",
			  G_CALLBACK (mcm_prefs_info_bar_response_cb), prefsdata);

	/* TRANSLATORS: button for more details about the vcgt failure */
	gtk_info_bar_add_button (GTK_INFO_BAR(prefsdata->info_bar_vcgt), _("More Information"), GTK_RESPONSE_HELP);
	/* TRANSLATORS: button to install extra profiles */
	gtk_info_bar_add_button (GTK_INFO_BAR(prefsdata->info_bar_profiles), _("Install now"), GTK_RESPONSE_APPLY);

	/* TRANSLATORS: this is displayed while the devices are being probed */
	info_bar_loading_label = gtk_label_new (_("Loading list of devices…"));
	gtk_info_bar_set_message_type (GTK_INFO_BAR(prefsdata->info_bar_loading), GTK_MESSAGE_INFO);
	widget = gtk_info_bar_get_content_area (GTK_INFO_BAR(prefsdata->info_bar_loading));
	gtk_container_add (GTK_CONTAINER(widget), info_bar_loading_label);
	gtk_widget_show (info_bar_loading_label);

	/* TRANSLATORS: this is displayed when the profile is crap */
	info_bar_vcgt_label = gtk_label_new (_("This profile does not have the information required for whole-screen color correction."));
	gtk_label_set_line_wrap (GTK_LABEL (info_bar_vcgt_label), TRUE);
	gtk_info_bar_set_message_type (GTK_INFO_BAR(prefsdata->info_bar_vcgt), GTK_MESSAGE_INFO);
	widget = gtk_info_bar_get_content_area (GTK_INFO_BAR(prefsdata->info_bar_vcgt));
	gtk_container_add (GTK_CONTAINER(widget), info_bar_vcgt_label);
	gtk_widget_show (info_bar_vcgt_label);

	/* TRANSLATORS: this is displayed when the profile is crap */
	info_bar_profiles_label = gtk_label_new (_("More color profiles could be automatically installed."));
	gtk_label_set_line_wrap (GTK_LABEL (info_bar_profiles_label), TRUE);
	gtk_info_bar_set_message_type (GTK_INFO_BAR(prefsdata->info_bar_profiles), GTK_MESSAGE_INFO);
	widget = gtk_info_bar_get_content_area (GTK_INFO_BAR(prefsdata->info_bar_profiles));
	gtk_container_add (GTK_CONTAINER(widget), info_bar_profiles_label);
	gtk_widget_show (info_bar_profiles_label);

	/* add infobar to devices pane */
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "vbox_devices"));
	gtk_box_pack_start (GTK_BOX(widget), prefsdata->info_bar_loading, FALSE, FALSE, 0);

	/* add infobar to devices pane */
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "vbox_sections"));
	gtk_box_pack_start (GTK_BOX(widget), prefsdata->info_bar_vcgt, FALSE, FALSE, 0);

	/* add infobar to defaults pane */
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "vbox3"));
	gtk_box_pack_start (GTK_BOX(widget), prefsdata->info_bar_profiles, TRUE, FALSE, 0);

	/* show main UI */
	gtk_widget_show (main_window);

	/* refresh UI */
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "combobox_graph"));
	mcm_prefs_graph_combo_changed_cb (widget, prefsdata);

	/* connect up sliders */
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "hscale_contrast"));
	g_signal_connect (widget, "value-changed",
			  G_CALLBACK (mcm_prefs_slider_changed_cb), prefsdata);
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "hscale_brightness"));
	g_signal_connect (widget, "value-changed",
			  G_CALLBACK (mcm_prefs_slider_changed_cb), prefsdata);
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "hscale_gamma"));
	g_signal_connect (widget, "value-changed",
			  G_CALLBACK (mcm_prefs_slider_changed_cb), prefsdata);

	/* connect up global widget */
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "checkbutton_display"));
	g_settings_bind (prefsdata->settings,
			 MCM_SETTINGS_GLOBAL_DISPLAY_CORRECTION,
			 widget, "active",
			 G_SETTINGS_BIND_DEFAULT);
	g_signal_connect (widget, "clicked",
			  G_CALLBACK (mcm_prefs_checkbutton_changed_cb), prefsdata);

	/* connect up atom widget */
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "checkbutton_profile"));
	g_settings_bind (prefsdata->settings,
			 MCM_SETTINGS_SET_ICC_PROFILE_ATOM,
			 widget, "active",
			 G_SETTINGS_BIND_DEFAULT);
	g_signal_connect (widget, "clicked",
			  G_CALLBACK (mcm_prefs_checkbutton_changed_cb), prefsdata);

	/* do we show the fine tuning box */
	widget = GTK_WIDGET (gtk_builder_get_object (prefsdata->builder, "expander_fine_tuning"));
	g_settings_bind (prefsdata->settings,
			 MCM_SETTINGS_SHOW_FINE_TUNING,
			 widget, "visible",
			 G_SETTINGS_BIND_DEFAULT | G_SETTINGS_BIND_NO_SENSITIVITY);

	/* do all this after the window has been set up */
	g_idle_add ((GSourceFunc) mcm_prefs_startup_phase1_idle_cb, prefsdata);

	/* wait */
	gtk_application_run (prefsdata->application);
out:
	g_object_unref (prefsdata->application);
	if (prefsdata->current_device != NULL)
		g_object_unref (prefsdata->current_device);
	if (prefsdata->colorimeter != NULL)
		g_object_unref (prefsdata->colorimeter);
	if (prefsdata->settings != NULL)
		g_object_unref (prefsdata->settings);
	if (prefsdata->builder != NULL)
		g_object_unref (prefsdata->builder);
	if (prefsdata->profile_store != NULL)
		g_object_unref (prefsdata->profile_store);
	if (prefsdata->mcm_client != NULL)
		g_object_unref (prefsdata->mcm_client);
	g_free (prefsdata);
	return retval;
}

