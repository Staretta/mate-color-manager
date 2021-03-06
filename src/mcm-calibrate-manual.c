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
 * SECTION:mcm-calibrate-manual
 * @short_description: routines to manually create a color profile.
 *
 * This object can create an ICC file manually.
 */

#include "config.h"

#include <glib-object.h>
#include <glib/gi18n.h>
#include <gtk/gtk.h>
#include <math.h>

#include "egg-debug.h"

#include "mcm-utils.h"
#include "mcm-clut.h"
#include "mcm-gamma-widget.h"
#include "mcm-trc-widget.h"
#include "mcm-calibrate-manual.h"

#include "egg-debug.h"

static void     mcm_calibrate_manual_finalize	(GObject     *object);

#define MCM_CALIBRATE_MANUAL_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), MCM_TYPE_CALIBRATE_MANUAL, McmCalibrateManualPrivate))

/**
 * McmCalibrateManualPrivate:
 *
 * Private #McmCalibrateManual data
 **/
struct _McmCalibrateManualPrivate
{
	guint				 calibration_steps;
	GMainLoop			*loop;
	GtkBuilder			*builder;
	gboolean			 setting_up_colors;
	GtkWidget			*gamma_widget;
	GtkWidget			*trc_widget;
	gdouble				 midpoint;
	guint				 current_page;
	guint				 current_gamma;
	gdouble				*profile_red;
	gdouble				*profile_green;
	gdouble				*profile_blue;
	GError				**error;
	gboolean			 ret;
};

enum {
	PROP_0,
	PROP_CALIBRATION_STEPS,
	PROP_LAST
};

enum {
	MCM_CALIBRATE_MANUAL_PAGE_INTRO,
	MCM_CALIBRATE_MANUAL_PAGE_GAMMA,
	MCM_CALIBRATE_MANUAL_PAGE_LAST
};

G_DEFINE_TYPE (McmCalibrateManual, mcm_calibrate_manual, MCM_TYPE_CALIBRATE)


/**
 * mcm_calibrate_manual_close_cb:
 **/
static void
mcm_calibrate_manual_close_cb (GtkWidget *widget, McmCalibrateManual *calibrate)
{
	McmCalibrateManualPrivate *priv = calibrate->priv;

	/* we closed */
	priv->ret = FALSE;
	if (priv->error != NULL)
		*(priv->error) = g_error_new (MCM_CALIBRATE_ERROR,
					      MCM_CALIBRATE_ERROR_USER_ABORT,
					      "user closed window");

	/* we're done */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "dialog_calibrate"));
	gtk_widget_hide (widget);
	g_main_loop_quit (priv->loop);
}

/**
 * mcm_calibrate_manual_delete_event_cb:
 **/
static gboolean
mcm_calibrate_manual_delete_event_cb (GtkWidget *widget, GdkEvent *event, McmCalibrateManual *calibrate)
{
	mcm_calibrate_manual_close_cb (widget, calibrate);
	return FALSE;
}

/**
 * mcm_calibrate_manual_help_cb:
 **/
static void
mcm_calibrate_manual_help_cb (GtkWidget *widget, McmCalibrateManual *calibrate)
{
	mcm_mate_help ("calibrate-manual");
}

/**
 * mcm_calibrate_manual_slider_changed_cb:
 **/
static void
mcm_calibrate_manual_slider_changed_cb (GtkRange *range, McmCalibrateManual *calibrate)
{
	gdouble brightness;
	gdouble red;
	gdouble green;
	gdouble blue;
	GtkWidget *widget;
	McmCalibrateManualPrivate *priv = calibrate->priv;

	/* we're just setting up the colors, not moving the slider */
	if (priv->setting_up_colors)
		goto out;

	/* get values */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "hscale_brightness"));
	brightness = gtk_range_get_value (GTK_RANGE (widget));
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "hscale_red"));
	red = gtk_range_get_value (GTK_RANGE (widget));
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "hscale_green"));
	green = gtk_range_get_value (GTK_RANGE (widget));
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "hscale_blue"));
	blue = gtk_range_get_value (GTK_RANGE (widget));

	/* offset */
	red = priv->midpoint + red + brightness;
	green = priv->midpoint + green + brightness;
	blue = priv->midpoint + blue + brightness;

	/* constrain */
	red = CLAMP (red, 0.0f, 1.0f);
	green = CLAMP (green, 0.0f, 1.0f);
	blue = CLAMP (blue, 0.0f, 1.0f);

	g_object_set (priv->gamma_widget,
		      "color-red", red,
		      "color-green", green,
		      "color-blue", blue,
		      NULL);

	/* save in array */
	priv->profile_red[priv->current_gamma] = red;
	priv->profile_green[priv->current_gamma] = green;
	priv->profile_blue[priv->current_gamma] = blue;

	egg_debug ("@%i, (%f,%f,%f)", priv->current_gamma, red, green, blue);
out:
	return;
}

/**
 * mcm_calibrate_manual_setup_page:
 **/
static void
mcm_calibrate_manual_setup_page (McmCalibrateManual *calibrate, guint page)
{
	GtkWidget *widget;
	gdouble light = 1.0f;
	gdouble dark = 0.0f;
	gdouble ave;
	gchar *title = NULL;
	gdouble div;
	GString *string_title = NULL;
	GString *string_msg = NULL;
	McmCalibrateManualPrivate *priv = calibrate->priv;

	if (page == MCM_CALIBRATE_MANUAL_PAGE_INTRO) {
		widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "label_title"));
		/* TRANSLATORS: dialog title */
		gtk_label_set_label (GTK_LABEL(widget), _("Introduction to display calibration"));
		widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "button_next"));
		gtk_widget_show (widget);
		widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "button_prev"));
		gtk_widget_hide (widget);
		widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "button_apply"));
		gtk_widget_hide (widget);
		widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "table_adjust"));
		gtk_widget_hide (widget);
		widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "expander_details"));
		gtk_widget_hide (widget);
		widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "aspectframe_gamma"));
		gtk_widget_hide (widget);
		widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "aspectframe_trc"));
		gtk_widget_hide (widget);
		widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "hbox_text1"));
		gtk_widget_show (widget);

		string_msg = g_string_new ("");
		string_title = g_string_new ("");

		/* TRANSLATORS: message text, an ICC profile is a file that characterizes the device */
		g_string_append_printf (string_msg, "%s ", _("This dialog will help calibrate your display and create a custom ICC profile."));

		/* TRANSLATORS: message text, telling the user they are in for the long haul */
		g_string_append_printf (string_msg, "%s ", _("The calibration will involve several steps so that an accurate profile can be obtained."));

		/* TRANSLATORS: message text, this is a lie. It will take more than a few minutes, but we don't want to scare the hapless user */
		g_string_append_printf (string_msg, "%s", _("It should only take a few minutes."));

		/* set the message */
		widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "label_text1"));
		gtk_label_set_label (GTK_LABEL(widget), string_msg->str);

		widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "hbox_text2"));
		gtk_widget_show (widget);

		/* TRANSLATORS: message text, when you're comparing colors, it helps if the image is a bit out of focus otherwise the
		 * fovea (center bit of the eye) tries to 'pick out' a colour, rather than take the average reading */
		g_string_append_printf (string_title, "%s ", _("It may help to sit further from the screen or to squint at the calibration images in order to accurately compare the colors."));

		/* TRANSLATORS: message text, tell the use that they can go back and forwards, as the human eye sucks */
		g_string_append_printf (string_title, "%s", _("You can repeat the calibration steps as many times as you want."));

		/* set the message */
		widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "label_text2"));
		gtk_label_set_label (GTK_LABEL(widget), string_title->str);
		goto out;
	}

	if (page == MCM_CALIBRATE_MANUAL_PAGE_GAMMA) {

		widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "label_title"));
		/* TRANSLATORS: dialog title */
		title = g_strdup_printf (_("Create table item %i/%i"), priv->current_gamma+1, priv->calibration_steps);
		gtk_label_set_label (GTK_LABEL(widget), title);

		widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "button_next"));
		gtk_widget_show (widget);
		widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "button_prev"));
		gtk_widget_show (widget);
		widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "button_apply"));
		gtk_widget_hide (widget);
		widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "table_adjust"));
		gtk_widget_show (widget);
		widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "expander_details"));
		gtk_widget_hide (widget);
		widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "aspectframe_gamma"));
		gtk_widget_show (widget);
		widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "aspectframe_trc"));
		gtk_widget_hide (widget);
		widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "hbox_text1"));
		gtk_widget_show (widget);
		widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "label_text1"));
		/* TRANSLATORS: message text */
		gtk_label_set_label (GTK_LABEL(widget), _("Please try to match up the gray square with the surrounding alternating bars. "
							  "You should match the brightness first, and then if required change the color tint so it looks plain gray."));
		widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "hbox_text2"));
		gtk_widget_hide (widget);

		/* calculate range */
		div = 1.0f / (gfloat) priv->calibration_steps;
		dark = div * priv->current_gamma;
		light = (div * priv->current_gamma) + div;

		/* save colors */
		priv->midpoint = dark + ((light - dark) / 2.0f);

		/* save default */
		if (priv->profile_red[priv->current_gamma] > 1.0f) {
			egg_debug ("resetting %i to %f", page, priv->midpoint);
			priv->profile_red[priv->current_gamma] = priv->midpoint;
			priv->profile_green[priv->current_gamma] = priv->midpoint;
			priv->profile_blue[priv->current_gamma] = priv->midpoint;
		}

		/* dis-arm */
		priv->setting_up_colors = TRUE;

		/* brightness is average */
		ave = (priv->profile_red[priv->current_gamma] + priv->profile_green[priv->current_gamma] + priv->profile_blue[priv->current_gamma]) / 3.0f;
		widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "hscale_brightness"));
		gtk_range_set_value (GTK_RANGE(widget), ave - priv->midpoint);
		egg_debug ("brightness compensation=%f", (ave - priv->midpoint));

		/* color is offset */
		widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "hscale_red"));
		gtk_range_set_value (GTK_RANGE(widget), priv->profile_red[priv->current_gamma] - priv->midpoint - (priv->midpoint - ave));
		widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "hscale_green"));
		gtk_range_set_value (GTK_RANGE(widget), priv->profile_green[priv->current_gamma] - priv->midpoint - (priv->midpoint - ave));
		widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "hscale_blue"));
		gtk_range_set_value (GTK_RANGE(widget), priv->profile_blue[priv->current_gamma] - priv->midpoint - (priv->midpoint - ave));
		
		/* arm, ready for launch */
		priv->setting_up_colors = FALSE;

		/* constrain */
		priv->profile_red[priv->current_gamma] = CLAMP (priv->profile_red[priv->current_gamma], 0.0f, 1.0f);
		priv->profile_green[priv->current_gamma] = CLAMP (priv->profile_green[priv->current_gamma], 0.0f, 1.0f);
		priv->profile_blue[priv->current_gamma] = CLAMP (priv->profile_blue[priv->current_gamma], 0.0f, 1.0f);

		egg_debug ("saving colours");
		g_object_set (priv->gamma_widget,
			      "color-light", light,
			      "color-dark", dark,
			      "color-red", priv->profile_red[priv->current_gamma],
			      "color-green", priv->profile_green[priv->current_gamma],
			      "color-blue", priv->profile_blue[priv->current_gamma],
			      NULL);

		goto out;
	}

	if (page == MCM_CALIBRATE_MANUAL_PAGE_LAST) {

		McmClut *clut;
		GPtrArray *array;
		McmClutData *data;
		guint i;

		array = g_ptr_array_new_with_free_func (g_free);

		/* add the zero point */
		data = g_new0 (McmClutData, 1);
		g_ptr_array_add (array, data);

		/* do each */
		for (i=1; i<priv->calibration_steps; i++) {
			data = g_new0 (McmClutData, 1);
			data->red = ((priv->profile_red[i-1] + priv->profile_red[i]) / 2.0f) * (gdouble) 0xffff;
			data->green = ((priv->profile_green[i-1] + priv->profile_green[i]) / 2.0f) * (gdouble) 0xffff;
			data->blue = ((priv->profile_blue[i-1] + priv->profile_blue[i]) / 2.0f) * (gdouble) 0xffff;
			g_ptr_array_add (array, data);
		}

		/* add the last point */
		data = g_new0 (McmClutData, 1);
		data->red = 0xffff;
		data->green = 0xffff;
		data->blue = 0xffff;
		g_ptr_array_add (array, data);

		clut = mcm_clut_new ();
		mcm_clut_set_source_array (clut, array);
		mcm_clut_print (clut);

		g_object_set (priv->trc_widget, "clut", clut, NULL);
		g_object_unref (clut);
		g_ptr_array_unref (array);

		widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "label_title"));
		/* TRANSLATORS: dialog title */
		gtk_label_set_label (GTK_LABEL(widget), _("Summary"));
		widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "button_next"));
		gtk_widget_hide (widget);
		widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "button_prev"));
		gtk_widget_show (widget);
		widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "button_apply"));
		gtk_widget_show (widget);
		widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "table_adjust"));
		gtk_widget_hide (widget);
		widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "expander_details"));
		gtk_widget_hide (widget);
		widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "aspectframe_gamma"));
		gtk_widget_hide (widget);
		widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "aspectframe_trc"));
		gtk_widget_show (widget);
		widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "hbox_text1"));
		gtk_widget_show (widget);
		widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "label_text1"));
		/* TRANSLATORS: message text */
		gtk_label_set_label (GTK_LABEL(widget), _("This display is now calibrated. You can change the current profile using the Color Profiles program."));
		widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "hbox_text2"));
		gtk_widget_hide (widget);
		goto out;
	}

	egg_warning ("oops - no page");
out:
	if (string_title != NULL)
		g_string_free (string_title, TRUE);
	if (string_msg != NULL)
		g_string_free (string_msg, TRUE);
	g_free (title);
	priv->current_page = page;
}

/**
 * mcm_calibrate_manual_next_cb:
 **/
static void
mcm_calibrate_manual_next_cb (GtkWidget *widget, McmCalibrateManual *calibrate)
{
	McmCalibrateManualPrivate *priv = calibrate->priv;

	if (priv->current_page == MCM_CALIBRATE_MANUAL_PAGE_INTRO) {
		priv->current_gamma = 0;
		mcm_calibrate_manual_setup_page (calibrate, priv->current_page+1);
		return;
	}
	if (priv->current_page == MCM_CALIBRATE_MANUAL_PAGE_GAMMA) {
		if (priv->current_gamma == priv->calibration_steps-1) {
			mcm_calibrate_manual_setup_page (calibrate, priv->current_page+1);
			return;
		}
		priv->current_gamma++;
		mcm_calibrate_manual_setup_page (calibrate, priv->current_page);
		return;
	}
}

/**
 * mcm_calibrate_manual_prev_cb:
 **/
static void
mcm_calibrate_manual_prev_cb (GtkWidget *widget, McmCalibrateManual *calibrate)
{
	McmCalibrateManualPrivate *priv = calibrate->priv;

	if (priv->current_page == MCM_CALIBRATE_MANUAL_PAGE_LAST) {
		mcm_calibrate_manual_setup_page (calibrate, priv->current_page-1);
		priv->current_gamma = priv->calibration_steps-1;
		return;
	}
	if (priv->current_page == MCM_CALIBRATE_MANUAL_PAGE_GAMMA) {
		if (priv->current_gamma == 0) {
			mcm_calibrate_manual_setup_page (calibrate, priv->current_page-1);
			return;
		}
		priv->current_gamma--;
		mcm_calibrate_manual_setup_page (calibrate, priv->current_page);
	}
}

/**
 * mcm_calibrate_manual_apply_cb:
 **/
static void
mcm_calibrate_manual_apply_cb (GtkWidget *widget, McmCalibrateManual *calibrate)
{
	McmCalibrateManualPrivate *priv = calibrate->priv;

	guint i;
	for (i=0; i<priv->calibration_steps; i++)
		egg_debug ("@%i, %f, %f, %f", i, priv->profile_red[i], priv->profile_green[i], priv->profile_blue[i]);
	egg_warning ("NOP: need to create profile with lcms!");
	priv->ret = TRUE;

	/* we're done */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "dialog_calibrate"));
	gtk_widget_hide (widget);
	g_main_loop_quit (priv->loop);
}

/**
 * mcm_calibrate_manual_display:
 **/
static gboolean
mcm_calibrate_manual_display (McmCalibrate *calibrate_, GtkWindow *window, GError **error)
{
	GtkWidget *widget;
	guint i;
	McmCalibrateManual *calibrate = MCM_CALIBRATE_MANUAL(calibrate_);
	McmCalibrateManualPrivate *priv = calibrate->priv;
	egg_debug ("calibrate_display in %i steps", priv->calibration_steps);

	/* save error, which can be NULL */
	priv->error = error;

	/* create new array */
	g_free (priv->profile_red);
	g_free (priv->profile_green);
	g_free (priv->profile_blue);
	priv->profile_red = g_new (gdouble, priv->calibration_steps);
	priv->profile_green = g_new (gdouble, priv->calibration_steps);
	priv->profile_blue = g_new (gdouble, priv->calibration_steps);

	/* set to something insane */
	for (i=0; i<priv->calibration_steps; i++) {
		priv->profile_red[i] = 2.0f;
		priv->profile_green[i] = 2.0f;
		priv->profile_blue[i] = 2.0f;
	}

	/* switch to the introduction */
	mcm_calibrate_manual_setup_page (calibrate, MCM_CALIBRATE_MANUAL_PAGE_INTRO);

	/* show main UI */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "dialog_calibrate"));
	gtk_window_set_default_size (GTK_WINDOW (widget), 500, 280);
	gtk_widget_show (widget);

	/* wait */
	g_main_loop_run (priv->loop);

	return priv->ret;
}

/**
 * mcm_calibrate_manual_get_property:
 **/
static void
mcm_calibrate_manual_get_property (GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
	McmCalibrateManual *calibrate = MCM_CALIBRATE_MANUAL (object);
	McmCalibrateManualPrivate *priv = calibrate->priv;

	switch (prop_id) {
	case PROP_CALIBRATION_STEPS:
		g_value_set_uint (value, priv->calibration_steps);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/**
 * mcm_calibrate_manual_set_property:
 **/
static void
mcm_calibrate_manual_set_property (GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec)
{
	McmCalibrateManual *calibrate = MCM_CALIBRATE_MANUAL (object);
	McmCalibrateManualPrivate *priv = calibrate->priv;

	switch (prop_id) {
	case PROP_CALIBRATION_STEPS:
		priv->calibration_steps = g_value_get_uint (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/**
 * mcm_calibrate_manual_class_init:
 **/
static void
mcm_calibrate_manual_class_init (McmCalibrateManualClass *klass)
{
	GParamSpec *pspec;
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	McmCalibrateClass *parent_class = MCM_CALIBRATE_CLASS (klass);
	object_class->finalize = mcm_calibrate_manual_finalize;
	object_class->get_property = mcm_calibrate_manual_get_property;
	object_class->set_property = mcm_calibrate_manual_set_property;

	/* setup klass links */
	parent_class->calibrate_display = mcm_calibrate_manual_display;

	/**
	 * McmCalibrateManual:calibration-steps:
	 */
	pspec = g_param_spec_uint ("calibration-steps", NULL, NULL,
				   0, G_MAXUINT, 5,
				   G_PARAM_READWRITE);
	g_object_class_install_property (object_class, PROP_CALIBRATION_STEPS, pspec);

	g_type_class_add_private (klass, sizeof (McmCalibrateManualPrivate));
}

/**
 * mcm_calibrate_manual_init:
 **/
static void
mcm_calibrate_manual_init (McmCalibrateManual *calibrate)
{
	GtkWidget *widget;
	GError *error = NULL;
	McmCalibrateManualPrivate *priv;
	gint retval;

	priv = calibrate->priv = MCM_CALIBRATE_MANUAL_GET_PRIVATE (calibrate);

	/* good default precision */
	priv->calibration_steps = 10;

	/* block in a loop */
	priv->loop = g_main_loop_new (NULL, FALSE);

	/* get UI */
	priv->builder = gtk_builder_new ();
	retval = gtk_builder_add_from_file (priv->builder, MCM_DATA "/mcm-calibrate.ui", &error);
	if (retval == 0) {
		egg_error ("failed to load ui: %s", error->message);
		g_error_free (error);
	}

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "dialog_calibrate"));

	/* Hide window first so that the dialogue resizes itself without redrawing */
	gtk_widget_hide (widget);
	gtk_window_set_icon_name (GTK_WINDOW (widget), MCM_STOCK_ICON);
	g_signal_connect (widget, "delete_event",
			  G_CALLBACK (mcm_calibrate_manual_delete_event_cb), calibrate);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "button_cancel"));
	g_signal_connect (widget, "clicked",
			  G_CALLBACK (mcm_calibrate_manual_close_cb), calibrate);
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "button_help"));
	g_signal_connect (widget, "clicked",
			  G_CALLBACK (mcm_calibrate_manual_help_cb), calibrate);
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "button_next"));
	g_signal_connect (widget, "clicked",
			  G_CALLBACK (mcm_calibrate_manual_next_cb), calibrate);
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "button_prev"));
	g_signal_connect (widget, "clicked",
			  G_CALLBACK (mcm_calibrate_manual_prev_cb), calibrate);
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "button_apply"));
	g_signal_connect (widget, "clicked",
			  G_CALLBACK (mcm_calibrate_manual_apply_cb), calibrate);

	/* set ranges */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "hscale_brightness"));
	gtk_range_set_range (GTK_RANGE (widget), -0.25f, 0.25f);
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "hscale_red"));
	gtk_range_set_range (GTK_RANGE (widget), -0.25f, 0.25f);
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "hscale_green"));
	gtk_range_set_range (GTK_RANGE (widget), -0.25f, 0.25f);
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "hscale_blue"));
	gtk_range_set_range (GTK_RANGE (widget), -0.25f, 0.25f);

	/* use gamma widget */
	priv->gamma_widget = mcm_gamma_widget_new ();
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "aspectframe_gamma"));
	gtk_container_add (GTK_CONTAINER(widget), priv->gamma_widget);
	gtk_widget_set_size_request (priv->gamma_widget, 150, 150);
	gtk_widget_show (priv->gamma_widget);

	/* use trc widget */
	priv->trc_widget = mcm_trc_widget_new ();
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "aspectframe_trc"));
	gtk_container_add (GTK_CONTAINER(widget), priv->trc_widget);
	gtk_widget_set_size_request (priv->trc_widget, 150, 150);
	gtk_widget_show (priv->trc_widget);

	/* connect up sliders */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "hscale_brightness"));
	g_signal_connect (widget, "value-changed",
			  G_CALLBACK (mcm_calibrate_manual_slider_changed_cb), calibrate);
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "hscale_red"));
	g_signal_connect (widget, "value-changed",
			  G_CALLBACK (mcm_calibrate_manual_slider_changed_cb), calibrate);
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "hscale_green"));
	g_signal_connect (widget, "value-changed",
			  G_CALLBACK (mcm_calibrate_manual_slider_changed_cb), calibrate);
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "hscale_blue"));
	g_signal_connect (widget, "value-changed",
			  G_CALLBACK (mcm_calibrate_manual_slider_changed_cb), calibrate);
}

/**
 * mcm_calibrate_manual_finalize:
 **/
static void
mcm_calibrate_manual_finalize (GObject *object)
{
	McmCalibrateManual *calibrate = MCM_CALIBRATE_MANUAL (object);
	McmCalibrateManualPrivate *priv = calibrate->priv;

	g_free (priv->profile_red);
	g_free (priv->profile_green);
	g_free (priv->profile_blue);

	g_main_loop_unref (priv->loop);
	g_object_unref (priv->builder);

	G_OBJECT_CLASS (mcm_calibrate_manual_parent_class)->finalize (object);
}

/**
 * mcm_calibrate_manual_new:
 *
 * Return value: a new McmCalibrateManual object.
 **/
McmCalibrateManual *
mcm_calibrate_manual_new (void)
{
	McmCalibrateManual *calibrate;
	calibrate = g_object_new (MCM_TYPE_CALIBRATE_MANUAL, NULL);
	return MCM_CALIBRATE_MANUAL (calibrate);
}

