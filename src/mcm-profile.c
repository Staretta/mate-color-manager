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
 * SECTION:mcm-profile
 * @short_description: A parser object that understands the ICC profile data format.
 *
 * This object is a simple parser for the ICC binary profile data. If only understands
 * a subset of the ICC profile, just enought to get some metadata and the LUT.
 */

#include "config.h"

#include <glib-object.h>
#include <glib/gi18n.h>
#include <gio/gio.h>
#include <lcms.h>

#include "egg-debug.h"

#include "mcm-profile.h"
#include "mcm-utils.h"
#include "mcm-xyz.h"

static void     mcm_profile_finalize	(GObject     *object);

#define MCM_PROFILE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), MCM_TYPE_PROFILE, McmProfilePrivate))

#define MCM_NUMTAGS			0x80
#define MCM_BODY			0x84

#define MCM_TAG_ID			0x00
#define MCM_TAG_OFFSET			0x04
#define MCM_TAG_SIZE			0x08
#define MCM_TAG_WIDTH			0x0c

#define icSigVideoCartGammaTableTag	0x76636774
#define icSigMachineLookUpTableTag	0x6d4c5554

#define MCM_MLUT_RED			0x000
#define MCM_MLUT_GREEN			0x200
#define MCM_MLUT_BLUE			0x400

#define MCM_DESC_RECORD_SIZE		0x08
#define MCM_DESC_RECORD_TEXT		0x0c
#define MCM_TEXT_RECORD_TEXT		0x08

#define MCM_VCGT_ID			0x00
#define MCM_VCGT_DUMMY			0x04
#define MCM_VCGT_GAMMA_TYPE		0x08
#define MCM_VCGT_GAMMA_DATA		0x0c

#define MCM_VCGT_FORMULA_GAMMA_RED	0x00
#define MCM_VCGT_FORMULA_MIN_RED	0x04
#define MCM_VCGT_FORMULA_MAX_RED	0x08
#define MCM_VCGT_FORMULA_GAMMA_GREEN	0x0c
#define MCM_VCGT_FORMULA_MIN_GREEN	0x10
#define MCM_VCGT_FORMULA_MAX_GREEN	0x14
#define MCM_VCGT_FORMULA_GAMMA_BLUE	0x18
#define MCM_VCGT_FORMULA_MIN_BLUE	0x1c
#define MCM_VCGT_FORMULA_MAX_BLUE	0x20

#define MCM_VCGT_TABLE_NUM_CHANNELS	0x00
#define MCM_VCGT_TABLE_NUM_ENTRIES	0x02
#define MCM_VCGT_TABLE_NUM_SIZE		0x04
#define MCM_VCGT_TABLE_NUM_DATA		0x06

/**
 * McmProfilePrivate:
 *
 * Private #McmProfile data
 **/
struct _McmProfilePrivate
{
	McmProfileKind		 kind;
	McmColorspace		 colorspace;
	guint			 size;
	gboolean		 has_vcgt;
	gboolean		 can_delete;
	gchar			*description;
	gchar			*filename;
	gchar			*copyright;
	gchar			*manufacturer;
	gchar			*model;
	gchar			*datetime;
	gchar			*checksum;
	McmXyz			*white;
	McmXyz			*black;
	McmXyz			*red;
	McmXyz			*green;
	McmXyz			*blue;
	GFileMonitor		*monitor;

	gboolean			 loaded;
	gboolean			 has_mlut;
	gboolean			 has_vcgt_formula;
	gboolean			 has_vcgt_table;
	cmsHPROFILE			 lcms_profile;
	McmClutData			*vcgt_data;
	guint				 vcgt_data_size;
	McmClutData			*mlut_data;
	guint				 mlut_data_size;
	gboolean			 adobe_gamma_workaround;
};

enum {
	PROP_0,
	PROP_COPYRIGHT,
	PROP_MANUFACTURER,
	PROP_MODEL,
	PROP_DATETIME,
	PROP_CHECKSUM,
	PROP_DESCRIPTION,
	PROP_FILENAME,
	PROP_KIND,
	PROP_COLORSPACE,
	PROP_SIZE,
	PROP_HAS_VCGT,
	PROP_CAN_DELETE,
	PROP_WHITE,
	PROP_BLACK,
	PROP_RED,
	PROP_GREEN,
	PROP_BLUE,
	PROP_LAST
};

G_DEFINE_TYPE (McmProfile, mcm_profile, G_TYPE_OBJECT)

static void mcm_profile_file_monitor_changed_cb (GFileMonitor *monitor, GFile *file, GFile *other_file, GFileMonitorEvent event_type, McmProfile *profile);

/**
 * mcm_parser_decode_32:
 **/
static guint
mcm_parser_decode_32 (const guint8 *data)
{
	guint retval;
	retval = (*(data + 0) << 0) + (*(data + 1) << 8) + (*(data + 2) << 16) + (*(data + 3) << 24);
	return GUINT32_FROM_BE (retval);
}

/**
 * mcm_parser_decode_16:
 **/
static guint
mcm_parser_decode_16 (const guint8 *data)
{
	guint retval;
	retval = (*(data + 0) << 0) + (*(data + 1) << 8);
	return GUINT16_FROM_BE (retval);
}

/**
 * mcm_parser_decode_8:
 **/
static guint
mcm_parser_decode_8 (const guint8 *data)
{
	guint retval;
	retval = (*data << 0);
	return GUINT16_FROM_BE (retval);
}

/**
 * mcm_parser_load_icc_mlut:
 **/
static gboolean
mcm_parser_load_icc_mlut (McmProfile *profile, const guint8 *data, guint size)
{
	gboolean ret = TRUE;
	guint i;
	McmClutData *mlut_data;

	/* just load in data into a fixed size LUT */
	profile->priv->mlut_data = g_new0 (McmClutData, 256);
	mlut_data = profile->priv->mlut_data;

	for (i=0; i<256; i++)
		mlut_data[i].red = mcm_parser_decode_16 (data + MCM_MLUT_RED + i*2);
	for (i=0; i<256; i++)
		mlut_data[i].green = mcm_parser_decode_16 (data + MCM_MLUT_GREEN + i*2);
	for (i=0; i<256; i++)
		mlut_data[i].blue = mcm_parser_decode_16 (data + MCM_MLUT_BLUE + i*2);

	/* save datatype */
	profile->priv->has_mlut = TRUE;
	return ret;
}

/**
 * mcm_parser_load_icc_vcgt_formula:
 **/
static gboolean
mcm_parser_load_icc_vcgt_formula (McmProfile *profile, const guint8 *data, guint size)
{
	gboolean ret = FALSE;
	McmClutData *vcgt_data;

	/* just load in data into a temporary array */
	profile->priv->vcgt_data = g_new0 (McmClutData, 4);
	vcgt_data = profile->priv->vcgt_data;

	/* read in block of data */
	vcgt_data[0].red = mcm_parser_decode_32 (data + MCM_VCGT_FORMULA_GAMMA_RED);
	vcgt_data[0].green = mcm_parser_decode_32 (data + MCM_VCGT_FORMULA_GAMMA_GREEN);
	vcgt_data[0].blue = mcm_parser_decode_32 (data + MCM_VCGT_FORMULA_GAMMA_BLUE);

	vcgt_data[1].red = mcm_parser_decode_32 (data + MCM_VCGT_FORMULA_MIN_RED);
	vcgt_data[1].green = mcm_parser_decode_32 (data + MCM_VCGT_FORMULA_MIN_GREEN);
	vcgt_data[1].blue = mcm_parser_decode_32 (data + MCM_VCGT_FORMULA_MIN_BLUE);

	vcgt_data[2].red = mcm_parser_decode_32 (data + MCM_VCGT_FORMULA_MAX_RED);
	vcgt_data[2].green = mcm_parser_decode_32 (data + MCM_VCGT_FORMULA_MAX_GREEN);
	vcgt_data[2].blue = mcm_parser_decode_32 (data + MCM_VCGT_FORMULA_MAX_BLUE);

	/* check if valid */
	if (vcgt_data[0].red / 65536.0 > 5.0 || vcgt_data[0].green / 65536.0 > 5.0 || vcgt_data[0].blue / 65536.0 > 5.0) {
		egg_warning ("Gamma values out of range: [R:%u G:%u B:%u]", vcgt_data[0].red, vcgt_data[0].green, vcgt_data[0].blue);
		goto out;
	}
	if (vcgt_data[1].red / 65536.0 >= 1.0 || vcgt_data[1].green / 65536.0 >= 1.0 || vcgt_data[1].blue / 65536.0 >= 1.0) {
		egg_warning ("Gamma min limit out of range: [R:%u G:%u B:%u]", vcgt_data[1].red, vcgt_data[1].green, vcgt_data[1].blue);
		goto out;
	}
	if (vcgt_data[2].red / 65536.0 > 1.0 || vcgt_data[2].green / 65536.0 > 1.0 || vcgt_data[2].blue / 65536.0 > 1.0) {
		egg_warning ("Gamma max limit out of range: [R:%u G:%u B:%u]", vcgt_data[2].red, vcgt_data[2].green, vcgt_data[2].blue);
		goto out;
	}

	/* save datatype */
	profile->priv->has_vcgt_formula = TRUE;
	profile->priv->vcgt_data_size = 3;
	ret = TRUE;
out:
	return ret;
}

/**
 * mcm_parser_load_icc_vcgt_table:
 **/
static gboolean
mcm_parser_load_icc_vcgt_table (McmProfile *profile, const guint8 *data, guint size)
{
	gboolean ret = TRUE;
	guint num_channels = 0;
	guint num_entries = 0;
	guint entry_size = 0;
	guint i;
	McmClutData *vcgt_data;

	num_channels = mcm_parser_decode_16 (data + MCM_VCGT_TABLE_NUM_CHANNELS);
	num_entries = mcm_parser_decode_16 (data + MCM_VCGT_TABLE_NUM_ENTRIES);
	entry_size = mcm_parser_decode_16 (data + MCM_VCGT_TABLE_NUM_SIZE);

	/* work-around for AdobeGamma-ProfileLcms1s (taken from xcalib) */
	if (profile->priv->adobe_gamma_workaround) {
		egg_debug ("Working around AdobeGamma profile");
		entry_size = 2;
		num_entries = 256;
		num_channels = 3;
	}

	/* only able to parse RGB data */
	if (num_channels != 3) {
		egg_warning ("cannot parse non RGB entries");
		ret = FALSE;
		goto out;
	}

	/* bigger than will fit in 16 bits? */
	if (entry_size > 2) {
		egg_warning ("cannot parse large entries");
		ret = FALSE;
		goto out;
	}

	/* allocate ramp, plus one entry for extrapolation */
	profile->priv->vcgt_data = g_new0 (McmClutData, num_entries + 1);
	vcgt_data = profile->priv->vcgt_data;

	if (entry_size == 1) {
		for (i=0; i<num_entries; i++)
			vcgt_data[i].red = mcm_parser_decode_8 (data + MCM_VCGT_TABLE_NUM_DATA + (num_entries * 0) + i);
		for (i=0; i<num_entries; i++)
			vcgt_data[i].green = mcm_parser_decode_8 (data + MCM_VCGT_TABLE_NUM_DATA + (num_entries * 1) + i);
		for (i=0; i<num_entries; i++)
			vcgt_data[i].blue = mcm_parser_decode_8 (data + MCM_VCGT_TABLE_NUM_DATA + (num_entries * 2) + i);
	} else {
		for (i=0; i<num_entries; i++)
			vcgt_data[i].red = mcm_parser_decode_16 (data + MCM_VCGT_TABLE_NUM_DATA + (num_entries * 0) + (i*2));
		for (i=0; i<num_entries; i++)
			vcgt_data[i].green = mcm_parser_decode_16 (data + MCM_VCGT_TABLE_NUM_DATA + (num_entries * 2) + (i*2));
		for (i=0; i<num_entries; i++)
			vcgt_data[i].blue = mcm_parser_decode_16 (data + MCM_VCGT_TABLE_NUM_DATA + (num_entries * 4) + (i*2));
	}

	/* save datatype */
	profile->priv->has_vcgt_table = TRUE;
	profile->priv->vcgt_data_size = num_entries;
out:
	return ret;
}

/**
 * mcm_parser_load_icc_vcgt:
 **/
static gboolean
mcm_parser_load_icc_vcgt (McmProfile *profile, const guint8 *data, guint size)
{
	gboolean ret = FALSE;
	guint tag_id;
	guint gamma_type;

	/* check we have a VCGT block */
	tag_id = mcm_parser_decode_32 (data);
	if (tag_id != icSigVideoCartGammaTableTag) {
		egg_warning ("invalid content of table vcgt, starting with %x", tag_id);
		goto out;
	}

	/* check what type of gamma encoding we have */
	gamma_type = mcm_parser_decode_32 (data + MCM_VCGT_GAMMA_TYPE);
	if (gamma_type == 0) {
		ret = mcm_parser_load_icc_vcgt_table (profile, data + MCM_VCGT_GAMMA_DATA, size);
		goto out;
	}
	if (gamma_type == 1) {
		ret = mcm_parser_load_icc_vcgt_formula (profile, data + MCM_VCGT_GAMMA_DATA, size);
		goto out;
	}

	/* we didn't understand the encoding */
	egg_warning ("gamma type encoding not recognized");
out:
	return ret;
}

/**
 * mcm_profile_utf16be_to_locale:
 *
 * Convert ICC encoded UTF-16BE into a string the user can understand
 **/
static gchar *
mcm_profile_utf16be_to_locale (const guint8 *text, guint size)
{
	gsize items_written;
	gchar *text_utf8 = NULL;
	gchar *text_locale = NULL;
	GError *error = NULL;

	/* convert from ICC text encoding to UTF-8 */
	text_utf8 = g_convert ((const gchar*)text, size, "UTF-8", "UTF-16BE", NULL, &items_written, &error);
	if (text_utf8 == NULL) {
		egg_warning ("failed to convert to UTF-8: %s", error->message);
		g_error_free (error);
		goto out;
	}

	/* convert from UTF-8 to the users locale*/
	text_locale = g_locale_from_utf8 (text_utf8, items_written, NULL, NULL, &error);
	if (text_locale == NULL) {
		egg_warning ("failed to convert to locale: %s", error->message);
		g_error_free (error);
		goto out;
	}
out:
	g_free (text_utf8);
	return text_locale;
}

/**
 * mcm_profile_parse_multi_localized_unicode:
 **/
static gchar *
mcm_profile_parse_multi_localized_unicode (McmProfile *profile, const guint8 *data, guint size)
{
	guint i;
	gchar *text = NULL;
	guint record_size;
	guint names_size;
	guint len;
	guint offset_name;
	guint32 type;

	/* get type */
	type = mcm_parser_decode_32 (data);

	/* check we are not a localized tag */
	if (type == icSigTextDescriptionType) {
		record_size = mcm_parser_decode_32 (data + MCM_DESC_RECORD_SIZE);
		text = g_strndup ((const gchar*)&data[MCM_DESC_RECORD_TEXT], record_size);
		goto out;
	}

	/* check we are not a localized tag */
	if (type == icSigTextType) {
		text = g_strdup ((const gchar*)&data[MCM_TEXT_RECORD_TEXT]);
		goto out;
	}

	/* check we are not a localized tag */
	if (type == icSigMultiLocalizedUnicodeType) {
		names_size = mcm_parser_decode_32 (data + 8);
		if (names_size != 1) {
			/* there is more than one language encoded */
			egg_warning ("more than one item of data in MLUC (names size: %i), using first one", names_size);
		}
		len = mcm_parser_decode_32 (data + 20);
		offset_name = mcm_parser_decode_32 (data + 24);
		text = mcm_profile_utf16be_to_locale (data + offset_name, len);
		goto out;
	}

	/* an unrecognized tag */
	for (i=0x0; i<0x1c; i++) {
		egg_warning ("unrecognized text tag");
		if (data[i] >= 'A' && data[i] <= 'z')
			egg_debug ("%i\t%c (%i)", i, data[i], data[i]);
		else
			egg_debug ("%i\t  (%i)", i, data[i]);
	}
out:
	return text;
}

/**
 * mcm_profile_get_description:
 **/
const gchar *
mcm_profile_get_description (McmProfile *profile)
{
	g_return_val_if_fail (MCM_IS_PROFILE (profile), NULL);
	return profile->priv->description;
}

/**
 * mcm_profile_set_description:
 **/
void
mcm_profile_set_description (McmProfile *profile, const gchar *description)
{
	McmProfilePrivate *priv = profile->priv;
	g_return_if_fail (MCM_IS_PROFILE (profile));

	g_free (priv->description);
	priv->description = g_strdup (description);

	if (priv->description != NULL)
		mcm_utils_ensure_printable (priv->description);

	/* there's nothing sensible to display */
	if (priv->description == NULL || priv->description[0] == '\0') {
		g_free (priv->description);
		if (priv->filename != NULL) {
			priv->description = g_path_get_basename (priv->filename);
		} else {
			/* TRANSLATORS: this is where the ICC profile has no description */
			priv->description = g_strdup (_("Missing description"));
		}
	}
	g_object_notify (G_OBJECT (profile), "description");
}

/**
 * mcm_profile_get_filename:
 **/
const gchar *
mcm_profile_get_filename (McmProfile *profile)
{
	g_return_val_if_fail (MCM_IS_PROFILE (profile), NULL);
	return profile->priv->filename;
}

/**
 * mcm_profile_has_colorspace_description:
 *
 * Return value: if the description mentions the profile colorspace explicity,
 * e.g. "Adobe RGB" for %MCM_COLORSPACE_RGB.
 **/
gboolean
mcm_profile_has_colorspace_description (McmProfile *profile)
{
	McmProfilePrivate *priv = profile->priv;
	g_return_val_if_fail (MCM_IS_PROFILE (profile), FALSE);

	/* for each profile type */
	if (priv->colorspace == MCM_COLORSPACE_RGB)
		return (g_strstr_len (priv->description, -1, "RGB") != NULL);
	if (priv->colorspace == MCM_COLORSPACE_CMYK)
		return (g_strstr_len (priv->description, -1, "CMYK") != NULL);

	/* nothing */
	return FALSE;
}

/**
 * mcm_profile_set_filename:
 **/
void
mcm_profile_set_filename (McmProfile *profile, const gchar *filename)
{
	McmProfilePrivate *priv = profile->priv;
	GFile *file;

	g_return_if_fail (MCM_IS_PROFILE (profile));

	g_free (priv->filename);
	priv->filename = g_strdup (filename);

	/* unref old instance */
	if (priv->monitor != NULL) {
		g_object_unref (priv->monitor);
		priv->monitor = NULL;
	}

	/* setup watch on new profile */
	if (priv->filename != NULL) {
		file = g_file_new_for_path (priv->filename);
		priv->monitor = g_file_monitor_file (file, G_FILE_MONITOR_NONE, NULL, NULL);
		if (priv->monitor != NULL)
			g_signal_connect (priv->monitor, "changed", G_CALLBACK(mcm_profile_file_monitor_changed_cb), profile);
		g_object_unref (file);
	}
	g_object_notify (G_OBJECT (profile), "filename");
}

/**
 * mcm_profile_get_copyright:
 **/
const gchar *
mcm_profile_get_copyright (McmProfile *profile)
{
	g_return_val_if_fail (MCM_IS_PROFILE (profile), NULL);
	return profile->priv->copyright;
}

/**
 * mcm_profile_set_copyright:
 **/
void
mcm_profile_set_copyright (McmProfile *profile, const gchar *copyright)
{
	McmProfilePrivate *priv = profile->priv;

	g_return_if_fail (MCM_IS_PROFILE (profile));

	g_free (priv->copyright);
	priv->copyright = g_strdup (copyright);
	if (priv->copyright != NULL)
		mcm_utils_ensure_printable (priv->copyright);
	g_object_notify (G_OBJECT (profile), "copyright");
}

/**
 * mcm_profile_get_model:
 **/
const gchar *
mcm_profile_get_model (McmProfile *profile)
{
	g_return_val_if_fail (MCM_IS_PROFILE (profile), NULL);
	return profile->priv->model;
}

/**
 * mcm_profile_set_model:
 **/
void
mcm_profile_set_model (McmProfile *profile, const gchar *model)
{
	McmProfilePrivate *priv = profile->priv;

	g_return_if_fail (MCM_IS_PROFILE (profile));

	g_free (priv->model);
	priv->model = g_strdup (model);
	if (priv->model != NULL)
		mcm_utils_ensure_printable (priv->model);
	g_object_notify (G_OBJECT (profile), "model");
}

/**
 * mcm_profile_get_manufacturer:
 **/
const gchar *
mcm_profile_get_manufacturer (McmProfile *profile)
{
	g_return_val_if_fail (MCM_IS_PROFILE (profile), NULL);
	return profile->priv->manufacturer;
}

/**
 * mcm_profile_set_manufacturer:
 **/
void
mcm_profile_set_manufacturer (McmProfile *profile, const gchar *manufacturer)
{
	McmProfilePrivate *priv = profile->priv;

	g_return_if_fail (MCM_IS_PROFILE (profile));

	g_free (priv->manufacturer);
	priv->manufacturer = g_strdup (manufacturer);
	if (priv->manufacturer != NULL)
		mcm_utils_ensure_printable (priv->manufacturer);
	g_object_notify (G_OBJECT (profile), "manufacturer");
}

/**
 * mcm_profile_get_datetime:
 **/
const gchar *
mcm_profile_get_datetime (McmProfile *profile)
{
	g_return_val_if_fail (MCM_IS_PROFILE (profile), NULL);
	return profile->priv->datetime;
}

/**
 * mcm_profile_set_datetime:
 **/
void
mcm_profile_set_datetime (McmProfile *profile, const gchar *datetime)
{
	McmProfilePrivate *priv = profile->priv;

	g_return_if_fail (MCM_IS_PROFILE (profile));

	g_free (priv->datetime);
	priv->datetime = g_strdup (datetime);
	g_object_notify (G_OBJECT (profile), "datetime");
}

/**
 * mcm_profile_get_checksum:
 **/
const gchar *
mcm_profile_get_checksum (McmProfile *profile)
{
	g_return_val_if_fail (MCM_IS_PROFILE (profile), NULL);
	return profile->priv->checksum;
}

/**
 * mcm_profile_set_checksum:
 **/
static void
mcm_profile_set_checksum (McmProfile *profile, const gchar *checksum)
{
	McmProfilePrivate *priv = profile->priv;

	g_return_if_fail (MCM_IS_PROFILE (profile));

	g_free (priv->checksum);
	priv->checksum = g_strdup (checksum);
	g_object_notify (G_OBJECT (profile), "checksum");
}

/**
 * mcm_profile_get_size:
 **/
guint
mcm_profile_get_size (McmProfile *profile)
{
	g_return_val_if_fail (MCM_IS_PROFILE (profile), 0);
	return profile->priv->size;
}

/**
 * mcm_profile_set_size:
 **/
void
mcm_profile_set_size (McmProfile *profile, guint size)
{
	g_return_if_fail (MCM_IS_PROFILE (profile));
	profile->priv->size = size;
	g_object_notify (G_OBJECT (profile), "size");
}

/**
 * mcm_profile_get_kind:
 **/
McmProfileKind
mcm_profile_get_kind (McmProfile *profile)
{
	g_return_val_if_fail (MCM_IS_PROFILE (profile), MCM_PROFILE_KIND_UNKNOWN);
	return profile->priv->kind;
}

/**
 * mcm_profile_set_kind:
 **/
void
mcm_profile_set_kind (McmProfile *profile, McmProfileKind kind)
{
	g_return_if_fail (MCM_IS_PROFILE (profile));
	profile->priv->kind = kind;
	g_object_notify (G_OBJECT (profile), "kind");
}

/**
 * mcm_profile_get_colorspace:
 **/
McmColorspace
mcm_profile_get_colorspace (McmProfile *profile)
{
	g_return_val_if_fail (MCM_IS_PROFILE (profile), MCM_COLORSPACE_UNKNOWN);
	return profile->priv->colorspace;
}

/**
 * mcm_profile_set_colorspace:
 **/
void
mcm_profile_set_colorspace (McmProfile *profile, McmColorspace colorspace)
{
	g_return_if_fail (MCM_IS_PROFILE (profile));
	profile->priv->colorspace = colorspace;
	g_object_notify (G_OBJECT (profile), "colorspace");
}

/**
 * mcm_profile_get_has_vcgt:
 **/
gboolean
mcm_profile_get_has_vcgt (McmProfile *profile)
{
	g_return_val_if_fail (MCM_IS_PROFILE (profile), FALSE);
	return profile->priv->has_vcgt;
}

/**
 * mcm_profile_set_has_vcgt:
 **/
void
mcm_profile_set_has_vcgt (McmProfile *profile, gboolean has_vcgt)
{
	g_return_if_fail (MCM_IS_PROFILE (profile));
	profile->priv->has_vcgt = has_vcgt;
	g_object_notify (G_OBJECT (profile), "has_vcgt");
}

/**
 * mcm_profile_get_can_delete:
 **/
gboolean
mcm_profile_get_can_delete (McmProfile *profile)
{
	g_return_val_if_fail (MCM_IS_PROFILE (profile), FALSE);
	return profile->priv->can_delete;
}

/**
 * mcm_profile_parse_data:
 **/
gboolean
mcm_profile_parse_data (McmProfile *profile, const guint8 *data, gsize length, GError **error)
{
	gboolean ret = FALSE;
	gchar *checksum = NULL;
	guint num_tags;
	guint i;
	guint tag_id;
	guint offset;
	guint tag_size;
	guint tag_offset;
	icProfileClassSignature profile_class;
	icColorSpaceSignature color_space;
	McmColorspace colorspace;
	McmProfileKind profile_kind;
	cmsCIEXYZ cie_xyz;
	cmsCIEXYZTRIPLE cie_illum;
	struct tm created;
	cmsHPROFILE xyz_profile;
	cmsHTRANSFORM transform;
	gchar *text;
	McmXyz *xyz;
	McmProfilePrivate *priv = profile->priv;

	g_return_val_if_fail (MCM_IS_PROFILE (profile), FALSE);
	g_return_val_if_fail (data != NULL, FALSE);
	g_return_val_if_fail (priv->loaded == FALSE, FALSE);

	/* save the length */
	priv->size = length;
	priv->loaded = TRUE;

	/* load profile into lcms */
	priv->lcms_profile = cmsOpenProfileFromMem ((LPVOID)data, length);
	if (priv->lcms_profile == NULL) {
		g_set_error_literal (error, 1, 0, "failed to load: not an ICC profile");
		goto out;
	}

	/* get white point */
	ret = cmsTakeMediaWhitePoint (&cie_xyz, priv->lcms_profile);
	if (ret) {
		xyz = mcm_xyz_new ();
		g_object_set (xyz,
			      "cie-x", cie_xyz.X,
			      "cie-y", cie_xyz.Y,
			      "cie-z", cie_xyz.Z,
			      NULL);
		g_object_set (profile,
			      "white", xyz,
			      NULL);
		g_object_unref (xyz);
	} else {
		egg_warning ("failed to get white point");
	}

	/* get black point */
	ret = cmsTakeMediaBlackPoint (&cie_xyz, priv->lcms_profile);
	if (ret) {
		xyz = mcm_xyz_new ();
		g_object_set (xyz,
			      "cie-x", cie_xyz.X,
			      "cie-y", cie_xyz.Y,
			      "cie-z", cie_xyz.Z,
			      NULL);
		g_object_set (profile,
			      "black", xyz,
			      NULL);
		g_object_unref (xyz);
	} else {
		egg_warning ("failed to get black point");
	}

	/* get the profile kind */
	profile_class = cmsGetDeviceClass (priv->lcms_profile);
	switch (profile_class) {
	case icSigInputClass:
		profile_kind = MCM_PROFILE_KIND_INPUT_DEVICE;
		break;
	case icSigDisplayClass:
		profile_kind = MCM_PROFILE_KIND_DISPLAY_DEVICE;
		break;
	case icSigOutputClass:
		profile_kind = MCM_PROFILE_KIND_OUTPUT_DEVICE;
		break;
	case icSigLinkClass:
		profile_kind = MCM_PROFILE_KIND_DEVICELINK;
		break;
	case icSigColorSpaceClass:
		profile_kind = MCM_PROFILE_KIND_COLORSPACE_CONVERSION;
		break;
	case icSigAbstractClass:
		profile_kind = MCM_PROFILE_KIND_ABSTRACT;
		break;
	case icSigNamedColorClass:
		profile_kind = MCM_PROFILE_KIND_NAMED_COLOR;
		break;
	default:
		profile_kind = MCM_PROFILE_KIND_UNKNOWN;
	}
	mcm_profile_set_kind (profile, profile_kind);

	/* get colorspace */
	color_space = cmsGetColorSpace (priv->lcms_profile);
	switch (color_space) {
	case icSigXYZData:
		colorspace = MCM_COLORSPACE_XYZ;
		break;
	case icSigLabData:
		colorspace = MCM_COLORSPACE_LAB;
		break;
	case icSigLuvData:
		colorspace = MCM_COLORSPACE_LUV;
		break;
	case icSigYCbCrData:
		colorspace = MCM_COLORSPACE_YCBCR;
		break;
	case icSigYxyData:
		colorspace = MCM_COLORSPACE_YXY;
		break;
	case icSigRgbData:
		colorspace = MCM_COLORSPACE_RGB;
		break;
	case icSigGrayData:
		colorspace = MCM_COLORSPACE_GRAY;
		break;
	case icSigHsvData:
		colorspace = MCM_COLORSPACE_HSV;
		break;
	case icSigCmykData:
		colorspace = MCM_COLORSPACE_CMYK;
		break;
	case icSigCmyData:
		colorspace = MCM_COLORSPACE_CMY;
		break;
	default:
		colorspace = MCM_COLORSPACE_UNKNOWN;
	}
	mcm_profile_set_colorspace (profile, colorspace);

	/* get primary illuminants */
	ret = cmsTakeColorants (&cie_illum, priv->lcms_profile);

	/* geting the illuminants failed, try running it through the profile */
	if (!ret && color_space == icSigRgbData) {
		gdouble rgb_values[3];

		/* create a transform from profile to XYZ */
		xyz_profile = cmsCreateXYZProfile ();
		transform = cmsCreateTransform (priv->lcms_profile, TYPE_RGB_DBL, xyz_profile, TYPE_XYZ_DBL, INTENT_PERCEPTUAL, 0);
		if (transform != NULL) {

			/* red */
			rgb_values[0] = 1.0;
			rgb_values[1] = 0.0;
			rgb_values[2] = 0.0;
			cmsDoTransform (transform, rgb_values, &cie_illum.Red, 1);

			/* green */
			rgb_values[0] = 0.0;
			rgb_values[1] = 1.0;
			rgb_values[2] = 0.0;
			cmsDoTransform (transform, rgb_values, &cie_illum.Green, 1);

			/* blue */
			rgb_values[0] = 0.0;
			rgb_values[1] = 0.0;
			rgb_values[2] = 1.0;
			cmsDoTransform (transform, rgb_values, &cie_illum.Blue, 1);

			/* we're done */
			cmsDeleteTransform (transform);
			ret = TRUE;
		}

		/* no more need for the output profile */
		cmsCloseProfile (xyz_profile);
	}

	/* we've got valid values */
	if (ret) {
		/* red */
		xyz = mcm_xyz_new ();
		g_object_set (xyz,
			      "cie-x", cie_illum.Red.X,
			      "cie-y", cie_illum.Red.Y,
			      "cie-z", cie_illum.Red.Z,
			      NULL);
		g_object_set (profile,
			      "red", xyz,
			      NULL);
		g_object_unref (xyz);

		/* green */
		xyz = mcm_xyz_new ();
		g_object_set (xyz,
			      "cie-x", cie_illum.Green.X,
			      "cie-y", cie_illum.Green.Y,
			      "cie-z", cie_illum.Green.Z,
			      NULL);
		g_object_set (profile,
			      "green", xyz,
			      NULL);
		g_object_unref (xyz);

		/* blue */
		xyz = mcm_xyz_new ();
		g_object_set (xyz,
			      "cie-x", cie_illum.Blue.X,
			      "cie-y", cie_illum.Blue.Y,
			      "cie-z", cie_illum.Blue.Z,
			      NULL);
		g_object_set (profile,
			      "blue", xyz,
			      NULL);
		g_object_unref (xyz);
	} else {
		egg_debug ("failed to get luminance values");
	}

	/* get the profile created time and date */
	ret = cmsTakeCreationDateTime (&created, priv->lcms_profile);
	if (ret) {
		text = mcm_utils_format_date_time (&created);
		mcm_profile_set_datetime (profile, text);
		g_free (text);
	}

	/* get the number of tags in the file */
	num_tags = mcm_parser_decode_32 (data + MCM_NUMTAGS);
	for (i=0; i<num_tags; i++) {
		offset = MCM_TAG_WIDTH * i;
		tag_id = mcm_parser_decode_32 (data + MCM_BODY + offset + MCM_TAG_ID);
		tag_offset = mcm_parser_decode_32 (data + MCM_BODY + offset + MCM_TAG_OFFSET);
		tag_size = mcm_parser_decode_32 (data + MCM_BODY + offset + MCM_TAG_SIZE);

		/* print tag */
//		egg_debug ("tag %x is present at 0x%x with size %u", tag_id, tag_offset, tag_size);

		if (tag_id == icSigProfileDescriptionTag) {
			text = mcm_profile_parse_multi_localized_unicode (profile, data + tag_offset, tag_size);
			mcm_profile_set_description (profile, text);
			g_free (text);
		}
		if (tag_id == icSigCopyrightTag) {
			text = mcm_profile_parse_multi_localized_unicode (profile, data + tag_offset, tag_size);
			mcm_profile_set_copyright (profile, text);
			g_free (text);
		}
		if (tag_id == icSigDeviceMfgDescTag) {
			text = mcm_profile_parse_multi_localized_unicode (profile, data + tag_offset, tag_size);
			mcm_profile_set_manufacturer (profile, text);
			g_free (text);
		}
		if (tag_id == icSigDeviceModelDescTag) {
			text = mcm_profile_parse_multi_localized_unicode (profile, data + tag_offset, tag_size);
			mcm_profile_set_model (profile, text);
			g_free (text);
		}
		if (tag_id == icSigMachineLookUpTableTag) {
			ret = mcm_parser_load_icc_mlut (profile, data + tag_offset, tag_size);
			if (!ret) {
				g_set_error_literal (error, 1, 0, "failed to load mlut");
				goto out;
			}
		}
		if (tag_id == icSigVideoCartGammaTableTag) {
			if (tag_size == 1584)
				priv->adobe_gamma_workaround = TRUE;
			ret = mcm_parser_load_icc_vcgt (profile, data + tag_offset, tag_size);
			if (!ret) {
				g_set_error_literal (error, 1, 0, "failed to load vcgt");
				goto out;
			}
		}
	}

	/* success */
	ret = TRUE;

	/* set properties */
	mcm_profile_set_has_vcgt (profile, priv->has_vcgt_formula || priv->has_vcgt_table);

	/* generate and set checksum */
	checksum = g_compute_checksum_for_data (G_CHECKSUM_MD5, (const guchar *) data, length);
	mcm_profile_set_checksum (profile, checksum);
out:
	g_free (checksum);
	return ret;
}

/**
 * mcm_profile_parse:
 **/
gboolean
mcm_profile_parse (McmProfile *profile, GFile *file, GError **error)
{
	gchar *data = NULL;
	gboolean ret = FALSE;
	gsize length;
	gchar *filename = NULL;
	GError *error_local = NULL;
	GFileInfo *info;

	g_return_val_if_fail (MCM_IS_PROFILE (profile), FALSE);
	g_return_val_if_fail (file != NULL, FALSE);

	/* find out if the user could delete this profile */
	info = g_file_query_info (file, G_FILE_ATTRIBUTE_ACCESS_CAN_DELETE,
				  G_FILE_QUERY_INFO_NONE, NULL, error);
	if (info == NULL)
		goto out;
	profile->priv->can_delete = g_file_info_get_attribute_boolean (info, G_FILE_ATTRIBUTE_ACCESS_CAN_DELETE);

	/* load files */
	ret = g_file_load_contents (file, NULL, &data, &length, NULL, &error_local);
	if (!ret) {
		g_set_error (error, 1, 0, "failed to load profile: %s", error_local->message);
		g_error_free (error_local);
		goto out;
	}

	/* parse the data */
	ret = mcm_profile_parse_data (profile, (const guint8*)data, length, error);
	if (!ret)
		goto out;

	/* save */
	filename = g_file_get_path (file);
	mcm_profile_set_filename (profile, filename);
out:
	if (info != NULL)
		g_object_unref (info);
	g_free (filename);
	g_free (data);
	return ret;
}

/**
 * mcm_profile_save:
 **/
gboolean
mcm_profile_save (McmProfile *profile, const gchar *filename, GError **error)
{
	gboolean ret = FALSE;
	McmProfilePrivate *priv = profile->priv;

	/* not loaded */
	if (priv->size == 0) {
		g_set_error_literal (error, 1, 0, "not loaded");
		goto out;
	}

	/* save, TODO: get error */
	_cmsSaveProfile (priv->lcms_profile, filename);
	ret = TRUE;
out:
	return ret;
}

/**
 * mcm_profile_generate_vcgt:
 *
 * Free with g_object_unref();
 **/
McmClut *
mcm_profile_generate_vcgt (McmProfile *profile, guint size)
{
	/* proxy */
	guint i;
	guint ratio;
	McmClutData *tmp;
	McmClutData *vcgt_data;
	McmClutData *mlut_data;
	gfloat gamma_red, min_red, max_red;
	gfloat gamma_green, min_green, max_green;
	gfloat gamma_blue, min_blue, max_blue;
	guint num_entries;
	McmClut *clut = NULL;
	GPtrArray *array = NULL;
	gfloat inverse_ratio;
	guint idx;
	gfloat frac;

	g_return_val_if_fail (MCM_IS_PROFILE (profile), NULL);
	g_return_val_if_fail (size != 0, FALSE);

	/* reduce dereferences */
	vcgt_data = profile->priv->vcgt_data;
	mlut_data = profile->priv->mlut_data;

	if (profile->priv->has_vcgt_table) {

		/* create array */
		array = g_ptr_array_new_with_free_func (g_free);

		/* simply subsample if the LUT is smaller than the number of entries in the file */
		num_entries = profile->priv->vcgt_data_size;
		if (num_entries >= size) {
			ratio = (guint) (num_entries / size);
			for (i=0; i<size; i++) {
				/* add a point */
				tmp = g_new0 (McmClutData, 1);
				tmp->red = vcgt_data[ratio*i].red;
				tmp->green = vcgt_data[ratio*i].green;
				tmp->blue = vcgt_data[ratio*i].blue;
				g_ptr_array_add (array, tmp);
			}
			goto out;
		}

		/* LUT is bigger than number of entries, so interpolate */
		inverse_ratio = (gfloat) num_entries / size;
		vcgt_data[num_entries].red = 0xffff;
		vcgt_data[num_entries].green = 0xffff;
		vcgt_data[num_entries].blue = 0xffff;

		/* interpolate */
		for (i=0; i<size; i++) {
			idx = floor(i*inverse_ratio);
			frac = (i*inverse_ratio) - idx;
			tmp = g_new0 (McmClutData, 1);
			tmp->red = vcgt_data[idx].red * (1.0f-frac) + vcgt_data[idx + 1].red * frac;
			tmp->green = vcgt_data[idx].green * (1.0f-frac) + vcgt_data[idx + 1].green * frac;
			tmp->blue = vcgt_data[idx].blue * (1.0f-frac) + vcgt_data[idx + 1].blue * frac;
			g_ptr_array_add (array, tmp);
		}
		goto out;
	}

	if (profile->priv->has_vcgt_formula) {

		/* create array */
		array = g_ptr_array_new_with_free_func (g_free);

		gamma_red = (gfloat) vcgt_data[0].red / 65536.0;
		gamma_green = (gfloat) vcgt_data[0].green / 65536.0;
		gamma_blue = (gfloat) vcgt_data[0].blue / 65536.0;
		min_red = (gfloat) vcgt_data[1].red / 65536.0;
		min_green = (gfloat) vcgt_data[1].green / 65536.0;
		min_blue = (gfloat) vcgt_data[1].blue / 65536.0;
		max_red = (gfloat) vcgt_data[2].red / 65536.0;
		max_green = (gfloat) vcgt_data[2].green / 65536.0;
		max_blue = (gfloat) vcgt_data[2].blue / 65536.0;

		/* create mapping of desired size */
		for (i=0; i<size; i++) {
			/* add a point */
			tmp = g_new0 (McmClutData, 1);
			tmp->red = 65536.0 * ((gdouble) pow ((gdouble) i / (gdouble) size, gamma_red) * (max_red - min_red) + min_red);
			tmp->green = 65536.0 * ((gdouble) pow ((gdouble) i / (gdouble) size, gamma_green) * (max_green - min_green) + min_green);
			tmp->blue = 65536.0 * ((gdouble) pow ((gdouble) i / (gdouble) size, gamma_blue) * (max_blue - min_blue) + min_blue);
			g_ptr_array_add (array, tmp);
		}
		goto out;
	}

	if (profile->priv->has_mlut) {

		/* create array */
		array = g_ptr_array_new_with_free_func (g_free);

		/* roughly interpolate table */
		ratio = (guint) (256 / (size));
		for (i=0; i<size; i++) {
			/* add a point */
			tmp = g_new0 (McmClutData, 1);
			tmp->red = mlut_data[ratio*i].red;
			tmp->green = mlut_data[ratio*i].green;
			tmp->blue = mlut_data[ratio*i].blue;
			g_ptr_array_add (array, tmp);
		}
		goto out;
	}

	/* bugger */
	egg_debug ("no LUT to generate");
out:
	if (array != NULL) {
		/* create new output array */
		clut = mcm_clut_new ();
		mcm_clut_set_source_array (clut, array);
		g_ptr_array_unref (array);
	}
	return clut;
}

/**
 * mcm_profile_generate_curve:
 *
 * Free with g_object_unref();
 **/
McmClut *
mcm_profile_generate_curve (McmProfile *profile, guint size)
{
	McmClut *clut = NULL;
	gdouble *values_in = NULL;
	gdouble *values_out = NULL;
	guint i;
	McmClutData *data;
	GPtrArray *array = NULL;
	gfloat divamount;
	gfloat divadd;
	guint component_width;
	cmsHPROFILE srgb_profile = NULL;
	cmsHTRANSFORM transform = NULL;
	guint type;
	McmColorspace colorspace;
	McmProfilePrivate *priv = profile->priv;

	/* run through the profile */
	colorspace = mcm_profile_get_colorspace (profile);
	if (colorspace == MCM_COLORSPACE_RGB) {

		/* RGB */
		component_width = 3;
		type = TYPE_RGB_DBL;

		/* create input array */
		values_in = g_new0 (gdouble, size * 3 * component_width);
		divamount = 1.0f / (gfloat) (size - 1);
		for (i=0; i<size; i++) {
			divadd = divamount * (gfloat) i;

			/* red component */
			values_in[(i * 3 * component_width)+0] = divadd;
			values_in[(i * 3 * component_width)+1] = 0.0f;
			values_in[(i * 3 * component_width)+2] = 0.0f;

			/* green component */
			values_in[(i * 3 * component_width)+3] = 0.0f;
			values_in[(i * 3 * component_width)+4] = divadd;
			values_in[(i * 3 * component_width)+5] = 0.0f;

			/* blue component */
			values_in[(i * 3 * component_width)+6] = 0.0f;
			values_in[(i * 3 * component_width)+7] = 0.0f;
			values_in[(i * 3 * component_width)+8] = divadd;
		}
	}

	/* do each transform */
	if (values_in != NULL) {
		/* create output array */
		values_out = g_new0 (gdouble, size * 3 * component_width);

		/* create a transform from profile to sRGB */
		srgb_profile = cmsCreate_sRGBProfile ();
		transform = cmsCreateTransform (priv->lcms_profile, type, srgb_profile, TYPE_RGB_DBL, INTENT_PERCEPTUAL, 0);
		if (transform == NULL)
			goto out;

		/* do transform */
		cmsDoTransform (transform, values_in, values_out, size * 3);

		/* create output array */
		array = g_ptr_array_new_with_free_func (g_free);

		for (i=0; i<size; i++) {
			data = g_new0 (McmClutData, 1);

			data->red = values_out[(i * 3 * component_width)+0] * (gfloat) 0xffff;
			data->green = values_out[(i * 3 * component_width)+4] * (gfloat) 0xffff;
			data->blue = values_out[(i * 3 * component_width)+8] * (gfloat) 0xffff;
			g_ptr_array_add (array, data);
		}
		clut = mcm_clut_new ();
		mcm_clut_set_source_array (clut, array);
	}

out:
	g_free (values_in);
	g_free (values_out);
	if (array != NULL)
		g_ptr_array_unref (array);
	if (transform != NULL)
		cmsDeleteTransform (transform);
	if (srgb_profile != NULL)
		cmsCloseProfile (srgb_profile);
	return clut;
}

/**
 * mcm_profile_file_monitor_changed_cb:
 **/
static void
mcm_profile_file_monitor_changed_cb (GFileMonitor *monitor, GFile *file, GFile *other_file, GFileMonitorEvent event_type, McmProfile *profile)
{
	McmProfilePrivate *priv = profile->priv;

	/* ony care about deleted events */
	if (event_type != G_FILE_MONITOR_EVENT_DELETED)
		goto out;

	/* just rescan everything */
	egg_debug ("%s deleted, clearing filename", priv->filename);
	mcm_profile_set_filename (profile, NULL);
out:
	return;
}

/**
 * mcm_profile_lcms_error_cb:
 **/
static int
mcm_profile_lcms_error_cb (int ErrorCode, const char *ErrorText)
{
	egg_warning ("LCMS error %i: %s", ErrorCode, ErrorText);
	return LCMS_ERRC_WARNING;
}

/**
 * mcm_profile_get_property:
 **/
static void
mcm_profile_get_property (GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
	McmProfile *profile = MCM_PROFILE (object);
	McmProfilePrivate *priv = profile->priv;

	switch (prop_id) {
	case PROP_COPYRIGHT:
		g_value_set_string (value, priv->copyright);
		break;
	case PROP_MANUFACTURER:
		g_value_set_string (value, priv->manufacturer);
		break;
	case PROP_MODEL:
		g_value_set_string (value, priv->model);
		break;
	case PROP_DATETIME:
		g_value_set_string (value, priv->datetime);
		break;
	case PROP_CHECKSUM:
		g_value_set_string (value, priv->checksum);
		break;
	case PROP_DESCRIPTION:
		g_value_set_string (value, priv->description);
		break;
	case PROP_FILENAME:
		g_value_set_string (value, priv->filename);
		break;
	case PROP_KIND:
		g_value_set_uint (value, priv->kind);
		break;
	case PROP_COLORSPACE:
		g_value_set_uint (value, priv->colorspace);
		break;
	case PROP_SIZE:
		g_value_set_uint (value, priv->size);
		break;
	case PROP_HAS_VCGT:
		g_value_set_boolean (value, priv->has_vcgt);
		break;
	case PROP_CAN_DELETE:
		g_value_set_boolean (value, priv->can_delete);
		break;
	case PROP_WHITE:
		g_value_set_object (value, priv->white);
		break;
	case PROP_BLACK:
		g_value_set_object (value, priv->black);
		break;
	case PROP_RED:
		g_value_set_object (value, priv->red);
		break;
	case PROP_GREEN:
		g_value_set_object (value, priv->green);
		break;
	case PROP_BLUE:
		g_value_set_object (value, priv->blue);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/**
 * mcm_profile_set_property:
 **/
static void
mcm_profile_set_property (GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec)
{
	McmProfile *profile = MCM_PROFILE (object);
	McmProfilePrivate *priv = profile->priv;

	switch (prop_id) {
	case PROP_COPYRIGHT:
		mcm_profile_set_copyright (profile, g_value_get_string (value));
		break;
	case PROP_MANUFACTURER:
		mcm_profile_set_manufacturer (profile, g_value_get_string (value));
		break;
	case PROP_MODEL:
		mcm_profile_set_model (profile, g_value_get_string (value));
		break;
	case PROP_DATETIME:
		mcm_profile_set_datetime (profile, g_value_get_string (value));
		break;
	case PROP_DESCRIPTION:
		mcm_profile_set_description (profile, g_value_get_string (value));
		break;
	case PROP_FILENAME:
		mcm_profile_set_filename (profile, g_value_get_string (value));
		break;
	case PROP_KIND:
		mcm_profile_set_kind (profile, g_value_get_uint (value));
		break;
	case PROP_COLORSPACE:
		mcm_profile_set_colorspace (profile, g_value_get_uint (value));
		break;
	case PROP_SIZE:
		mcm_profile_set_size (profile, g_value_get_uint (value));
		break;
	case PROP_HAS_VCGT:
		mcm_profile_set_has_vcgt (profile, g_value_get_boolean (value));
		break;
	case PROP_WHITE:
		priv->white = g_value_dup_object (value);
		break;
	case PROP_BLACK:
		priv->black = g_value_dup_object (value);
		break;
	case PROP_RED:
		priv->red = g_value_dup_object (value);
		break;
	case PROP_GREEN:
		priv->green = g_value_dup_object (value);
		break;
	case PROP_BLUE:
		priv->blue = g_value_dup_object (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/**
 * mcm_profile_class_init:
 **/
static void
mcm_profile_class_init (McmProfileClass *klass)
{
	GParamSpec *pspec;
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	object_class->finalize = mcm_profile_finalize;
	object_class->get_property = mcm_profile_get_property;
	object_class->set_property = mcm_profile_set_property;

	/**
	 * McmProfile:copyright:
	 */
	pspec = g_param_spec_string ("copyright", NULL, NULL,
				     NULL,
				     G_PARAM_READWRITE);
	g_object_class_install_property (object_class, PROP_COPYRIGHT, pspec);

	/**
	 * McmProfile:manufacturer:
	 */
	pspec = g_param_spec_string ("manufacturer", NULL, NULL,
				     NULL,
				     G_PARAM_READWRITE);
	g_object_class_install_property (object_class, PROP_MANUFACTURER, pspec);

	/**
	 * McmProfile:model:
	 */
	pspec = g_param_spec_string ("model", NULL, NULL,
				     NULL,
				     G_PARAM_READWRITE);
	g_object_class_install_property (object_class, PROP_MODEL, pspec);

	/**
	 * McmProfile:datetime:
	 */
	pspec = g_param_spec_string ("datetime", NULL, NULL,
				     NULL,
				     G_PARAM_READWRITE);
	g_object_class_install_property (object_class, PROP_DATETIME, pspec);

	/**
	 * McmProfile:checksum:
	 */
	pspec = g_param_spec_string ("checksum", NULL, NULL,
				     NULL,
				     G_PARAM_READABLE);
	g_object_class_install_property (object_class, PROP_CHECKSUM, pspec);

	/**
	 * McmProfile:description:
	 */
	pspec = g_param_spec_string ("description", NULL, NULL,
				     NULL,
				     G_PARAM_READWRITE);
	g_object_class_install_property (object_class, PROP_DESCRIPTION, pspec);

	/**
	 * McmProfile:filename:
	 */
	pspec = g_param_spec_string ("filename", NULL, NULL,
				     NULL,
				     G_PARAM_READWRITE);
	g_object_class_install_property (object_class, PROP_FILENAME, pspec);

	/**
	 * McmProfile:kind:
	 */
	pspec = g_param_spec_uint ("kind", NULL, NULL,
				   0, G_MAXUINT, 0,
				   G_PARAM_READWRITE);
	g_object_class_install_property (object_class, PROP_KIND, pspec);

	/**
	 * McmProfile:colorspace:
	 */
	pspec = g_param_spec_uint ("colorspace", NULL, NULL,
				   0, G_MAXUINT, 0,
				   G_PARAM_READWRITE);
	g_object_class_install_property (object_class, PROP_COLORSPACE, pspec);

	/**
	 * McmProfile:size:
	 */
	pspec = g_param_spec_uint ("size", NULL, NULL,
				   0, G_MAXUINT, 0,
				   G_PARAM_READWRITE);
	g_object_class_install_property (object_class, PROP_SIZE, pspec);

	/**
	 * McmProfile:has-vcgt:
	 */
	pspec = g_param_spec_boolean ("has-vcgt", NULL, NULL,
				      FALSE,
				      G_PARAM_READWRITE);
	g_object_class_install_property (object_class, PROP_HAS_VCGT, pspec);

	/**
	 * McmProfile:can-delete:
	 */
	pspec = g_param_spec_boolean ("can-delete", NULL, NULL,
				      FALSE,
				      G_PARAM_READABLE);
	g_object_class_install_property (object_class, PROP_CAN_DELETE, pspec);

	/**
	 * McmProfile:white:
	 */
	pspec = g_param_spec_object ("white", NULL, NULL,
				     MCM_TYPE_XYZ,
				     G_PARAM_READWRITE);
	g_object_class_install_property (object_class, PROP_WHITE, pspec);

	/**
	 * McmProfile:black:
	 */
	pspec = g_param_spec_object ("black", NULL, NULL,
				     MCM_TYPE_XYZ,
				     G_PARAM_READWRITE);
	g_object_class_install_property (object_class, PROP_BLACK, pspec);

	/**
	 * McmProfile:red:
	 */
	pspec = g_param_spec_object ("red", NULL, NULL,
				     MCM_TYPE_XYZ,
				     G_PARAM_READWRITE);
	g_object_class_install_property (object_class, PROP_RED, pspec);

	/**
	 * McmProfile:green:
	 */
	pspec = g_param_spec_object ("green", NULL, NULL,
				     MCM_TYPE_XYZ,
				     G_PARAM_READWRITE);
	g_object_class_install_property (object_class, PROP_GREEN, pspec);

	/**
	 * McmProfile:blue:
	 */
	pspec = g_param_spec_object ("blue", NULL, NULL,
				     MCM_TYPE_XYZ,
				     G_PARAM_READWRITE);
	g_object_class_install_property (object_class, PROP_BLUE, pspec);

	g_type_class_add_private (klass, sizeof (McmProfilePrivate));
}

/**
 * mcm_profile_init:
 **/
static void
mcm_profile_init (McmProfile *profile)
{
	profile->priv = MCM_PROFILE_GET_PRIVATE (profile);
	profile->priv->vcgt_data = NULL;
	profile->priv->mlut_data = NULL;
	profile->priv->adobe_gamma_workaround = FALSE;
	profile->priv->can_delete = FALSE;
	profile->priv->monitor = NULL;
	profile->priv->kind = MCM_PROFILE_KIND_UNKNOWN;
	profile->priv->colorspace = MCM_COLORSPACE_UNKNOWN;
	profile->priv->white = mcm_xyz_new ();
	profile->priv->black = mcm_xyz_new ();
	profile->priv->red = mcm_xyz_new ();
	profile->priv->green = mcm_xyz_new ();
	profile->priv->blue = mcm_xyz_new ();

	/* setup LCMS */
	cmsSetErrorHandler (mcm_profile_lcms_error_cb);
	cmsErrorAction (LCMS_ERROR_SHOW);
	cmsSetLanguage ("en", "US");
}

/**
 * mcm_profile_finalize:
 **/
static void
mcm_profile_finalize (GObject *object)
{
	McmProfile *profile = MCM_PROFILE (object);
	McmProfilePrivate *priv = profile->priv;

	g_free (priv->copyright);
	g_free (priv->description);
	g_free (priv->filename);
	g_free (priv->manufacturer);
	g_free (priv->model);
	g_free (priv->datetime);
	g_free (priv->checksum);
	g_free (priv->vcgt_data);
	g_free (priv->mlut_data);
	g_object_unref (priv->white);
	g_object_unref (priv->black);
	g_object_unref (priv->red);
	g_object_unref (priv->green);
	g_object_unref (priv->blue);
	if (priv->monitor != NULL)
		g_object_unref (priv->monitor);

	if (priv->lcms_profile != NULL)
		cmsCloseProfile (priv->lcms_profile);

	G_OBJECT_CLASS (mcm_profile_parent_class)->finalize (object);
}

/**
 * mcm_profile_new:
 *
 * Return value: a new McmProfile object.
 **/
McmProfile *
mcm_profile_new (void)
{
	McmProfile *profile;
	profile = g_object_new (MCM_TYPE_PROFILE, NULL);
	return MCM_PROFILE (profile);
}

