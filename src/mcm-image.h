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

#ifndef __MCM_IMAGE_H
#define __MCM_IMAGE_H

#include <glib-object.h>
#include <gtk/gtk.h>

G_BEGIN_DECLS

#define MCM_TYPE_IMAGE		(mcm_image_get_type ())
#define MCM_IMAGE(o)		(G_TYPE_CHECK_INSTANCE_CAST ((o), MCM_TYPE_IMAGE, McmImage))
#define MCM_IMAGE_CLASS(k)	(G_TYPE_CHECK_CLASS_CAST((k), MCM_TYPE_IMAGE, McmImageClass))
#define MCM_IS_IMAGE(o)		(G_TYPE_CHECK_INSTANCE_TYPE ((o), MCM_TYPE_IMAGE))
#define MCM_IS_IMAGE_CLASS(k)	(G_TYPE_CHECK_CLASS_TYPE ((k), MCM_TYPE_IMAGE))
#define MCM_IMAGE_GET_CLASS(o)	(G_TYPE_INSTANCE_GET_CLASS ((o), MCM_TYPE_IMAGE, McmImageClass))

typedef struct _McmImagePrivate	McmImagePrivate;
typedef struct _McmImage	McmImage;
typedef struct _McmImageClass	McmImageClass;

struct _McmImage
{
	 GtkImage		 parent;
	 McmImagePrivate	*priv;
};

struct _McmImageClass
{
	GtkImageClass		parent_class;
	/* padding for future expansion */
	void (*_mcm_reserved1) (void);
	void (*_mcm_reserved2) (void);
	void (*_mcm_reserved3) (void);
	void (*_mcm_reserved4) (void);
	void (*_mcm_reserved5) (void);
};

GType		 mcm_image_get_type		(void);
McmImage	*mcm_image_new		 	(void);

G_END_DECLS

#endif /* __MCM_IMAGE_H */

