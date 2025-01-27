/*
 * Copyright (C) 2019 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include "config.h"

#include <fwupdplugin.h>

#include "fu-jabra-device.h"

void
fu_plugin_init (FuPlugin *plugin)
{
	FuContext *ctx = fu_plugin_get_context (plugin);
	fu_plugin_set_build_hash (plugin, FU_BUILD_HASH);
	fu_plugin_add_device_gtype (plugin, FU_TYPE_JABRA_DEVICE);
	fu_context_add_quirk_key (ctx, "JabraMagic");
}

/* slightly weirdly, this takes us from appIDLE back into the actual
 * runtime mode where the device actually works */
gboolean
fu_plugin_cleanup(FuPlugin *plugin, FwupdInstallFlags flags, FuDevice *device, GError **error)
{
	GUsbDevice *usb_device;
	g_autoptr(FuDeviceLocker) locker = NULL;
	g_autoptr(GError) error_local = NULL;

	/* check for a property on the *dfu* FuDevice, which is also why we
	 * can't just rely on using FuDevice->cleanup() */
	if (!fu_device_has_internal_flag (device, FU_DEVICE_INTERNAL_FLAG_ATTACH_EXTRA_RESET))
		return TRUE;
	locker = fu_device_locker_new (device, error);
	if (locker == NULL)
		return FALSE;
	fu_device_set_status (device, FWUPD_STATUS_DEVICE_RESTART);
	usb_device = fu_usb_device_get_dev (FU_USB_DEVICE (device));
	if (!g_usb_device_reset (usb_device, &error_local)) {
		g_set_error (error,
			     FWUPD_ERROR,
			     FWUPD_ERROR_NOT_SUPPORTED,
			     "cannot reset USB device: %s [%i]",
			     error_local->message,
			     error_local->code);
		return FALSE;
	}

	/* wait for device to re-appear */
	fu_device_add_flag (device, FWUPD_DEVICE_FLAG_WAIT_FOR_REPLUG);
	return TRUE;
}
