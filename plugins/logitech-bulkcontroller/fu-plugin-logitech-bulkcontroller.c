/*
 * Copyright (c) 1999-2021 Logitech, Inc.
 * All Rights Reserved
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include "config.h"

#include <fwupdplugin.h>

#include "bulk_controller.h"
#include "proto_manager.h"

/* Firmware upgrade time on UPD interface. 20 minutes, 1200 seconds */
#define TIMEOUT_UPD_1200SEC 1200
#define DEVICE_NAME_LENGTH  25
#define VERSION_LENGTH	    25
/* Wait period for response on SYNC interface 5 seconds */
#define TIMEOUT_SYNC_RESPONSE_5SEC 5

struct FuPluginData {
	DeviceType device_type;
	gchar *device_name;
	gboolean run_devicemode_info_;
	gboolean device_info_available;
	DeviceInfo device_info;
	GCond test_upd_cond;
	GMutex test_upd_mutex;
	FuDevice *device_obj;
	LogiBulkController *bulkcontroller_obj;
	gchar old_version[VERSION_LENGTH];
};

/* Helper functions */
gboolean
send_device_info_request(void *data);

/* Callback prototypes */
void
bulk_error_cb(gint error_code,
	      BulkInterface bulk_int,
	      const gchar *data,
	      guint32 size,
	      void *user_data);
void
read_sync_data_cb(const gchar *data, guint32 size, void *user_data);
void
read_upd_data_cb(const gchar *data, guint32 size, void *user_data);
void
send_data_sync_cb(gint error_code, gint status, gint id, void *user_data);
void
bulk_file_transfer_cb(FileTransferState state,
		      gint progress,
		      BulkInterface bulk_intf,
		      void *user_data);

void
bulk_error_cb(gint error_code,
	      BulkInterface bulk_int,
	      const gchar *data,
	      guint32 size,
	      void *user_data)
{
	FuPluginData *plugin_data = (FuPluginData *)user_data;
	if (ERRORCODE_NO_ERROR != error_code) {
		g_debug("%s with reason : %s %d", plugin_data->device_name, data, error_code);
	}
}

void
read_sync_data_cb(const gchar *data, guint32 size, void *user_data)
{
	DecodedData decoded_data;
	Proto_id proto_id = proto_manager_decode_message(data, size, &decoded_data);
	g_debug("Length of in coming data on sync interface %u", size);
	switch (proto_id) {
	case kProtoId_GetDeviceInfoResponse: {
		DeviceInfo device_info;
		FuPluginData *plugin_data = (FuPluginData *)user_data;
		if (!proto_manager_parse_device_info(decoded_data.device_info, &device_info)) {
			g_warning(
			    "[read_sync_data_cb] - Failed to parse incoming device info response");
			return;
		}
		if (plugin_data) {
			if (plugin_data->device_info_available == FALSE) {
				plugin_data->device_info_available = TRUE;
				g_debug(
				    "[read_sync_data_cb] - Received first device info response");
			}
			plugin_data->device_info = device_info;
		}
	} break;
	case kProtoId_KongEvent: {
		DeviceInfo device_info;
		FuPluginData *plugin_data = (FuPluginData *)user_data;
		if (!proto_manager_parse_device_info(decoded_data.device_info, &device_info)) {
			g_warning(
			    "[read_sync_data_cb] - Failed to parse incoming device info Event");
			return;
		}
		if (plugin_data) {
			if (plugin_data->device_info_available == FALSE) {
				plugin_data->device_info_available = TRUE;
				g_debug("[read_sync_data_cb] - Received first device info Event");
			}
			plugin_data->device_info = device_info;
		}
	} break;
	case kProtoId_TransitionToDeviceModeResponse: {
		/*  set a flag to indicate TransitionToDeviceModeResponse was received */
		FuPluginData *plugin_data = (FuPluginData *)user_data;
		if (plugin_data)
			plugin_data->run_devicemode_info_ = TRUE;
	} break;
	default:
		break;
	};
}

void
read_upd_data_cb(const gchar *data, guint32 size, void *user_data)
{
	g_debug("Not implemented yet");
}

void
send_data_sync_cb(gint error_code, gint status, gint id, void *user_data)
{
	FuPluginData *plugin_data = (FuPluginData *)user_data;
	(status == TRANSFER_SUCCESS)
	    ? g_debug("Send data sync success ID: %d ErrorCode: %d", id, error_code)
	    : g_warning("Send data sync failed ID: %d ErrorCode: %d", id, error_code);
	g_cond_signal(&plugin_data->test_upd_cond);
}

void
bulk_file_transfer_cb(FileTransferState state,
		      gint progress,
		      BulkInterface bulk_intf,
		      void *user_data)
{
	FuPluginData *plugin_data = (FuPluginData *)user_data;
	switch (state) {
	case TRANSFER_HASH_STARTED:
		g_debug("[%s] : File transfer hash in progress %u",
			plugin_data->device_name,
			bulk_intf);
		break;
	case TRANSFER_INIT_STARTED:
		g_debug("[%s] : File transfer init in progress %u",
			plugin_data->device_name,
			bulk_intf);
		break;
	case TRANSFER_STARTED:
		g_debug("[%s] : File transfer started for interface %u",
			plugin_data->device_name,
			bulk_intf);
		break;
	case TRANSFER_FAILED:
		g_warning("[%s] : File transfer failed for interface %u",
			  plugin_data->device_name,
			  bulk_intf);
		g_cond_signal(&plugin_data->test_upd_cond);
		break;
	case TRANSFER_INPROGRESS:
		if (BULK_INTERFACE_UPD == bulk_intf) {
			FuDevice *device;
			g_debug("\r[%s] : Interface: %u File uploaded : [%d%%]",
				plugin_data->device_name,
				bulk_intf,
				progress);
			fflush(stdout);
			device = plugin_data->device_obj;
			if (device)
				fu_device_set_progress(plugin_data->device_obj, progress);
		} else if (BULK_INTERFACE_SYNC == bulk_intf) {
			g_debug("\r[%s] : Interface: %u File received : [%d%%]",
				plugin_data->device_name,
				bulk_intf,
				progress);
			fflush(stdout);
		}
		break;
	case TRANSFER_COMPLETED:
		g_debug("[%s] :  File transfer completed for interface %u",
			plugin_data->device_name,
			bulk_intf);
		g_cond_signal(&plugin_data->test_upd_cond);
		break;
	default:
		break;
	}
}

gboolean
send_device_info_request(void *data)
{
	gint ret;
	Message message = {0};
	FuPluginData *plugin_data;
	plugin_data = (FuPluginData *)data;
	g_cond_init(&plugin_data->test_upd_cond);
	g_mutex_init(&plugin_data->test_upd_mutex);
	g_mutex_lock(&plugin_data->test_upd_mutex);

	ret = proto_manager_generate_get_device_info_request(&message);
	if (!ret && message.data) {
		ReturnValue *ret_val;
		g_debug("Sending GetDeviceInfoRequest. Length %lu", message.len);
		ret_val = logibulkcontroller_send_data_sync(plugin_data->bulkcontroller_obj,
							    message.data,
							    message.len);
		g_free(message.data);
		if ((ERRORCODE_NO_ERROR != ret_val->error_code) &&
		    (ERRORCODE_SEND_DATA_REQUEST_PUSHED_TO_QUEUE != ret_val->error_code)) {
			g_warning("Error in sending GetDeviceInfoRequest %u", ret_val->error_code);
			return FALSE;
		}
		if (g_cond_wait_until(&plugin_data->test_upd_cond,
				      &plugin_data->test_upd_mutex,
				      g_get_monotonic_time() + 5 * G_TIME_SPAN_SECOND)) {
			g_mutex_unlock(&plugin_data->test_upd_mutex);
			g_mutex_lock(&plugin_data->test_upd_mutex);
		}
	}
	return TRUE;
}

void
fu_plugin_init(FuPlugin *plugin)
{
	g_debug("Initializing Logitech bulk controller plugin");
	fu_plugin_set_build_hash(plugin, FU_BUILD_HASH);
	fu_plugin_alloc_data(plugin, sizeof(FuPluginData));
}

gboolean
fu_plugin_coldplug(FuPlugin *plugin, GError **error)
{
	LogiBulkController *obj;
	FuPluginData *plugin_data;
	gint pid;
	FuContext *ctx;
	BulkControllerCallbacks bulkcb = {bulk_error_cb,
					  bulk_file_transfer_cb,
					  read_upd_data_cb,
					  read_sync_data_cb,
					  send_data_sync_cb};

	plugin_data = fu_plugin_get_data(plugin);
	plugin_data->bulkcontroller_obj = NULL;
	/* Check if Logitech Rally Bar Mini is conneced */
	pid = 0x08D3;
	plugin_data->device_name = g_strdup("Rally Bar Mini");
	plugin_data->device_type = kDeviceTypeRallyBarMini;
	plugin_data->device_info_available = FALSE;
	plugin_data->run_devicemode_info_ = FALSE;
	obj = logibulkcontroller_create_bulk_controller(0x46d, pid, bulkcb, plugin_data);
	if (ERRORCODE_NO_ERROR == logibulkcontroller_open_device(obj)) {
		g_autoptr(FuDevice) device = NULL;
		plugin_data->bulkcontroller_obj = obj;
		if (!send_device_info_request(plugin_data)) {
			g_warning(" Failed to communicate with device %s",
				  plugin_data->device_name);
			logibulkcontroller_close_device(obj);
			return FALSE;
		}
		/* Wait for the response */
		sleep(TIMEOUT_SYNC_RESPONSE_5SEC);
		if (!plugin_data->device_info_available) {
			g_warning(" Failed to receive device information from device %s",
				  plugin_data->device_name);
			logibulkcontroller_close_device(obj);
			return FALSE;
		}
		ctx = fu_plugin_get_context(plugin);

		device = fu_device_new_with_context(ctx);
		fu_device_set_id(device, "logibulkctrl-video-conf-devices");
		fu_device_add_guid(device, "7da607b9-1f8f-597a-8f5e-5788d6f8bcb3");
		fu_device_set_name(device, plugin_data->device_info.name);
		fu_device_set_version_format(device, FWUPD_VERSION_FORMAT_TRIPLET);
		fu_device_set_vendor(device, "Logitech");
		fu_device_add_vendor_id(device, "USB:0x046D");
		fu_device_add_flag(device, FWUPD_DEVICE_FLAG_UPDATABLE);
		fu_device_add_protocol(device, "com.logitech.vc.proto");
		fu_device_set_version(device, plugin_data->device_info.sw);
		fu_plugin_device_add(plugin, device);
		return TRUE;
	}
	/* Check if Logitech Rally Bar is conneced */
	pid = 0x089B;
	plugin_data->device_name = g_strdup("Rally Bar");
	plugin_data->device_type = kDeviceTypeRallyBar;
	plugin_data->device_info_available = FALSE;
	plugin_data->run_devicemode_info_ = FALSE;
	obj = logibulkcontroller_create_bulk_controller(0x46d, pid, bulkcb, plugin_data);
	if (ERRORCODE_NO_ERROR == logibulkcontroller_open_device(obj)) {
		g_autoptr(FuDevice) device = NULL;
		plugin_data->bulkcontroller_obj = obj;
		if (!send_device_info_request(plugin_data)) {
			g_warning(" Failed to communicate with device %s",
				  plugin_data->device_name);
			logibulkcontroller_close_device(obj);
			return FALSE;
		}
		/* Wait for the response */
		sleep(TIMEOUT_SYNC_RESPONSE_5SEC);
		if (!plugin_data->device_info_available) {
			g_warning(" Failed to receive device information from device %s",
				  plugin_data->device_name);
			logibulkcontroller_close_device(obj);
			return FALSE;
		}
		ctx = fu_plugin_get_context(plugin);

		device = fu_device_new_with_context(ctx);
		fu_device_set_id(device, "logibulkctrl-video-conf-devices");
		fu_device_add_guid(device, "9608c52f-e60f-597d-a813-84c6f2177a89");
		fu_device_set_name(device, plugin_data->device_info.name);
		fu_device_add_flag(device, FWUPD_DEVICE_FLAG_UPDATABLE);
		fu_device_add_protocol(device, "com.logitech.vc.proto");
		fu_device_set_vendor(device, "Logitech");
		fu_device_add_vendor_id(device, "USB:0x046D");
		fu_device_set_version_format(device, FWUPD_VERSION_FORMAT_TRIPLET);
		fu_device_set_version(device, plugin_data->device_info.sw);
		fu_plugin_device_add(plugin, device);
		return TRUE;
	}
	g_debug("Unknown or unsupported device");
	return FALSE;
}

gboolean
fu_plugin_write_firmware(FuPlugin *plugin,
			 FuDevice *device,
			 GBytes *blob_fw,
			 FwupdInstallFlags flags,
			 GError **error)
{
	FuPluginData *plugin_data;

	plugin_data = fu_plugin_get_data(plugin);
	if (plugin_data->device_type == kDeviceTypeUnknown) {
		g_warning("Device no longer available");
		return FALSE;
	}
	if (plugin_data->bulkcontroller_obj == NULL) {
		g_warning("Device no longer connected, retry");
		return FALSE;
	}
	plugin_data->device_obj = device;
	/* Preserve current version for later comparison */
	g_stpcpy(plugin_data->old_version, plugin_data->device_info.sw);
	g_debug("Updating firmware for %s, current %s, new size = %" G_GSIZE_FORMAT,
		plugin_data->device_info.name,
		plugin_data->device_info.sw,
		g_bytes_get_size(blob_fw));
	fu_device_set_status(device, FWUPD_STATUS_DEVICE_WRITE);
	logibulkcontroller_send_file_upd(plugin_data->bulkcontroller_obj,
					 blob_fw,
					 g_bytes_get_size(blob_fw),
					 TRUE);
	if (g_cond_wait_until(&plugin_data->test_upd_cond,
			      &plugin_data->test_upd_mutex,
			      g_get_monotonic_time() + TIMEOUT_UPD_1200SEC * G_TIME_SPAN_SECOND)) {
		g_mutex_unlock(&plugin_data->test_upd_mutex);
		g_mutex_lock(&plugin_data->test_upd_mutex);
	}
	return TRUE;
}

void
fu_plugin_destroy(FuPlugin *plugin)
{
	FuPluginData *plugin_data = fu_plugin_get_data(plugin);
	g_debug("Terminating Logitech bulk controller plugin");
	/* Following cleanup is for troubleshooting purpose only */
	plugin_data->run_devicemode_info_ = FALSE;
	plugin_data->device_info_available = FALSE;
	plugin_data->device_type = kDeviceTypeUnknown;
	if (plugin_data->bulkcontroller_obj) {
		logibulkcontroller_close_device(plugin_data->bulkcontroller_obj);
		plugin_data->bulkcontroller_obj = NULL;
	}
}
