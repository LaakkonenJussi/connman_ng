/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2013  Intel Corporation. All rights reserved.
 *  Copyright (C) 2025-2026  Jolla Mobile Ltd. All right reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <getopt.h>
#include <sys/stat.h>
#include <net/if.h>
#include <netdb.h>

#include <gdbus.h>

#include "connman.h"
#include "src/shared/util.h"
#include <connman/setting.h>

#define MAINFILE "main.conf"
#define CONFIGMAINFILE CONFIGDIR "/" MAINFILE
#define CONFIGMAINDIR CONFIGMAINFILE ".d"
#define CONFIGSUFFIX ".conf"

static GKeyFile *load_config(const char *file)
{
	GError *err = NULL;
	GKeyFile *keyfile;

	keyfile = g_key_file_new();

	g_key_file_set_list_separator(keyfile, ',');

	if (!g_key_file_load_from_file(keyfile, file, 0, &err)) {
		if (err->code != G_FILE_ERROR_NOENT) {
			connman_error("Parsing %s failed: %s", file,
								err->message);
		}

		g_error_free(err);
		g_key_file_unref(keyfile);
		return NULL;
	}

	return keyfile;
}

static void check_config(GKeyFile *config, const char *file)
{
	char **keys;
	int j;

	if (!config)
		return;

	keys = g_key_file_get_groups(config, NULL);

	for (j = 0; keys && keys[j]; j++) {
		if (g_strcmp0(keys[j], GENERAL_GROUP) != 0)
			connman_warn("Unknown group %s in %s", keys[j], file);
	}

	g_strfreev(keys);

	keys = g_key_file_get_keys(config, GENERAL_GROUP, NULL, NULL);

	for (j = 0; keys && keys[j]; j++) {
		if (!__connman_setting_is_supported_option(keys[j]))
			connman_warn("Unknown option %s in %s", keys[j], file);
	}

	g_strfreev(keys);
}


static int config_init(const char *file, bool mainconfig, bool append)
{
	GKeyFile *config;

	config = load_config(file);
	if (config) {
		DBG("parsing %s", file);
		check_config(config, file);
		__connman_setting_read_config_values(config, mainconfig,
									append);
		g_key_file_unref(config);
	}

	return 0;
}

static int config_read(const char *file)
{
	return config_init(file, false, false);
}

static GMainLoop *main_loop = NULL;

static unsigned int __terminated = 0;

static gboolean signal_handler(GIOChannel *channel, GIOCondition cond,
							gpointer user_data)
{
	struct signalfd_siginfo si;
	ssize_t result;
	int fd;

	if (cond & (G_IO_NVAL | G_IO_ERR | G_IO_HUP))
		return FALSE;

	fd = g_io_channel_unix_get_fd(channel);

	result = read(fd, &si, sizeof(si));
	if (result != sizeof(si))
		return FALSE;

	switch (si.ssi_signo) {
	case SIGINT:
	case SIGTERM:
		if (__terminated == 0) {
			connman_info("Terminating");
			g_main_loop_quit(main_loop);
		}

		__terminated = 1;
		break;
	}

	return TRUE;
}

static guint setup_signalfd(void)
{
	GIOChannel *channel;
	guint source;
	sigset_t mask;
	int fd;

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);

	if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) {
		perror("Failed to set signal mask");
		return 0;
	}

	fd = signalfd(-1, &mask, 0);
	if (fd < 0) {
		perror("Failed to create signal descriptor");
		return 0;
	}

	channel = g_io_channel_unix_new(fd);

	g_io_channel_set_close_on_unref(channel, TRUE);
	g_io_channel_set_encoding(channel, NULL, NULL);
	g_io_channel_set_buffered(channel, FALSE);

	source = g_io_add_watch(channel,
				G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
				signal_handler, NULL);

	g_io_channel_unref(channel);

	return source;
}

static void disconnect_callback(DBusConnection *conn, void *user_data)
{
	connman_error("D-Bus disconnect");

	g_main_loop_quit(main_loop);
}

static gchar *option_config = NULL;
static gchar *option_debug = NULL;
static gchar *option_device = NULL;
static gchar *option_plugin = NULL;
static gchar *option_nodevice = NULL;
static gchar *option_noplugin = NULL;
static gboolean option_detach = TRUE;
static gboolean option_dnsproxy = TRUE;
static gboolean option_backtrace = TRUE;
static gboolean option_version = FALSE;

static bool parse_debug(const char *key, const char *value,
					gpointer user_data, GError **error)
{
	if (value) {
		if (option_debug) {
			char *prev = option_debug;

			option_debug = g_strconcat(prev, ",", value, NULL);
			g_free(prev);
		} else {
			option_debug = g_strdup(value);
		}
	} else {
		g_free(option_debug);
		option_debug = g_strdup("*");
	}

	return true;
}

static bool parse_noplugin(const char *key, const char *value,
					gpointer user_data, GError **error)
{
	if (option_noplugin) {
		char *prev = option_noplugin;

		option_noplugin = g_strconcat(prev, ",", value, NULL);
		g_free(prev);
	} else {
		option_noplugin = g_strdup(value);
	}

	return true;
}

static bool parse_wifi(const char *key, const char *value,
					gpointer user_data, GError **error)
{
	__connman_setting_set_option(key, value);
	return true;
}

static GOptionEntry options[] = {
	{ "config", 'c', 0, G_OPTION_ARG_STRING, &option_config,
				"Load the specified configuration file "
				"instead of " CONFIGMAINFILE, "FILE" },
	{ "debug", 'd', G_OPTION_FLAG_OPTIONAL_ARG,
				G_OPTION_ARG_CALLBACK, parse_debug,
				"Specify debug options to enable", "DEBUG" },
	{ "device", 'i', 0, G_OPTION_ARG_STRING, &option_device,
			"Specify networking devices or interfaces", "DEV,..." },
	{ "nodevice", 'I', 0, G_OPTION_ARG_STRING, &option_nodevice,
			"Specify networking interfaces to ignore", "DEV,..." },
	{ "plugin", 'p', 0, G_OPTION_ARG_STRING, &option_plugin,
				"Specify plugins to load", "NAME,..." },
	{ "noplugin", 'P', 0, G_OPTION_ARG_CALLBACK, &parse_noplugin,
				"Specify plugins not to load", "NAME,..." },
	{ "wifi", 'W', 0, G_OPTION_ARG_CALLBACK, &parse_wifi,
				"Specify driver for WiFi/Supplicant", "NAME" },
	{ "nodaemon", 'n', G_OPTION_FLAG_REVERSE,
				G_OPTION_ARG_NONE, &option_detach,
				"Don't fork daemon to background" },
	{ "nodnsproxy", 'r', G_OPTION_FLAG_REVERSE,
				G_OPTION_ARG_NONE, &option_dnsproxy,
				"Don't support DNS resolving" },
	{ "nobacktrace", 0, G_OPTION_FLAG_REVERSE,
				G_OPTION_ARG_NONE, &option_backtrace,
				"Don't print out backtrace information" },
	{ "version", 'v', 0, G_OPTION_ARG_NONE, &option_version,
				"Show version information and exit" },
	{ NULL },
};

int main(int argc, char *argv[])
{
	GOptionContext *context;
	GError *error = NULL;
	DBusConnection *conn;
	DBusError err;
	guint signal;
	int fs_err;

	context = g_option_context_new(NULL);
	g_option_context_add_main_entries(context, options, NULL);
	__connman_setting_init();

	if (!g_option_context_parse(context, &argc, &argv, &error)) {
		if (error) {
			g_printerr("%s\n", error->message);
			g_error_free(error);
		} else
			g_printerr("An unknown error occurred\n");
		exit(1);
	}

	g_option_context_free(context);

	if (option_version) {
		printf("%s\n", VERSION);
		exit(0);
	}

	if (option_detach) {
		if (daemon(0, 0)) {
			perror("Can't start daemon");
			exit(1);
		}
	}

	if (mkdir(STORAGEDIR, S_IRUSR | S_IWUSR | S_IXUSR |
				S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) < 0) {
		if (errno != EEXIST)
			perror("Failed to create storage directory");
	}

	umask(0077);

	main_loop = g_main_loop_new(NULL, FALSE);

	signal = setup_signalfd();

	dbus_error_init(&err);

	conn = g_dbus_setup_bus(DBUS_BUS_SYSTEM, CONNMAN_SERVICE, &err);
	if (!conn) {
		if (dbus_error_is_set(&err)) {
			fprintf(stderr, "%s\n", err.message);
			dbus_error_free(&err);
		} else
			fprintf(stderr, "Can't register with system bus\n");
		exit(1);
	}

	g_dbus_set_disconnect_function(conn, disconnect_callback, NULL, NULL);

	__connman_log_init(argv[0], option_debug, option_detach,
			option_backtrace, "Connection Manager", VERSION);

	__connman_dbus_init(conn);

	if (!option_config)
		config_init(CONFIGMAINFILE, true, false);
	else
		config_init(option_config, true, false);

	fs_err = util_read_config_files_from(CONFIGMAINDIR, CONFIGSUFFIX,
				NULL, config_read);
	if (fs_err && fs_err != -ENOTDIR)
		connman_error("failed to read configs from %s: %s",
				CONFIGMAINDIR, strerror(-fs_err));

	__connman_setting_log();
	__connman_util_init();
	__connman_inotify_init();
	__connman_technology_init();
	__connman_notifier_init();
	__connman_agent_init();
	__connman_service_init();
	__connman_peer_service_init();
	__connman_peer_init();
	__connman_provider_init();
	__connman_network_init();
	__connman_config_init();
	__connman_device_init(option_device, option_nodevice);

	__connman_ippool_init();
	__connman_firewall_init();
	__connman_nat_init();
	__connman_tethering_init();
	__connman_counter_init();
	__connman_manager_init();
	__connman_stats_init();
	__connman_clock_init();

	__connman_ipconfig_init();
	__connman_rtnl_init();
	__connman_task_init();
	__connman_proxy_init();
	__connman_detect_init();
	__connman_session_init();
	__connman_timeserver_init();
	__connman_gateway_init();

	__connman_plugin_init(option_plugin, option_noplugin);

	__connman_resolver_init(option_dnsproxy);
	__connman_rtnl_start();
	__connman_dhcp_init();
	__connman_dhcpv6_init();
	__connman_wpad_init();
	__connman_wispr_init();
	__connman_rfkill_init();
	__connman_machine_init();

	g_free(option_config);
	g_free(option_device);
	g_free(option_plugin);
	g_free(option_nodevice);
	g_free(option_noplugin);

	g_main_loop_run(main_loop);

	g_source_remove(signal);

	__connman_machine_cleanup();
	__connman_rfkill_cleanup();
	__connman_wispr_cleanup();
	__connman_wpad_cleanup();
	__connman_dhcpv6_cleanup();
	__connman_session_cleanup();
	__connman_plugin_cleanup();
	__connman_provider_cleanup();
	__connman_gateway_cleanup();
	__connman_timeserver_cleanup();
	__connman_detect_cleanup();
	__connman_proxy_cleanup();
	__connman_task_cleanup();
	__connman_rtnl_cleanup();
	__connman_resolver_cleanup();

	__connman_clock_cleanup();
	__connman_stats_cleanup();
	__connman_config_cleanup();
	__connman_manager_cleanup();
	__connman_counter_cleanup();
	__connman_tethering_cleanup();
	__connman_nat_cleanup();
	__connman_firewall_cleanup();
	__connman_peer_service_cleanup();
	__connman_peer_cleanup();
	__connman_ippool_cleanup();
	__connman_device_cleanup();
	__connman_network_cleanup();
	__connman_dhcp_cleanup();
	__connman_service_cleanup();
	__connman_agent_cleanup();
	__connman_ipconfig_cleanup();
	__connman_notifier_cleanup();
	__connman_technology_cleanup();
	__connman_inotify_cleanup();

	__connman_util_cleanup();
	__connman_dbus_cleanup();

	__connman_log_cleanup(option_backtrace);

	dbus_connection_unref(conn);

	g_main_loop_unref(main_loop);

	__connman_setting_cleanup();

	g_free(option_debug);

	return 0;
}
