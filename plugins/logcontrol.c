/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2015, 2026 Jolla Ltd. All rights reserved.
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

#include <gdbus.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/log.h>
#include <connman.h>

#define LOG_INTERFACE  CONNMAN_SERVICE ".DebugLog"
#define LOG_PATH       "/"

static DBusConnection *connection = NULL;

static DBusMessage *logcontrol_dbusmsg(DBusConnection *conn, DBusMessage *msg,
			unsigned int set_flags, unsigned int clear_flags)
{
	const char *pattern;

	if (dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &pattern,
							DBUS_TYPE_INVALID)) {
		connman_log_update_builtin(pattern, set_flags, clear_flags);
		connman_plugin_log_update(pattern, set_flags, clear_flags);
		return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
	}

	return __connman_error_invalid_arguments(msg);
}

static DBusMessage *logcontrol_enable(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	return logcontrol_dbusmsg(conn, msg, CONNMAN_DEBUG_FLAG_PRINT, 0);
}

static DBusMessage *logcontrol_disable(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	return logcontrol_dbusmsg(conn, msg, 0, CONNMAN_DEBUG_FLAG_PRINT);
}

static gint logcontrol_list_compare(gconstpointer a, gconstpointer b)
{
	return strcmp((const char *)a, (const char *)b);
}

struct logcontrol_list_data {
	GHashTable *hash;
	DBusMessageIter *array;
};

static void logcontrol_list_append(gpointer name, gpointer user_data)
{
	struct logcontrol_list_data *data = user_data;
	struct connman_debug_desc *desc;
	DBusMessageIter *array = data->array;
	DBusMessageIter iter;
	const char *name_str = name;
	dbus_bool_t enabled;

	desc = g_hash_table_lookup(data->hash, name);
	if (!desc)
		return;

	enabled = connman_log_is_enabled(desc);

	dbus_message_iter_open_container(array, DBUS_TYPE_STRUCT, NULL, &iter);

	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &name_str);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_BOOLEAN, &enabled);

	dbus_message_iter_close_container(array, &iter);
}

static DBusMessage *logcontrol_list(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	DBusMessageIter iter, array;
	GHashTable *hash;
	GList *names;
	struct logcontrol_list_data list_data;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	hash = g_hash_table_new(g_str_hash, g_str_equal);

	connman_log_list_builtin(hash);
	connman_plugin_log_list(hash);

	names = g_list_sort(g_hash_table_get_keys(hash),
						logcontrol_list_compare);

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_STRUCT_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING
			DBUS_TYPE_BOOLEAN_AS_STRING
			DBUS_STRUCT_END_CHAR_AS_STRING,
			&array);

	list_data.hash = hash;
	list_data.array = &array;
	g_list_foreach(names, logcontrol_list_append, &list_data);

	dbus_message_iter_close_container(&iter, &array);

	g_list_free(names);
	g_hash_table_destroy(hash);

	return reply;
}

static const GDBusMethodTable methods[] = {
	{ GDBUS_METHOD("Enable", GDBUS_ARGS({ "pattern", "s" }), NULL,
							logcontrol_enable) },
	{ GDBUS_METHOD("Disable", GDBUS_ARGS({ "pattern", "s" }), NULL,
							logcontrol_disable) },
	{ GDBUS_METHOD("List", NULL, GDBUS_ARGS({ "names", "a(sb)" }),
							logcontrol_list) },
	{ },
};

static int logcontrol_init(void)
{
	DBG("");

	connection = connman_dbus_get_connection();
	if (!connection)
		return -1;

	if (!g_dbus_register_interface(connection, LOG_PATH, LOG_INTERFACE,
					methods, NULL, NULL, NULL, NULL)) {
		connman_error("logcontrol: failed to register " LOG_INTERFACE);
		return -1;
	}

	return 0;
}

static void logcontrol_exit(void)
{
	DBG("");

	if (connection) {
		g_dbus_unregister_interface(connection, LOG_PATH,
								LOG_INTERFACE);
		dbus_connection_unref(connection);
		connection = NULL;
	}
}

CONNMAN_PLUGIN_DEFINE(logcontrol, "Debug log control interface",
			VERSION, CONNMAN_PLUGIN_PRIORITY_DEFAULT,
			logcontrol_init, logcontrol_exit)
