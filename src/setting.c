/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2025  Jolla Ltd.
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
#include <arpa/inet.h>

#include "connman.h"


#define CONF_ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]) - 1)

#define DEFAULT_INPUT_REQUEST_TIMEOUT (120 * 1000)
#define DEFAULT_BROWSER_LAUNCH_TIMEOUT (300 * 1000)

#define DEFAULT_ONLINE_CHECK_IPV4_URL "http://ipv4.connman.net/online/status.html"
#define DEFAULT_ONLINE_CHECK_IPV6_URL "http://ipv6.connman.net/online/status.html"

#define DEFAULT_ONLINE_CHECK_CONNECT_TIMEOUT (0 * 1000)
/*
 * We set the integer to 1 sec so that we have a chance to get
 * necessary IPv6 router advertisement messages that might have
 * DNS data etc.
 */
#define DEFAULT_ONLINE_CHECK_INITIAL_INTERVAL 1
#define DEFAULT_ONLINE_CHECK_MAX_INTERVAL 12

#define DEFAULT_ONLINE_CHECK_FAILURES_THRESHOLD 6
#define DEFAULT_ONLINE_CHECK_SUCCESSES_THRESHOLD 6

#define ONLINE_CHECK_INTERVAL_STYLE_FIBONACCI "fibonacci"
#define ONLINE_CHECK_INTERVAL_STYLE_GEOMETRIC "geometric"

#define DEFAULT_ONLINE_CHECK_INTERVAL_STYLE ONLINE_CHECK_INTERVAL_STYLE_GEOMETRIC

#define DEFAULT_LOCALTIME "/etc/localtime"

#define DEFAULT_WIFI_OPTION "nl80211,wext"

static char *default_auto_connect[] = {
	"wifi",
	"ethernet",
	"cellular",
	NULL
};

static char *default_enabled_techs[] = {
	"ethernet",
	NULL
};

static char *default_favorite_techs[] = {
	"ethernet",
	NULL
};

static char *default_blacklist[] = {
	"vmnet",
	"vboxnet",
	"virbr",
	"ifb",
	"ve-",
	"vb-",
	"ham",
	"veth",
	NULL
};

enum option_val {
	CONF_BG_SCAN_VAL = 0,
	CONF_PREF_TIMESERVERS_VAL,
	CONF_AUTO_CONNECT_TECHS_VAL,
	CONF_ENABLED_TECHS_VAL,
	CONF_FAVORITE_TECHS_VAL,
	CONF_ALWAYS_CONNECTED_TECHS_VAL,
	CONF_PREFERRED_TECHS_VAL,
	CONF_FALLBACK_NAMESERVERS_VAL,
	CONF_TIMEOUT_INPUTREQ_VAL,
	CONF_TIMEOUT_BROWSERLAUNCH_VAL,
	CONF_BLACKLISTED_INTERFACES_VAL,
	CONF_ALLOW_HOSTNAME_UPDATES_VAL,
	CONF_ALLOW_DOMAINNAME_UPDATES_VAL,
	CONF_SINGLE_TECH_VAL,
	CONF_TETHERING_TECHNOLOGIES_VAL,
	CONF_PERSISTENT_TETHERING_MODE_VAL,
	CONF_ENABLE_6TO4_VAL,
	CONF_VENDOR_CLASS_ID_VAL,
	CONF_ENABLE_ONLINE_CHECK_VAL,
	CONF_ENABLE_ONLINE_TO_READY_TRANSITION_VAL,
	CONF_ONLINE_CHECK_MODE_VAL,
	CONF_ONLINE_CHECK_IPV4_URL_VAL,
	CONF_ONLINE_CHECK_IPV6_URL_VAL,
	CONF_ONLINE_CHECK_CONNECT_TIMEOUT_VAL,
	CONF_ONLINE_CHECK_INITIAL_INTERVAL_VAL,
	CONF_ONLINE_CHECK_MAX_INTERVAL_VAL,
	CONF_ONLINE_CHECK_FAILURES_THRESHOLD_VAL,
	CONF_ONLINE_CHECK_SUCCESSES_THRESHOLD_VAL,
	CONF_ONLINE_CHECK_INTERVAL_STYLE_VAL,
	CONF_AUTO_CONNECT_ROAMING_SERVICES_VAL,
	CONF_ACD_VAL,
	CONF_USE_GATEWAYS_AS_TIMESERVERS_VAL,
	CONF_LOCALTIME_VAL,
	CONF_REGDOM_FOLLOWS_TIMEZONE_VAL,
	CONF_RESOLV_CONF_VAL,
	CONF_FALLBACK_DEVICE_TYPES_VAL,
	CONF_OPTION_WIFI_VAL,
};

enum option_type {
	CONF_TYPE_UINT = 0,
	CONF_TYPE_UINTARR,
	CONF_TYPE_STR,
	CONF_TYPE_STRARR,
	CONF_TYPE_BOOL,
	CONF_TYPE_DOUBLE,
	CONF_TYPE_HASHTABLE
};

/* Union for storing the values */
union config_value {
	bool bool_val;
	unsigned int uint_val;
	double double_val;
	char *str_val;
	char **str_array_val;
	unsigned int *int_array_val;
	GHashTable *hash_table_val;
};

/* Callback for checking if value is acceptable */
typedef gboolean (*value_check_callback)(const char *value);

/* Callback for parsing items in a string list */
typedef char** (*parse_callback)(char **str_list, gsize *len);

/* Callback for parsing uint list from the NULL terminated string list */
typedef uint* (*parse_list_uint_callback)(char **list, gsize len);

/* Callback for parsing the string to add the values separately to an option. */
typedef void (*parse_list_item_callback) (const char *value);

/* Callback for parsing string list into hashtable. */
typedef GHashTable* (*parse_hashtable_callback)(char **list, gsize len);

/* Error callback */
typedef int (*error_callback)(void);

/*
 * Configuration options struct.
 *
 * Any new configuration option has to have at least key, value and type (and
 * return type) set. The fields are detailed as follows:
 *
 * opt_key		Option name, used for searching in getters
 * opt_value		enum value for the option
 * opt_type		Option type, see enum option_type
 * opt_return_type	The type of this option returns, supported: str -> uint
 * default_val		Default value as union option, must match opt_type
 * check_str_cb		Callback for checking string value: CONF_TYPE_STR
 * parse_list_strs_cb	Callback for parsing a string list: CONF_TYPE_STRARR
 * parse_list_uint_cb	Callback for parsing int list: CONF_TYPE_UINTARR
 * parse_list_item_cb	Callback to handle of strings separate: CONF_TYPE_STRARR
 * parse_hashtable_cb	Callback for parsing a hash table: CONF_TYPE_HASHTABLE
 * error_cb		Error callback when check_str_cb fails
 * multiplier		For CONF_TYPE_UINT and CONF_TYPE_DOUBLE correlation
 *
 * If both parse_list_strs_cb and parse_list_item_cb are missing the string list
 * is saved as is to configuration. The special case of parse_list_item_cb
 * handling is to not to create a string list but to handle items separately,
 * for example, using different concatenation to form a one value.
 *
 * The alternative return type, opt_return_type, can be used to define a
 * conversion type value for a string. Currently accepted conversions are STR ->
 * UINT and DOUBLE -> UINT only.
 *
 * The error_cb is useful in cases where the value needs a complicated setup.
 *
 * The integer multiplier is applied only for INT and DOUBLE values when set.
 * Keep this 1 for INT/DOUBLE and 0 for everything else.
 *
 * The default_val can be used to define the config option default value. All
 * regular values (BOOL, INT, DOUBLE) will get the value copied to current_val.
 * STR will get copied only when it is converted to INT at return. Any INTARR,
 * STRARR or HASHTABLE opt_type needs to be initialized in
 * initialize_default_values(), and free'd in __connman_settings_cleanup().
 */
struct config_option {
	const char *opt_key;			/* Config option name */
	enum option_val opt_value;		/* Enum identifier */
	enum option_type opt_type;		/* Define valid union field */
	/* Special handling, read as opt_type, return with this union type */
	enum option_type opt_return_type;

	/* Unions for default value and current storage */
	union config_value default_val;
	union config_value current_val;

	value_check_callback check_str_cb;
	parse_callback parse_list_strs_cb;
	parse_list_uint_callback parse_list_uint_cb;
	parse_list_item_callback parse_list_item_cb;
	parse_hashtable_callback parse_hashtable_cb;
	error_callback error_cb;
	unsigned int multiplier;		/* For integers/doubles*/
};

/* Global config options hash table */
static GHashTable *config_options_table = NULL;

/* Parsers for config options. */
static uint *parse_service_types(char **str_list, gsize len)
{
	unsigned int *type_list;
	int i, j;
	enum connman_service_type type;

	type_list = g_try_new0(unsigned int, len + 1);
	if (!type_list)
		return NULL;

	i = 0;
	j = 0;
	while (str_list[i]) {
		type = __connman_service_string2type(str_list[i]);

		if (type != CONNMAN_SERVICE_TYPE_UNKNOWN) {
			type_list[j] = type;
			j += 1;
		}
		i += 1;
	}

	type_list[j] = CONNMAN_SERVICE_TYPE_UNKNOWN;

	return type_list;
}

static char **parse_fallback_nameservers(char **nameservers, gsize *len)
{
	char **servers;
	int i, j;

	servers = g_try_new0(char *, *len + 1);
	if (!servers)
		return NULL;

	i = 0;
	j = 0;
	while (nameservers[i]) {
		if (connman_inet_check_ipaddress(nameservers[i]) > 0) {
			servers[j] = g_strdup(nameservers[i]);
			j += 1;
		}
		i += 1;
	}

	*len = j + 1;

	return servers;
}

static GHashTable *parse_fallback_device_types(char **devtypes, gsize len)
{
	GHashTable *h;
	gsize i;

	h = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

	for (i = 0; i < len; ++i) {
		char **v;

		v = g_strsplit(devtypes[i], ":", 2);
		if (!v)
			continue;

		if (v[0] && v[1]) {
			if (__connman_device_string2type(v[1]) ==
						CONNMAN_DEVICE_TYPE_UNKNOWN)
				connman_warn("Invalid FallbackDeviceType in %s",
								devtypes[i]);
			else
				g_hash_table_replace(h, g_strdup(v[0]),
								g_strdup(v[1]));
		}

		g_strfreev(v);
	}

	if (g_hash_table_size(h) > 0)
		return h;

	g_hash_table_unref(h);
	return NULL;
}

/* Find option by key */
static struct config_option *config_option_lookup(const char *key)
{
	if (!key || !config_options_table)
		return NULL;

	return g_hash_table_lookup(config_options_table, key);
}

/* Type-safe getters using the union */
bool connman_setting_get_bool(const char *key)
{
	struct config_option *opt;

	opt = config_option_lookup(key);
	if (!opt || opt->opt_type != CONF_TYPE_BOOL)
		return false;

	return opt->current_val.bool_val;
}

unsigned int connman_setting_get_uint(const char *key)
{
	struct config_option *opt;

	opt = config_option_lookup(key);
	if (!opt)
		return 0;

	if (opt->opt_type != CONF_TYPE_UINT &&
					opt->opt_return_type != CONF_TYPE_UINT)
		return 0;

	return opt->current_val.uint_val;
}

const char *connman_setting_get_string(const char *key)
{
	struct config_option *opt;

	opt = config_option_lookup(key);
	if (!opt || opt->opt_type != CONF_TYPE_STR)
		return NULL;

	if (opt->current_val.str_val)
		return opt->current_val.str_val;

	return opt->default_val.str_val;
}

char **connman_setting_get_string_list(const char *key)
{
	struct config_option *opt;

	opt = config_option_lookup(key);
	if (!opt || opt->opt_type != CONF_TYPE_STRARR)
		return NULL;

	if (opt->current_val.str_array_val)
		return opt->current_val.str_array_val;

	return opt->default_val.str_array_val;
}

unsigned int *connman_setting_get_uint_list(const char *key)
{
	struct config_option *opt;

	opt = config_option_lookup(key);
	if (!opt || opt->opt_type != CONF_TYPE_UINTARR)
		return NULL;

	if (opt->current_val.int_array_val)
		return opt->current_val.int_array_val;

	return opt->default_val.int_array_val;
}

/* Wrappers for input request/browser launch timeout getters */
unsigned int connman_timeout_input_request(void)
{
	return connman_setting_get_uint(CONF_TIMEOUT_INPUTREQ);
}

unsigned int connman_timeout_browser_launch(void)
{
	return connman_setting_get_uint(CONF_TIMEOUT_BROWSERLAUNCH);
}

/* Type-safe value setters */
static void set_bool_value(struct config_option *opt, bool value)
{
	if (opt->opt_type != CONF_TYPE_BOOL)
		return;

	opt->current_val.bool_val = value;
}

static void set_uint_value(struct config_option *opt, unsigned int value)
{
	if (opt->opt_type != CONF_TYPE_UINT &&
					opt->opt_return_type != CONF_TYPE_UINT)
		return;

	opt->current_val.uint_val = value;
}

static void set_str_value(struct config_option *opt, char *value,
						value_check_callback check_str_cb)
{
	if (opt->opt_type != CONF_TYPE_STR)
		return;

	if (check_str_cb && !check_str_cb(value)) {
		g_free(value);
		return;
	}

	if (!g_strcmp0(opt->current_val.str_val, value))
		return;

	g_free(opt->current_val.str_val);
	opt->current_val.str_val = value;
}

static void set_str_array_value(struct config_option *opt, char **value)
{
	if (opt->opt_type != CONF_TYPE_STRARR)
		return;

	g_strfreev(opt->current_val.str_array_val);
	opt->current_val.str_array_val = value;
}

/* For setting a value individually with a callback to a specific option */
static void set_str_array_value_cb(struct config_option *opt, char **value,
						parse_list_item_callback cb,
						gsize len, bool append)
{
	int i;

	if (opt->opt_type != CONF_TYPE_STRARR)
		return;

	if (append) {
		/* TODO */
		connman_warn("set_str_array_value_cb() append is ENOTSUP");
	}

	for (i = 0; i < len; i++)
		cb(value[i]);
}

static void set_int_array_value(struct config_option *opt, unsigned int *value)
{
	if (opt->opt_type != CONF_TYPE_UINTARR)
		return;

	g_free(opt->current_val.int_array_val);
	opt->current_val.int_array_val = value;
}

static void set_hash_table_value(struct config_option *opt, GHashTable *value)
{
	if (opt->opt_type != CONF_TYPE_HASHTABLE)
		return;

	if (opt->current_val.hash_table_val)
		g_hash_table_destroy(opt->current_val.hash_table_val);

	opt->current_val.hash_table_val = value;
}

/* Internal helper-wrappers */
static int setting_set_bool(const char *key, bool value)
{
	struct config_option *opt;

	opt = config_option_lookup(key);
	if (!opt)
		return -EINVAL;

	set_bool_value(opt, value);

	return 0;
}

static int setting_set_uint(const char *key, unsigned int value)
{
	struct config_option *opt;

	opt = config_option_lookup(key);
	if (!opt)
		return -EINVAL;

	set_uint_value(opt, value);

	return 0;
}

/* Public setters for internal use */
void __connman_setting_set_option(const char *key, const char *value)
{
	struct config_option *opt;

	if (!key)
		return;

	opt = config_option_lookup(key);
	if (!opt)
		return;

	set_str_value(opt, g_strdup(value), NULL);
}

/* Online mode checking functions */
static int online_check_connect_timeout_error(void)
{
	connman_warn("Incorrect online check connect timeout");

	return setting_set_uint(CONF_ONLINE_CHECK_CONNECT_TIMEOUT,
					DEFAULT_ONLINE_CHECK_CONNECT_TIMEOUT);
}

static int online_check_mode_set_from_deprecated(void)
{
	bool enable_online_check;
	bool enable_online_to_ready_transition;

	enable_online_check = connman_setting_get_bool(
					CONF_ENABLE_ONLINE_CHECK);
	enable_online_to_ready_transition = connman_setting_get_bool(
					CONF_ENABLE_ONLINE_TO_READY_TRANSITION);

	return setting_set_uint(CONF_ONLINE_CHECK_MODE,
		enable_online_check ?
			enable_online_to_ready_transition ?
				CONNMAN_SERVICE_ONLINE_CHECK_MODE_CONTINUOUS :
				CONNMAN_SERVICE_ONLINE_CHECK_MODE_ONE_SHOT :
		CONNMAN_SERVICE_ONLINE_CHECK_MODE_NONE);
}

static void online_check_mode_set_to_deprecated(void)
{
	bool enable_online_check;
	bool enable_online_to_ready_transition;

	switch (connman_setting_get_uint(CONF_ONLINE_CHECK_MODE)) {
	case CONNMAN_SERVICE_ONLINE_CHECK_MODE_NONE:
		enable_online_check = false;
		enable_online_to_ready_transition = false;
		break;
	case CONNMAN_SERVICE_ONLINE_CHECK_MODE_ONE_SHOT:
		enable_online_check = true;
		enable_online_to_ready_transition = false;
		break;
	case CONNMAN_SERVICE_ONLINE_CHECK_MODE_CONTINUOUS:
		enable_online_check = true;
		enable_online_to_ready_transition = true;
		break;
	default:
		return;
	}

	setting_set_bool(CONF_ENABLE_ONLINE_CHECK,
					enable_online_check);
	setting_set_bool(CONF_ENABLE_ONLINE_TO_READY_TRANSITION,
					enable_online_to_ready_transition);
}

static gboolean check_online_mode(const char *str)
{
	enum service_online_check_mode online_check_mode =
			__connman_service_online_check_string2mode(str);

	setting_set_uint(CONF_ONLINE_CHECK_MODE, online_check_mode);

	if (online_check_mode == CONNMAN_SERVICE_ONLINE_CHECK_MODE_UNKNOWN) {
		connman_error("Invalid online check mode \"%s\"", str);

		online_check_mode_set_from_deprecated();
	} else {
		online_check_mode_set_to_deprecated();
	}

	return false;
}

static gboolean check_online_check_interval_style(const char *str)
{
	if ((g_strcmp0(str, ONLINE_CHECK_INTERVAL_STYLE_FIBONACCI) == 0) ||
		(g_strcmp0(str, ONLINE_CHECK_INTERVAL_STYLE_GEOMETRIC) == 0)) {
		return true;
	} else {
		connman_warn("Incorrect online check interval style [%s]", str);
		return false;
	}
}

static void online_check_settings_log(void)
{
	if (!connman_setting_get_string(CONF_ONLINE_CHECK_MODE))
		connman_info("Online check disabled by config");
	else
		connman_info("Online check mode \"%s\"",
				__connman_service_online_check_mode2string(
					connman_setting_get_uint(
						CONF_ONLINE_CHECK_MODE)));

	if (connman_setting_get_uint(CONF_ONLINE_CHECK_MODE) ==
			CONNMAN_SERVICE_ONLINE_CHECK_MODE_NONE)
		return;

	connman_info("Online check IPv4 URL \"%s\"",
		connman_setting_get_string(CONF_ONLINE_CHECK_IPV4_URL));

	connman_info("Online check IPv6 URL \"%s\"",
		connman_setting_get_string(CONF_ONLINE_CHECK_IPV6_URL));

	connman_info("Online check interval style \"%s\"",
		connman_setting_get_string(CONF_ONLINE_CHECK_INTERVAL_STYLE));

	connman_info("Online check interval range [%u, %u]",
		connman_setting_get_uint(CONF_ONLINE_CHECK_INITIAL_INTERVAL),
		connman_setting_get_uint(CONF_ONLINE_CHECK_MAX_INTERVAL));

	if (connman_setting_get_uint(CONF_ONLINE_CHECK_CONNECT_TIMEOUT))
		connman_info("Online check connect timeout %u ms",
			connman_setting_get_uint(
				CONF_ONLINE_CHECK_CONNECT_TIMEOUT));

	if (connman_setting_get_uint(CONF_ONLINE_CHECK_MODE) !=
			CONNMAN_SERVICE_ONLINE_CHECK_MODE_CONTINUOUS)
		return;

	connman_info("Online check continuous mode failures threshold %d",
			connman_setting_get_uint(
				CONF_ONLINE_CHECK_FAILURES_THRESHOLD));

	connman_info("Online check continuous mode successes threshold %d",
			connman_setting_get_uint(
				CONF_ONLINE_CHECK_SUCCESSES_THRESHOLD));
}

static struct config_option config_options[] = {
	/* BackgroundScanning */
	{
		.opt_key = CONF_BG_SCAN,
		.opt_value = CONF_BG_SCAN_VAL,
		.opt_type = CONF_TYPE_BOOL,
		.opt_return_type = CONF_TYPE_BOOL,
		.default_val.bool_val = true,
		.check_str_cb = NULL,
		.parse_list_strs_cb = NULL,
		.parse_list_uint_cb = NULL,
		.parse_list_item_cb = NULL,
		.parse_hashtable_cb = NULL,
		.error_cb = NULL,
		.multiplier = 0
	},
	/* FallbackTimeservers */
	{
		.opt_key = CONF_PREF_TIMESERVERS,
		.opt_value = CONF_PREF_TIMESERVERS_VAL,
		.opt_type = CONF_TYPE_STRARR,
		.opt_return_type = CONF_TYPE_STRARR,
		.default_val.str_array_val = NULL,
		.check_str_cb = NULL,
		.parse_list_strs_cb = NULL,
		.parse_list_uint_cb = parse_service_types,
		.parse_list_item_cb = NULL,
		.parse_hashtable_cb = NULL,
		.error_cb = NULL,
		.multiplier = 0
	},
	/* DefaultAutoConnectTechnologies */
	{
		.opt_key = CONF_AUTO_CONNECT_TECHS,
		.opt_value = CONF_AUTO_CONNECT_TECHS_VAL,
		.opt_type = CONF_TYPE_UINTARR,
		.opt_return_type = CONF_TYPE_UINTARR,
		.default_val.int_array_val = NULL,
		.check_str_cb = NULL,
		.parse_list_strs_cb = NULL,
		.parse_list_uint_cb = parse_service_types,
		.parse_list_item_cb = NULL,
		.parse_hashtable_cb = NULL,
		.error_cb = NULL,
		.multiplier = 0
	},
	/* DefaultEnabledTechnologies */
	{
		.opt_key = CONF_ENABLED_TECHS,
		.opt_value = CONF_ENABLED_TECHS_VAL,
		.opt_type = CONF_TYPE_UINTARR,
		.opt_return_type = CONF_TYPE_UINTARR,
		.default_val.int_array_val = NULL,
		.check_str_cb = NULL,
		.parse_list_strs_cb = NULL,
		.parse_list_uint_cb = parse_service_types,
		.parse_list_item_cb = NULL,
		.parse_hashtable_cb = NULL,
		.error_cb = NULL,
		.multiplier = 0
	},
	/* DefaultFavoriteTechnologies */
	{
		.opt_key = CONF_FAVORITE_TECHS,
		.opt_value = CONF_FAVORITE_TECHS_VAL,
		.opt_type = CONF_TYPE_UINTARR,
		.opt_return_type = CONF_TYPE_UINTARR,
		.default_val.int_array_val = NULL,
		.check_str_cb = NULL,
		.parse_list_strs_cb = NULL,
		.parse_list_uint_cb = parse_service_types,
		.parse_list_item_cb = NULL,
		.parse_hashtable_cb = NULL,
		.error_cb = NULL,
		.multiplier = 0
	},
	/* AlwaysConnectedTechnologies */
	{
		.opt_key = CONF_ALWAYS_CONNECTED_TECHS,
		.opt_value = CONF_ALWAYS_CONNECTED_TECHS_VAL,
		.opt_type = CONF_TYPE_UINTARR,
		.opt_return_type = CONF_TYPE_UINTARR,
		.default_val.int_array_val = NULL,
		.check_str_cb = NULL,
		.parse_list_strs_cb = NULL,
		.parse_list_uint_cb = parse_service_types,
		.parse_list_item_cb = NULL,
		.parse_hashtable_cb = NULL,
		.error_cb = NULL,
		.multiplier = 0
	},
	/* PreferredTechnologies */
	{
		.opt_key = CONF_PREFERRED_TECHS,
		.opt_value = CONF_PREFERRED_TECHS_VAL,
		.opt_type = CONF_TYPE_UINTARR,
		.opt_return_type = CONF_TYPE_UINTARR,
		.default_val.int_array_val = NULL,
		.check_str_cb = NULL,
		.parse_list_strs_cb = NULL,
		.parse_list_uint_cb = parse_service_types,
		.parse_list_item_cb = NULL,
		.parse_hashtable_cb = NULL,
		.error_cb = NULL,
		.multiplier = 0
	},
	/* FallbackNameservers */
	{
		.opt_key = CONF_FALLBACK_NAMESERVERS,
		.opt_value = CONF_FALLBACK_NAMESERVERS_VAL,
		.opt_type = CONF_TYPE_STRARR,
		.opt_return_type = CONF_TYPE_STRARR,
		.default_val.str_array_val = NULL,
		.check_str_cb = NULL,
		.parse_list_strs_cb = parse_fallback_nameservers,
		.parse_list_uint_cb = NULL,
		.parse_list_item_cb = NULL,
		.parse_hashtable_cb = NULL,
		.error_cb = NULL,
		.multiplier = 0
	},
	/* InputRequestTimeout */
	{
		.opt_key = CONF_TIMEOUT_INPUTREQ,
		.opt_value = CONF_TIMEOUT_INPUTREQ_VAL,
		.opt_type = CONF_TYPE_UINT,
		.opt_return_type = CONF_TYPE_UINT,
		.default_val.uint_val = DEFAULT_INPUT_REQUEST_TIMEOUT,
		.check_str_cb = NULL,
		.parse_list_strs_cb = NULL,
		.parse_list_uint_cb = NULL,
		.parse_list_item_cb = NULL,
		.parse_hashtable_cb = NULL,
		.error_cb = NULL,
		.multiplier = 1000
	},
	/* BrowserLaunchTimeout */
	{
		.opt_key = CONF_TIMEOUT_BROWSERLAUNCH,
		.opt_value = CONF_TIMEOUT_BROWSERLAUNCH_VAL,
		.opt_type = CONF_TYPE_UINT,
		.opt_return_type = CONF_TYPE_UINT,
		.default_val.uint_val = DEFAULT_BROWSER_LAUNCH_TIMEOUT,
		.check_str_cb = NULL,
		.parse_list_strs_cb = NULL,
		.parse_list_uint_cb = NULL,
		.parse_list_item_cb = NULL,
		.parse_hashtable_cb = NULL,
		.error_cb = NULL,
		.multiplier = 1000
	},
	/* NetworkInterfaceBlacklist */
	{
		.opt_key = CONF_BLACKLISTED_INTERFACES,
		.opt_value = CONF_BLACKLISTED_INTERFACES_VAL,
		.opt_type = CONF_TYPE_STRARR,
		.opt_return_type = CONF_TYPE_STRARR,
		.default_val.str_array_val = NULL,
		.check_str_cb = NULL,
		.parse_list_strs_cb = NULL,
		.parse_list_uint_cb = NULL,
		.parse_list_item_cb = NULL,
		.parse_hashtable_cb = NULL,
		.error_cb = NULL,
		.multiplier = 0
	},
	/* AllowHostnameUpdates */
	{
		.opt_key = CONF_ALLOW_HOSTNAME_UPDATES,
		.opt_value = CONF_ALLOW_HOSTNAME_UPDATES_VAL,
		.opt_type = CONF_TYPE_BOOL,
		.opt_return_type = CONF_TYPE_BOOL,
		.default_val.bool_val = true,
		.check_str_cb = NULL,
		.parse_list_strs_cb = NULL,
		.parse_list_uint_cb = NULL,
		.parse_list_item_cb = NULL,
		.parse_hashtable_cb = NULL,
		.error_cb = NULL,
		.multiplier = 0
	},
	/* AllowDomainnameUpdates */
	{
		.opt_key = CONF_ALLOW_DOMAINNAME_UPDATES,
		.opt_value = CONF_ALLOW_DOMAINNAME_UPDATES_VAL,
		.opt_type = CONF_TYPE_BOOL,
		.opt_return_type = CONF_TYPE_BOOL,
		.default_val.bool_val = true,
		.check_str_cb = NULL,
		.parse_list_strs_cb = NULL,
		.parse_list_uint_cb = NULL,
		.parse_list_item_cb = NULL,
		.parse_hashtable_cb = NULL,
		.error_cb = NULL,
		.multiplier = 0
	},
	/* SingleConnectedTechnology */
	{
		.opt_key = CONF_SINGLE_TECH,
		.opt_value = CONF_SINGLE_TECH_VAL,
		.opt_type = CONF_TYPE_BOOL,
		.opt_return_type = CONF_TYPE_BOOL,
		.default_val.bool_val = false,
		.check_str_cb = NULL,
		.parse_list_strs_cb = NULL,
		.parse_list_uint_cb = NULL,
		.parse_list_item_cb = NULL,
		.parse_hashtable_cb = NULL,
		.error_cb = NULL,
		.multiplier = 0
	},
	/* TetheringTechnologies */
	{
		.opt_key = CONF_TETHERING_TECHNOLOGIES,
		.opt_value = CONF_TETHERING_TECHNOLOGIES_VAL,
		.opt_type = CONF_TYPE_STRARR,
		.opt_return_type = CONF_TYPE_STRARR,
		.default_val.str_array_val = NULL,
		.check_str_cb = NULL,
		.parse_list_strs_cb = NULL,
		.parse_list_uint_cb = NULL,
		.parse_list_item_cb = NULL,
		.parse_hashtable_cb = NULL,
		.error_cb = NULL,
		.multiplier = 0
	},
	/* PersistentTetheringMode */
	{
		.opt_key = CONF_PERSISTENT_TETHERING_MODE,
		.opt_value = CONF_PERSISTENT_TETHERING_MODE_VAL,
		.opt_type = CONF_TYPE_BOOL,
		.opt_return_type = CONF_TYPE_BOOL,
		.default_val.bool_val = false,
		.check_str_cb = NULL,
		.parse_list_strs_cb = NULL,
		.parse_list_uint_cb = NULL,
		.parse_list_item_cb = NULL,
		.parse_hashtable_cb = NULL,
		.error_cb = NULL,
		.multiplier = 0
	},
	/* Enable6to4 */
	{
		.opt_key = CONF_ENABLE_6TO4,
		.opt_value = CONF_ENABLE_6TO4_VAL,
		.opt_type = CONF_TYPE_BOOL,
		.opt_return_type = CONF_TYPE_BOOL,
		.default_val.bool_val = false,
		.check_str_cb = NULL,
		.parse_list_strs_cb = NULL,
		.parse_list_uint_cb = NULL,
		.parse_list_item_cb = NULL,
		.parse_hashtable_cb = NULL,
		.error_cb = NULL,
		.multiplier = 0
	},
	/* VendorClassID */
	{
		.opt_key = CONF_VENDOR_CLASS_ID,
		.opt_value = CONF_VENDOR_CLASS_ID_VAL,
		.opt_type = CONF_TYPE_STR,
		.opt_return_type = CONF_TYPE_STR,
		.default_val.str_val = NULL,
		.check_str_cb = NULL,
		.parse_list_strs_cb = NULL,
		.parse_list_uint_cb = NULL,
		.parse_list_item_cb = NULL,
		.parse_hashtable_cb = NULL,
		.error_cb = NULL,
		.multiplier = 0
	},
	/* EnableOnlineCheck */
	{
		.opt_key = CONF_ENABLE_ONLINE_CHECK,
		.opt_value = CONF_ENABLE_ONLINE_CHECK_VAL,
		.opt_type = CONF_TYPE_BOOL,
		.opt_return_type = CONF_TYPE_BOOL,
		.default_val.bool_val = true,
		.check_str_cb = NULL,
		.parse_list_strs_cb = NULL,
		.parse_list_uint_cb = NULL,
		.parse_list_item_cb = NULL,
		.parse_hashtable_cb = NULL,
		.error_cb = NULL,
		.multiplier = 0
	},
	/* EnableOnlineToReadyTransition */
	{
		.opt_key = CONF_ENABLE_ONLINE_TO_READY_TRANSITION,
		.opt_value = CONF_ENABLE_ONLINE_TO_READY_TRANSITION_VAL,
		.opt_type = CONF_TYPE_BOOL,
		.opt_return_type = CONF_TYPE_BOOL,
		.default_val.bool_val = false,
		.check_str_cb = NULL,
		.parse_list_strs_cb = NULL,
		.parse_list_uint_cb = NULL,
		.parse_list_item_cb = NULL,
		.parse_hashtable_cb = NULL,
		.error_cb = NULL,
		.multiplier = 0
	},
	/* OnlineCheckMode */
	{
		.opt_key = CONF_ONLINE_CHECK_MODE,
		.opt_value = CONF_ONLINE_CHECK_MODE_VAL,
		.opt_type = CONF_TYPE_STR,
		.opt_return_type = CONF_TYPE_UINT,
		.default_val.uint_val =
				CONNMAN_SERVICE_ONLINE_CHECK_MODE_ONE_SHOT,
		.check_str_cb = check_online_mode,
		.parse_list_strs_cb = NULL,
		.parse_list_uint_cb = NULL,
		.parse_list_item_cb = NULL,
		.parse_hashtable_cb = NULL,
		.error_cb = online_check_mode_set_from_deprecated,
		.multiplier = 0
	},
	/* OnlineCheckIPv4URL */
	{
		.opt_key = CONF_ONLINE_CHECK_IPV4_URL,
		.opt_value = CONF_ONLINE_CHECK_IPV4_URL_VAL,
		.opt_type = CONF_TYPE_STR,
		.opt_return_type = CONF_TYPE_STR,
		.default_val.str_val = DEFAULT_ONLINE_CHECK_IPV4_URL,
		.check_str_cb = NULL,
		.parse_list_strs_cb = NULL,
		.parse_list_uint_cb = NULL,
		.parse_list_item_cb = NULL,
		.parse_hashtable_cb = NULL,
		.error_cb = NULL,
		.multiplier = 0
	},
	/* OnlineCheckIPv6URL */
	{
		.opt_key = CONF_ONLINE_CHECK_IPV6_URL,
		.opt_value = CONF_ONLINE_CHECK_IPV6_URL_VAL,
		.opt_type = CONF_TYPE_STR,
		.opt_return_type = CONF_TYPE_STR,
		.default_val.str_val = DEFAULT_ONLINE_CHECK_IPV6_URL,
		.check_str_cb = NULL,
		.parse_list_strs_cb = NULL,
		.parse_list_uint_cb = NULL,
		.parse_list_item_cb = NULL,
		.parse_hashtable_cb = NULL,
		.error_cb = NULL,
		.multiplier = 0
	},
	/* OnlineCheckConnectTimeout */
	{
		.opt_key = CONF_ONLINE_CHECK_CONNECT_TIMEOUT,
		.opt_value = CONF_ONLINE_CHECK_CONNECT_TIMEOUT_VAL,
		.opt_type = CONF_TYPE_DOUBLE,
		.opt_return_type = CONF_TYPE_UINT,
		.default_val.double_val = DEFAULT_ONLINE_CHECK_CONNECT_TIMEOUT,
		.check_str_cb = NULL,
		.parse_list_strs_cb = NULL,
		.parse_list_uint_cb = NULL,
		.parse_list_item_cb = NULL,
		.parse_hashtable_cb = NULL,
		.error_cb = online_check_connect_timeout_error,
		.multiplier = 1000
	},
	/* OnlineCheckInitialInterval */
	{
		.opt_key = CONF_ONLINE_CHECK_INITIAL_INTERVAL,
		.opt_value = CONF_ONLINE_CHECK_INITIAL_INTERVAL_VAL,
		.opt_type = CONF_TYPE_UINT,
		.opt_return_type = CONF_TYPE_UINT,
		.default_val.uint_val = DEFAULT_ONLINE_CHECK_INITIAL_INTERVAL,
		.check_str_cb = NULL,
		.parse_list_strs_cb = NULL,
		.parse_list_uint_cb = NULL,
		.parse_list_item_cb = NULL,
		.parse_hashtable_cb = NULL,
		.error_cb = NULL,
		.multiplier = 1
	},
	/* OnlineCheckMaxInterval */
	{
		.opt_key = CONF_ONLINE_CHECK_MAX_INTERVAL,
		.opt_value = CONF_ONLINE_CHECK_MAX_INTERVAL_VAL,
		.opt_type = CONF_TYPE_UINT,
		.opt_return_type = CONF_TYPE_UINT,
		.default_val.uint_val = DEFAULT_ONLINE_CHECK_MAX_INTERVAL,
		.check_str_cb = NULL,
		.parse_list_strs_cb = NULL,
		.parse_list_uint_cb = NULL,
		.parse_list_item_cb = NULL,
		.parse_hashtable_cb = NULL,
		.error_cb = NULL,
		.multiplier = 1
	},
	/* OnlineCheckFailuresThreshold */
	{
		.opt_key = CONF_ONLINE_CHECK_FAILURES_THRESHOLD,
		.opt_value = CONF_ONLINE_CHECK_FAILURES_THRESHOLD_VAL,
		.opt_type = CONF_TYPE_UINT,
		.opt_return_type = CONF_TYPE_UINT,
		.default_val.uint_val = DEFAULT_ONLINE_CHECK_FAILURES_THRESHOLD,
		.check_str_cb = NULL,
		.parse_list_strs_cb = NULL,
		.parse_list_uint_cb = NULL,
		.parse_list_item_cb = NULL,
		.parse_hashtable_cb = NULL,
		.error_cb = NULL,
		.multiplier = 1
	},
	/* OnlineCheckSuccessesThreshold */
	{
		.opt_key = CONF_ONLINE_CHECK_SUCCESSES_THRESHOLD,
		.opt_value = CONF_ONLINE_CHECK_SUCCESSES_THRESHOLD_VAL,
		.opt_type = CONF_TYPE_UINT,
		.opt_return_type = CONF_TYPE_UINT,
		.default_val.uint_val = DEFAULT_ONLINE_CHECK_SUCCESSES_THRESHOLD,
		.check_str_cb = NULL,
		.parse_list_strs_cb = NULL,
		.parse_list_uint_cb = NULL,
		.parse_list_item_cb = NULL,
		.parse_hashtable_cb = NULL,
		.error_cb = NULL,
		.multiplier = 1
	},
	/* OnlineCheckIntervalStyle */
	{
		.opt_key = CONF_ONLINE_CHECK_INTERVAL_STYLE,
		.opt_value = CONF_ONLINE_CHECK_INTERVAL_STYLE_VAL,
		.opt_type = CONF_TYPE_STR,
		.opt_return_type = CONF_TYPE_STR,
		.default_val.str_val = DEFAULT_ONLINE_CHECK_INTERVAL_STYLE,
		.check_str_cb = check_online_check_interval_style,
		.parse_list_strs_cb = NULL,
		.parse_list_uint_cb = NULL,
		.parse_list_item_cb = NULL,
		.parse_hashtable_cb = NULL,
		.error_cb = NULL,
		.multiplier = 0
	},
	/* AutoConnectRoamingServices */
	{
		.opt_key = CONF_AUTO_CONNECT_ROAMING_SERVICES,
		.opt_value = CONF_AUTO_CONNECT_ROAMING_SERVICES_VAL,
		.opt_type = CONF_TYPE_BOOL,
		.opt_return_type = CONF_TYPE_BOOL,
		.default_val.bool_val = false,
		.check_str_cb = NULL,
		.parse_list_strs_cb = NULL,
		.parse_list_uint_cb = NULL,
		.parse_list_item_cb = NULL,
		.parse_hashtable_cb = NULL,
		.error_cb = NULL,
		.multiplier = 0
	},
	/* AddressConflictDetection */
	{
		.opt_key = CONF_ACD,
		.opt_value = CONF_ACD_VAL,
		.opt_type = CONF_TYPE_BOOL,
		.opt_return_type = CONF_TYPE_BOOL,
		.default_val.bool_val = false,
		.check_str_cb = NULL,
		.parse_list_strs_cb = NULL,
		.parse_list_uint_cb = NULL,
		.parse_list_item_cb = NULL,
		.parse_hashtable_cb = NULL,
		.error_cb = NULL,
		.multiplier = 0
	},
	/* UseGatewaysAsTimeservers */
	{
		.opt_key = CONF_USE_GATEWAYS_AS_TIMESERVERS,
		.opt_value = CONF_USE_GATEWAYS_AS_TIMESERVERS_VAL,
		.opt_type = CONF_TYPE_BOOL,
		.opt_return_type = CONF_TYPE_BOOL,
		.default_val.bool_val = false,
		.check_str_cb = NULL,
		.parse_list_strs_cb = NULL,
		.parse_list_uint_cb = NULL,
		.parse_list_item_cb = NULL,
		.parse_hashtable_cb = NULL,
		.error_cb = NULL,
		.multiplier = 0
	},
	/* Localtime */
	{
		.opt_key = CONF_LOCALTIME,
		.opt_value = CONF_LOCALTIME_VAL,
		.opt_type = CONF_TYPE_STR,
		.opt_return_type = CONF_TYPE_STR,
		.default_val.str_val = DEFAULT_LOCALTIME,
		.check_str_cb = NULL,
		.parse_list_strs_cb = NULL,
		.parse_list_uint_cb = NULL,
		.parse_list_item_cb = NULL,
		.parse_hashtable_cb = NULL,
		.error_cb = NULL,
		.multiplier = 0
	},
	/* RegdomFollowsTimezone */
	{
		.opt_key = CONF_REGDOM_FOLLOWS_TIMEZONE,
		.opt_value = CONF_REGDOM_FOLLOWS_TIMEZONE_VAL,
		.opt_type = CONF_TYPE_BOOL,
		.opt_return_type = CONF_TYPE_BOOL,
		.default_val.bool_val = false,
		.check_str_cb = NULL,
		.parse_list_strs_cb = NULL,
		.parse_list_uint_cb = NULL,
		.parse_list_item_cb = NULL,
		.parse_hashtable_cb = NULL,
		.error_cb = NULL,
		.multiplier = 0
	},
	/* ResolvConf */
	{
		.opt_key = CONF_RESOLV_CONF,
		.opt_value = CONF_RESOLV_CONF_VAL,
		.opt_type = CONF_TYPE_STR,
		.opt_return_type = CONF_TYPE_STR,
		.default_val.str_val = NULL,
		.check_str_cb = NULL,
		.parse_list_strs_cb = NULL,
		.parse_list_uint_cb = NULL,
		.parse_list_item_cb = NULL,
		.parse_hashtable_cb = NULL,
		.error_cb = NULL,
		.multiplier = 0
	},
	/* FallbackDeviceTypes */
	{
		.opt_key = CONF_FALLBACK_DEVICE_TYPES,
		.opt_value = CONF_FALLBACK_DEVICE_TYPES_VAL,
		.opt_type = CONF_TYPE_HASHTABLE,
		.opt_return_type = CONF_TYPE_HASHTABLE,
		.default_val.hash_table_val = NULL,
		.check_str_cb = NULL,
		.parse_list_strs_cb = NULL,
		.parse_list_uint_cb = NULL,
		.parse_list_item_cb = NULL,
		.parse_hashtable_cb = parse_fallback_device_types,
		.error_cb = NULL,
		.multiplier = 0
	},
	/* Option "wifi" */
	{
		.opt_key = CONF_OPTION_WIFI,
		.opt_value = CONF_OPTION_WIFI_VAL,
		.opt_type = CONF_TYPE_STR,
		.opt_return_type = CONF_TYPE_STR,
		.default_val.str_val = DEFAULT_WIFI_OPTION,
		.check_str_cb = NULL,
		.parse_list_strs_cb = NULL,
		.parse_list_uint_cb = NULL,
		.parse_list_item_cb = NULL,
		.parse_hashtable_cb = NULL,
		.error_cb = NULL,
		.multiplier = 0
	},

	{ 0 }
};

/* Generic read function that dispatches based on type */
static void read_config_value(GKeyFile *config, struct config_option *option,
								bool append)
{
	GError *error = NULL;
	const char *group = GENERAL_GROUP;
	char **list;
	gsize len;

	if (!option)
		return;

	if (!g_key_file_has_key(config, group, option->opt_key, NULL))
		return;

	switch (option->opt_type) {
	case CONF_TYPE_BOOL:
		bool value = __connman_config_get_bool(config, group,
						option->opt_key, &error);
		if (!error)
			set_bool_value(option, value);
		break;
	case CONF_TYPE_UINT:
		int integer = g_key_file_get_integer(config, group,
						option->opt_key, &error);
		if (!error && integer >= 0)
			set_uint_value(option, integer * option->multiplier);

		break;
	case CONF_TYPE_DOUBLE:
		double real = g_key_file_get_double(config, group,
						option->opt_key, &error);
		if (!error) {
			if (real < 0 && option->error_cb)
				option->error_cb();
			else
				set_uint_value(option,
						real * option->multiplier);
		} else if (option->error_cb) {
			option->error_cb();
		}

		break;
	case CONF_TYPE_STR:
		char *str = __connman_config_get_string(config, group,
						option->opt_key, &error);
		if (!error) {
			set_str_value(option, str, option->check_str_cb);
		} else if (option->error_cb) {
			option->error_cb();
			g_free(str);
		} else if (!str && option->default_val.str_val) {
			/* If not set and default exists, use default */
			set_str_value(option, g_strdup(
						option->default_val.str_val),
						option->check_str_cb);
		} else {
			g_free(str);
		}

		break;
	case CONF_TYPE_STRARR:
		list = __connman_config_get_string_list(config, group,
						option->opt_key, &len, &error);
		if (!error) {
			if (option->parse_list_item_cb) {
				set_str_array_value_cb(option, list,
						option->parse_list_item_cb,
						len, append);
				g_strfreev(list);
			} else if (option->parse_list_strs_cb) {
				char **new_list = option->parse_list_strs_cb(
								list, &len);
				g_strfreev(list);

				if (new_list)
					set_str_array_value(option, new_list);
			} else {
				set_str_array_value(option, list);
			}
		}

		break;
	case CONF_TYPE_UINTARR:
		list = __connman_config_get_string_list(config, group,
						option->opt_key, &len, &error);
		if (!error) {
			if (option->parse_list_uint_cb) {
				unsigned int *int_list =
						option->parse_list_uint_cb(
								list, len);
				set_int_array_value(option, int_list);
			}
		}

		g_strfreev(list);
		break;
	case CONF_TYPE_HASHTABLE:
		list = __connman_config_get_string_list(config, group,
						option->opt_key, &len, &error);
		if (!error) {
			GHashTable *hash = option->parse_hashtable_cb(list, len);
			g_strfreev(list);
			set_hash_table_value(option, hash);
		}

		break;
	}

	g_clear_error(&error);
}

static void read_non_main_config(GKeyFile *config, bool append)
{
	GError *error = NULL;
	struct config_option *opt;
	char **keys;
	gsize len;
	int i;

	DBG("");

	if (!config)
		return;

	keys = g_key_file_get_keys(config, GENERAL_GROUP, &len, &error);
	if (!error) {
		for (i = 0; i < len; i++) {
			opt = config_option_lookup(keys[i]);
			if (!opt) {
				DBG("invalid key %s", keys[i]);
				continue;
			}

			read_config_value(config, opt, append);
		}
	}

	g_clear_error(&error);
	g_strfreev(keys);
}

static void initialize_default_values()
{
	struct config_option *opt;
	int i;

	DBG("");

	for (i = 0; config_options[i].opt_key; i++) {
		opt = &config_options[i];

		if (g_str_equal(opt->opt_key, CONF_AUTO_CONNECT_TECHS)) {
			opt->default_val.int_array_val =
				parse_service_types(default_auto_connect,
				CONF_ARRAY_SIZE(default_auto_connect));
		} else if (g_str_equal(opt->opt_key, CONF_ENABLED_TECHS)) {
			opt->default_val.int_array_val =
				parse_service_types(default_enabled_techs,
				CONF_ARRAY_SIZE(default_enabled_techs));
		} else if (g_str_equal(opt->opt_key, CONF_FAVORITE_TECHS)) {
			opt->default_val.int_array_val =
				parse_service_types(default_favorite_techs,
				CONF_ARRAY_SIZE(default_favorite_techs));
		} else if (g_str_equal(opt->opt_key,
						CONF_BLACKLISTED_INTERFACES)) {
			opt->default_val.str_array_val = g_strdupv(
							default_blacklist);
		} else {
			switch (opt->opt_type) {
			case CONF_TYPE_STR:
				/*
				* Copy the string default only when the
				* conversion to an another type requires it.
				*/
				if (opt->opt_return_type == CONF_TYPE_STR)
					break;
				/* fall-through */
			case CONF_TYPE_BOOL:
			case CONF_TYPE_UINT:
			case CONF_TYPE_DOUBLE:
				opt->current_val = opt->default_val;
				break;
			case CONF_TYPE_UINTARR:
			case CONF_TYPE_STRARR:
			case CONF_TYPE_HASHTABLE:
				break;
			}
		}
	}
}

void __connman_setting_read_config_values(GKeyFile *config, bool mainconfig,
								bool append)
{
	unsigned int initial_interval;
	unsigned int max_interval;
	unsigned int failures_threshold;
	unsigned int successes_threshold;
	int i;

	if (!mainconfig) {
		read_non_main_config(config, append);
		return;
	}

	initialize_default_values();

	if (config) {
		for (i = 0; config_options[i].opt_key; i++)
			read_config_value(config, &config_options[i], append);
	}

	initial_interval = connman_setting_get_uint(
					CONF_ONLINE_CHECK_INITIAL_INTERVAL);
	max_interval = connman_setting_get_uint(CONF_ONLINE_CHECK_MAX_INTERVAL);
	if (initial_interval < 1 || initial_interval > max_interval) {
		connman_warn("Incorrect online check intervals [%u, %u]",
						initial_interval, max_interval);
		setting_set_uint(CONF_ONLINE_CHECK_INITIAL_INTERVAL,
				DEFAULT_ONLINE_CHECK_INITIAL_INTERVAL);
		setting_set_uint(CONF_ONLINE_CHECK_MAX_INTERVAL,
				DEFAULT_ONLINE_CHECK_MAX_INTERVAL);
	}

	failures_threshold = connman_setting_get_uint(
					CONF_ONLINE_CHECK_FAILURES_THRESHOLD);
	if (failures_threshold < 1) {
		connman_warn("Incorrect online check failures threshold [%d]",
						failures_threshold);
		setting_set_uint(CONF_ONLINE_CHECK_FAILURES_THRESHOLD,
				DEFAULT_ONLINE_CHECK_FAILURES_THRESHOLD);
	}

	successes_threshold = connman_setting_get_uint(
					CONF_ONLINE_CHECK_SUCCESSES_THRESHOLD);
	if (successes_threshold < 1) {
		connman_warn("Incorrect online check successes threshold [%d]",
						successes_threshold);
		setting_set_uint(CONF_ONLINE_CHECK_SUCCESSES_THRESHOLD,
				DEFAULT_ONLINE_CHECK_SUCCESSES_THRESHOLD);
	}
}

const char *__connman_setting_get_fallback_device_type(const char *interface)
{
	struct config_option *opt;

	opt = config_option_lookup(CONF_FALLBACK_DEVICE_TYPES);
	if (!opt || !opt->current_val.hash_table_val)
		return NULL;

	return g_hash_table_lookup(opt->current_val.hash_table_val, interface);
}

bool __connman_setting_is_supported_option(const char *key)
{
	return config_option_lookup(key) != NULL;
}

void __connman_setting_log()
{
	online_check_settings_log();
}

int __connman_setting_init()
{
	struct config_option *opt;
	int i;

	DBG("");

	if (config_options_table)
		g_hash_table_unref(config_options_table);

	config_options_table = g_hash_table_new(g_str_hash, g_str_equal);
	if (!config_options_table)
		return -ENOMEM;

	for (i = 0; config_options[i].opt_key; i++) {
		opt = &config_options[i];

		g_hash_table_insert(config_options_table, (gpointer)opt->opt_key,
					opt);
	}

	return 0;
}

void __connman_setting_cleanup()
{
	int i;
	struct config_option *opt;

	DBG("");

	for (i = 0; config_options[i].opt_key; i++) {
		opt = &config_options[i];

		switch (opt->opt_type) {
		case CONF_TYPE_BOOL:
		case CONF_TYPE_UINT:
			break;
		case CONF_TYPE_STR:
			/* Stores into something else, skip */
			if (opt->opt_return_type != CONF_TYPE_STR)
				break;

			if (opt->current_val.str_val !=
						opt->default_val.str_val)
				g_free(opt->current_val.str_val);

			opt->current_val.str_val = NULL;
			break;
		case CONF_TYPE_STRARR:
			g_strfreev(opt->current_val.str_array_val);
			opt->current_val.str_array_val = NULL;
			g_strfreev(opt->default_val.str_array_val);
			opt->default_val.str_array_val = NULL;
			break;
		case CONF_TYPE_UINTARR:
			g_free(opt->current_val.int_array_val);
			opt->current_val.int_array_val = NULL;
			g_free(opt->default_val.int_array_val);
			opt->default_val.int_array_val = NULL;
			break;
		case CONF_TYPE_HASHTABLE:
			if (opt->current_val.hash_table_val)
				g_hash_table_unref(
					opt->current_val.hash_table_val);

			opt->current_val.hash_table_val = NULL;
			break;
		default:
			break;
		}
	}

	if (config_options_table) {
		g_hash_table_destroy(config_options_table);
		config_options_table = NULL;
	}
}
