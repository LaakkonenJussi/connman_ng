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
	unsigned int *uint_array_val;
	GHashTable *hash_table_val;
};

/* Callback for checking if value is acceptable */
typedef gboolean (*parse_str_callback)(const char *value);

/* Callback for parsing items in a string list */
typedef char** (*parse_list_callback)(char **str_list, gsize *len);

/* Callback for parsing uint list from the NULL terminated string list */
typedef uint* (*parse_uint_list_callback)(char **list, gsize len);

/* Callback for parsing string list into hashtable. */
typedef GHashTable* (*parse_hashtable_callback)(char **list, gsize len);

/* Error callback */
typedef int (*error_callback)(void);

union parse_callback {
	parse_str_callback parse_str_cb;
	parse_list_callback parse_list_cb;
	parse_uint_list_callback parse_uint_list_cb;
	parse_hashtable_callback parse_hashtable_cb;
};

/*
 * Configuration options struct.
 *
 * Any new configuration option has to have at least key, value and type (and
 * return type) set. The fields are detailed as follows:
 *
 * opt_key		Option name, used for searching in getters
 * opt_value		enum value for the option
 * opt_return_type	The type of this option returns, supported: str -> uint
 * default_val		Default value as union option, must match opt_type
 * parser		Union for parser callbacks, contains:
 * 	parse_str_cb		Check string value: CONF_TYPE_STR
 * 	parse_list_cb		Parse a string list: CONF_TYPE_STRARR
 * 	parse_uint_list_cb	Parse int list: CONF_TYPE_UINTARR
 * 	parse_hashtable_cb	Parse a hash table: CONF_TYPE_HASHTABLE
 * error_cb		Error callback when check_str_cb fails
 * multiplier		For CONF_TYPE_UINT and CONF_TYPE_DOUBLE correlation
 *
 * If parse_str_cb is missing the string is saved as is. If parse_list_strs_cb
 * is missing the string list is saved as is. If any of the other parser
 * callbacks is missing the value will not be saved.
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
	enum option_type opt_type;		/* Define valid union field */
	/* Special handling, read as opt_type, return with this union type */
	enum option_type opt_return_type;

	/* Unions for default value and current storage */
	union config_value default_val;
	union config_value current_val;

	/* Callbacks, parsers are set in union for a type, or NULL if omitted */
	union parse_callback parser;
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

	if (!j) {
		g_free(type_list);
		return NULL;
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

	if (!j) {
		g_strfreev(servers);
		*len = 0;
		return NULL;
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
	if (!opt)
		return NULL;

	if (opt->opt_type != CONF_TYPE_STR &&
					opt->opt_return_type != CONF_TYPE_STR)
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

	if (opt->current_val.uint_array_val)
		return opt->current_val.uint_array_val;

	return opt->default_val.uint_array_val;
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

static void set_str_value(struct config_option *opt, const char *value)
{
	if (opt->opt_type != CONF_TYPE_STR)
		return;

	if (opt->parser.parse_str_cb && !opt->parser.parse_str_cb(value))
		return;

	if (!g_strcmp0(opt->current_val.str_val, value))
		return;

	g_free(opt->current_val.str_val);
	opt->current_val.str_val = g_strdup(value);
}

static void set_str_array_value(struct config_option *opt, char **value)
{
	if (opt->opt_type != CONF_TYPE_STRARR)
		return;

	g_strfreev(opt->current_val.str_array_val);
	opt->current_val.str_array_val = g_strdupv(value);
}

static void set_uint_array_value(struct config_option *opt,
				const unsigned int *value, gsize len)
{
	gsize size;

	if (opt->opt_type != CONF_TYPE_UINTARR)
		return;

	g_free(opt->current_val.uint_array_val);

	/* Take account the terminating 0 value in the array */
	size = (len + 1) * sizeof(*value);
	opt->current_val.uint_array_val = g_memdup2(value, size);
}

static void set_hash_table_value(struct config_option *opt, GHashTable *value)
{
	if (opt->opt_type != CONF_TYPE_HASHTABLE)
		return;

	if (opt->current_val.hash_table_val)
		g_hash_table_destroy(opt->current_val.hash_table_val);

	opt->current_val.hash_table_val = g_hash_table_ref(value);
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

	set_str_value(opt, value);
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
		.opt_type = CONF_TYPE_BOOL,
		.opt_return_type = CONF_TYPE_BOOL,
		.default_val.bool_val = true,
		.error_cb = NULL,
		.multiplier = 0
	},
	/* FallbackTimeservers */
	{
		.opt_key = CONF_PREF_TIMESERVERS,
		.opt_type = CONF_TYPE_STRARR,
		.opt_return_type = CONF_TYPE_STRARR,
		.default_val.str_array_val = NULL,
		.parser.parse_list_cb = NULL,
		.error_cb = NULL,
		.multiplier = 0
	},
	/* DefaultAutoConnectTechnologies */
	{
		.opt_key = CONF_AUTO_CONNECT_TECHS,
		.opt_type = CONF_TYPE_UINTARR,
		.opt_return_type = CONF_TYPE_UINTARR,
		.default_val.uint_array_val = NULL,
		.parser.parse_uint_list_cb = parse_service_types,
		.error_cb = NULL,
		.multiplier = 0
	},
	/* DefaultEnabledTechnologies */
	{
		.opt_key = CONF_ENABLED_TECHS,
		.opt_type = CONF_TYPE_UINTARR,
		.opt_return_type = CONF_TYPE_UINTARR,
		.default_val.uint_array_val = NULL,
		.parser.parse_uint_list_cb = parse_service_types,
		.error_cb = NULL,
		.multiplier = 0
	},
	/* DefaultFavoriteTechnologies */
	{
		.opt_key = CONF_FAVORITE_TECHS,
		.opt_type = CONF_TYPE_UINTARR,
		.opt_return_type = CONF_TYPE_UINTARR,
		.default_val.uint_array_val = NULL,
		.parser.parse_uint_list_cb = parse_service_types,
		.error_cb = NULL,
		.multiplier = 0
	},
	/* AlwaysConnectedTechnologies */
	{
		.opt_key = CONF_ALWAYS_CONNECTED_TECHS,
		.opt_type = CONF_TYPE_UINTARR,
		.opt_return_type = CONF_TYPE_UINTARR,
		.default_val.uint_array_val = NULL,
		.parser.parse_uint_list_cb = parse_service_types,
		.error_cb = NULL,
		.multiplier = 0
	},
	/* PreferredTechnologies */
	{
		.opt_key = CONF_PREFERRED_TECHS,
		.opt_type = CONF_TYPE_UINTARR,
		.opt_return_type = CONF_TYPE_UINTARR,
		.default_val.uint_array_val = NULL,
		.parser.parse_uint_list_cb = parse_service_types,
		.error_cb = NULL,
		.multiplier = 0
	},
	/* FallbackNameservers */
	{
		.opt_key = CONF_FALLBACK_NAMESERVERS,
		.opt_type = CONF_TYPE_STRARR,
		.opt_return_type = CONF_TYPE_STRARR,
		.default_val.str_array_val = NULL,
		.parser.parse_list_cb = parse_fallback_nameservers,
		.error_cb = NULL,
		.multiplier = 0
	},
	/* InputRequestTimeout */
	{
		.opt_key = CONF_TIMEOUT_INPUTREQ,
		.opt_type = CONF_TYPE_UINT,
		.opt_return_type = CONF_TYPE_UINT,
		.default_val.uint_val = DEFAULT_INPUT_REQUEST_TIMEOUT,
		.error_cb = NULL,
		.multiplier = 1000
	},
	/* BrowserLaunchTimeout */
	{
		.opt_key = CONF_TIMEOUT_BROWSERLAUNCH,
		.opt_type = CONF_TYPE_UINT,
		.opt_return_type = CONF_TYPE_UINT,
		.default_val.uint_val = DEFAULT_BROWSER_LAUNCH_TIMEOUT,
		.error_cb = NULL,
		.multiplier = 1000
	},
	/* NetworkInterfaceBlacklist */
	{
		.opt_key = CONF_BLACKLISTED_INTERFACES,
		.opt_type = CONF_TYPE_STRARR,
		.opt_return_type = CONF_TYPE_STRARR,
		.default_val.str_array_val = NULL,
		.parser.parse_list_cb = NULL,
		.error_cb = NULL,
		.multiplier = 0
	},
	/* AllowHostnameUpdates */
	{
		.opt_key = CONF_ALLOW_HOSTNAME_UPDATES,
		.opt_type = CONF_TYPE_BOOL,
		.opt_return_type = CONF_TYPE_BOOL,
		.default_val.bool_val = true,
		.error_cb = NULL,
		.multiplier = 0
	},
	/* AllowDomainnameUpdates */
	{
		.opt_key = CONF_ALLOW_DOMAINNAME_UPDATES,
		.opt_type = CONF_TYPE_BOOL,
		.opt_return_type = CONF_TYPE_BOOL,
		.default_val.bool_val = true,
		.error_cb = NULL,
		.multiplier = 0
	},
	/* SingleConnectedTechnology */
	{
		.opt_key = CONF_SINGLE_TECH,
		.opt_type = CONF_TYPE_BOOL,
		.opt_return_type = CONF_TYPE_BOOL,
		.default_val.bool_val = false,
		.error_cb = NULL,
		.multiplier = 0
	},
	/* TetheringTechnologies */
	{
		.opt_key = CONF_TETHERING_TECHNOLOGIES,
		.opt_type = CONF_TYPE_STRARR,
		.opt_return_type = CONF_TYPE_STRARR,
		.default_val.str_array_val = NULL,
		.parser.parse_list_cb = NULL,
		.error_cb = NULL,
		.multiplier = 0
	},
	/* PersistentTetheringMode */
	{
		.opt_key = CONF_PERSISTENT_TETHERING_MODE,
		.opt_type = CONF_TYPE_BOOL,
		.opt_return_type = CONF_TYPE_BOOL,
		.default_val.bool_val = false,
		.error_cb = NULL,
		.multiplier = 0
	},
	/* Enable6to4 */
	{
		.opt_key = CONF_ENABLE_6TO4,
		.opt_type = CONF_TYPE_BOOL,
		.opt_return_type = CONF_TYPE_BOOL,
		.default_val.bool_val = false,
		.error_cb = NULL,
		.multiplier = 0
	},
	/* VendorClassID */
	{
		.opt_key = CONF_VENDOR_CLASS_ID,
		.opt_type = CONF_TYPE_STR,
		.opt_return_type = CONF_TYPE_STR,
		.default_val.str_val = NULL,
		.parser.parse_str_cb = NULL,
		.error_cb = NULL,
		.multiplier = 0
	},
	/* EnableOnlineCheck */
	{
		.opt_key = CONF_ENABLE_ONLINE_CHECK,
		.opt_type = CONF_TYPE_BOOL,
		.opt_return_type = CONF_TYPE_BOOL,
		.default_val.bool_val = true,
		.error_cb = NULL,
		.multiplier = 0
	},
	/* EnableOnlineToReadyTransition */
	{
		.opt_key = CONF_ENABLE_ONLINE_TO_READY_TRANSITION,
		.opt_type = CONF_TYPE_BOOL,
		.opt_return_type = CONF_TYPE_BOOL,
		.default_val.bool_val = false,
		.error_cb = NULL,
		.multiplier = 0
	},
	/* OnlineCheckMode */
	{
		.opt_key = CONF_ONLINE_CHECK_MODE,
		.opt_type = CONF_TYPE_STR,
		.opt_return_type = CONF_TYPE_UINT,
		.default_val.uint_val =
				CONNMAN_SERVICE_ONLINE_CHECK_MODE_ONE_SHOT,
		.parser.parse_str_cb = check_online_mode,
		.error_cb = online_check_mode_set_from_deprecated,
		.multiplier = 0
	},
	/* OnlineCheckIPv4URL */
	{
		.opt_key = CONF_ONLINE_CHECK_IPV4_URL,
		.opt_type = CONF_TYPE_STR,
		.opt_return_type = CONF_TYPE_STR,
		.default_val.str_val = DEFAULT_ONLINE_CHECK_IPV4_URL,
		.parser.parse_str_cb = NULL,
		.error_cb = NULL,
		.multiplier = 0
	},
	/* OnlineCheckIPv6URL */
	{
		.opt_key = CONF_ONLINE_CHECK_IPV6_URL,
		.opt_type = CONF_TYPE_STR,
		.opt_return_type = CONF_TYPE_STR,
		.default_val.str_val = DEFAULT_ONLINE_CHECK_IPV6_URL,
		.parser.parse_str_cb = NULL,
		.error_cb = NULL,
		.multiplier = 0
	},
	/* OnlineCheckConnectTimeout */
	{
		.opt_key = CONF_ONLINE_CHECK_CONNECT_TIMEOUT,
		.opt_type = CONF_TYPE_DOUBLE,
		.opt_return_type = CONF_TYPE_UINT,
		.default_val.double_val = DEFAULT_ONLINE_CHECK_CONNECT_TIMEOUT,
		.error_cb = online_check_connect_timeout_error,
		.multiplier = 1000
	},
	/* OnlineCheckInitialInterval */
	{
		.opt_key = CONF_ONLINE_CHECK_INITIAL_INTERVAL,
		.opt_type = CONF_TYPE_UINT,
		.opt_return_type = CONF_TYPE_UINT,
		.default_val.uint_val = DEFAULT_ONLINE_CHECK_INITIAL_INTERVAL,
		.error_cb = NULL,
		.multiplier = 1
	},
	/* OnlineCheckMaxInterval */
	{
		.opt_key = CONF_ONLINE_CHECK_MAX_INTERVAL,
		.opt_type = CONF_TYPE_UINT,
		.opt_return_type = CONF_TYPE_UINT,
		.default_val.uint_val = DEFAULT_ONLINE_CHECK_MAX_INTERVAL,
		.error_cb = NULL,
		.multiplier = 1
	},
	/* OnlineCheckFailuresThreshold */
	{
		.opt_key = CONF_ONLINE_CHECK_FAILURES_THRESHOLD,
		.opt_type = CONF_TYPE_UINT,
		.opt_return_type = CONF_TYPE_UINT,
		.default_val.uint_val = DEFAULT_ONLINE_CHECK_FAILURES_THRESHOLD,
		.error_cb = NULL,
		.multiplier = 1
	},
	/* OnlineCheckSuccessesThreshold */
	{
		.opt_key = CONF_ONLINE_CHECK_SUCCESSES_THRESHOLD,
		.opt_type = CONF_TYPE_UINT,
		.opt_return_type = CONF_TYPE_UINT,
		.default_val.uint_val = DEFAULT_ONLINE_CHECK_SUCCESSES_THRESHOLD,
		.error_cb = NULL,
		.multiplier = 1
	},
	/* OnlineCheckIntervalStyle */
	{
		.opt_key = CONF_ONLINE_CHECK_INTERVAL_STYLE,
		.opt_type = CONF_TYPE_STR,
		.opt_return_type = CONF_TYPE_STR,
		.default_val.str_val = DEFAULT_ONLINE_CHECK_INTERVAL_STYLE,
		.parser.parse_str_cb = check_online_check_interval_style,
		.error_cb = NULL,
		.multiplier = 0
	},
	/* AutoConnectRoamingServices */
	{
		.opt_key = CONF_AUTO_CONNECT_ROAMING_SERVICES,
		.opt_type = CONF_TYPE_BOOL,
		.opt_return_type = CONF_TYPE_BOOL,
		.default_val.bool_val = false,
		.error_cb = NULL,
		.multiplier = 0
	},
	/* AddressConflictDetection */
	{
		.opt_key = CONF_ACD,
		.opt_type = CONF_TYPE_BOOL,
		.opt_return_type = CONF_TYPE_BOOL,
		.default_val.bool_val = false,
		.error_cb = NULL,
		.multiplier = 0
	},
	/* UseGatewaysAsTimeservers */
	{
		.opt_key = CONF_USE_GATEWAYS_AS_TIMESERVERS,
		.opt_type = CONF_TYPE_BOOL,
		.opt_return_type = CONF_TYPE_BOOL,
		.default_val.bool_val = false,
		.error_cb = NULL,
		.multiplier = 0
	},
	/* Localtime */
	{
		.opt_key = CONF_LOCALTIME,
		.opt_type = CONF_TYPE_STR,
		.opt_return_type = CONF_TYPE_STR,
		.default_val.str_val = DEFAULT_LOCALTIME,
		.parser.parse_str_cb = NULL,
		.error_cb = NULL,
		.multiplier = 0
	},
	/* RegdomFollowsTimezone */
	{
		.opt_key = CONF_REGDOM_FOLLOWS_TIMEZONE,
		.opt_type = CONF_TYPE_BOOL,
		.opt_return_type = CONF_TYPE_BOOL,
		.default_val.bool_val = false,
		.error_cb = NULL,
		.multiplier = 0
	},
	/* ResolvConf */
	{
		.opt_key = CONF_RESOLV_CONF,
		.opt_type = CONF_TYPE_STR,
		.opt_return_type = CONF_TYPE_STR,
		.default_val.str_val = NULL,
		.parser.parse_str_cb = NULL,
		.error_cb = NULL,
		.multiplier = 0
	},
	/* FallbackDeviceTypes */
	{
		.opt_key = CONF_FALLBACK_DEVICE_TYPES,
		.opt_type = CONF_TYPE_HASHTABLE,
		.opt_return_type = CONF_TYPE_HASHTABLE,
		.default_val.hash_table_val = NULL,
		.parser.parse_hashtable_cb = parse_fallback_device_types,
		.error_cb = NULL,
		.multiplier = 0
	},
	/* Option "wifi" */
	{
		.opt_key = CONF_OPTION_WIFI,
		.opt_type = CONF_TYPE_STR,
		.opt_return_type = CONF_TYPE_STR,
		.default_val.str_val = DEFAULT_WIFI_OPTION,
		.parser.parse_str_cb = NULL,
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
	char *str = NULL;
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
		if (error) {
			if (option->error_cb)
				option->error_cb();
			break;
		}

		set_bool_value(option, value);

		break;
	case CONF_TYPE_UINT:
		gint integer = g_key_file_get_integer(config, group,
						option->opt_key, &error);
		/* Ignore negative integer values. 0 is a valid value. */
		if (error || integer < 0) {
			if (option->error_cb)
				option->error_cb();
			break;
		}

		set_uint_value(option, integer * option->multiplier);

		break;
	case CONF_TYPE_DOUBLE:
		double real = g_key_file_get_double(config, group,
						option->opt_key, &error);
		if (error || real < 0) {
			if (option->error_cb)
				option->error_cb();
			break;
		}

		set_uint_value(option, real * option->multiplier);

		break;
	case CONF_TYPE_STR:
		str = __connman_config_get_string(config, group,
						option->opt_key, &error);
		if (error) {
			if (option->error_cb)
				option->error_cb();
			g_free(str);
			break;
		}

		if (str) {
			set_str_value(option, str);
			g_free(str);
		}

		break;
	case CONF_TYPE_STRARR:
		list = __connman_config_get_string_list(config, group,
						option->opt_key, &len, &error);
		if (error) {
			if (option->error_cb)
				option->error_cb();
		} else if (option->parser.parse_list_cb) {
			char **new_list = option->parser.parse_list_cb(
							list, &len);
			if (new_list)
				set_str_array_value(option, new_list);

			g_strfreev(new_list);
		} else {
			set_str_array_value(option, list);
		}

		g_strfreev(list);
		break;
	case CONF_TYPE_UINTARR:
		list = __connman_config_get_string_list(config, group,
						option->opt_key, &len, &error);
		if (error) {
			if (option->error_cb)
				option->error_cb();
		} else if (option->parser.parse_uint_list_cb) {
			unsigned int *uint_list =
					option->parser.parse_uint_list_cb(
								list, len);
			if (uint_list)
				set_uint_array_value(option, uint_list, len);

			g_free(uint_list);
		}

		g_strfreev(list);
		break;
	case CONF_TYPE_HASHTABLE:
		list = __connman_config_get_string_list(config, group,
						option->opt_key, &len, &error);
		if (error) {
			if (option->error_cb)
				option->error_cb();
		} else if (option->parser.parse_hashtable_cb) {
			GHashTable *hash = option->parser.parse_hashtable_cb(
								list, len);
			if (hash) {
				set_hash_table_value(option, hash);
				g_hash_table_unref(hash);
			}
		}

		g_strfreev(list);
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
			if (!opt->parser.parse_uint_list_cb)
				continue;

			opt->default_val.uint_array_val =
				opt->parser.parse_uint_list_cb(default_auto_connect,
					CONF_ARRAY_SIZE(default_auto_connect));
		} else if (g_str_equal(opt->opt_key, CONF_ENABLED_TECHS)) {
			if (!opt->parser.parse_uint_list_cb)
				continue;

			opt->default_val.uint_array_val =
				opt->parser.parse_uint_list_cb(
					default_enabled_techs,
					CONF_ARRAY_SIZE(default_enabled_techs));
		} else if (g_str_equal(opt->opt_key, CONF_FAVORITE_TECHS)) {
			if (!opt->parser.parse_uint_list_cb)
				continue;

			opt->default_val.uint_array_val =
				opt->parser.parse_uint_list_cb(default_favorite_techs,
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
			/* Copy simple types */
			case CONF_TYPE_BOOL:
			case CONF_TYPE_UINT:
			case CONF_TYPE_DOUBLE:
				opt->current_val = opt->default_val;
				break;
			case CONF_TYPE_UINTARR:
				opt->current_val.uint_array_val = NULL;
				break;
			case CONF_TYPE_STRARR:
				opt->current_val.str_array_val = NULL;
				break;
			case CONF_TYPE_HASHTABLE:
				opt->current_val.hash_table_val = NULL;
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
		return -EALREADY;

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

			/* Ensure that default static str is not freed. */
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
			g_free(opt->current_val.uint_array_val);
			opt->current_val.uint_array_val = NULL;
			g_free(opt->default_val.uint_array_val);
			opt->default_val.uint_array_val = NULL;
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
